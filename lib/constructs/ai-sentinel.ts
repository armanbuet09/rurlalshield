import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as path from 'path';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import * as tasks from 'aws-cdk-lib/aws-stepfunctions-tasks';
import * as apigw from 'aws-cdk-lib/aws-apigateway';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as bedrock from 'aws-cdk-lib/aws-bedrock';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import { NagSuppressions } from 'cdk-nag';
import { RuralShieldConfig } from '../config';

export interface AiSentinelProps {
  readonly config: RuralShieldConfig;
  readonly key: kms.IKey;
  readonly alerts: sns.ITopic;
  readonly logArchive: s3.IBucket;
  readonly appLogRetention: logs.RetentionDays;
}

/**
 * AI Sentinel = "LLM proposes, policy disposes".
 *
 *   Security Hub / GuardDuty finding  --EventBridge-->  Step Functions
 *      1. Triage (Lambda + Bedrock Converse, structured tool output, Guardrails):
 *         plain-English summary for a non-security IT generalist, patient-safety impact,
 *         PHI-exposure assessment, MITRE ATT&CK mapping, recommended *allow-listed* playbook.
 *      2. Policy (pure Python, no model in the loop): decides AUTO / APPROVAL / NOTIFY.
 *         Only reversible, low-blast-radius actions may run unattended. Findings are never
 *         suppressed or auto-closed (recall-preserving design).
 *      3. Approval via single-use HMAC-signed e-mail links (no console login required).
 *      4. Containment Lambda executes the playbook with tag-scoped IAM permissions.
 *      5. Every step is recorded in an incidents table (audit trail + evaluation dataset).
 *
 * A weekly Bedrock-generated posture report translates Security Hub, Config, GuardDuty, Inspector
 * and Backup status into a one-page e-mail for hospital leadership.
 */
export class AiSentinel extends Construct {
  public readonly incidents: dynamodb.TableV2;
  public readonly stateMachine: sfn.StateMachine;
  public readonly approvalApi: apigw.RestApi;
  public readonly functions: lambda.Function[] = [];

  constructor(scope: Construct, id: string, props: AiSentinelProps) {
    super(scope, id);
    const cfg = props.config;
    const stack = cdk.Stack.of(this);
    const slug = cfg.organization.slug!;
    const ai = cfg.security.aiTriage;

    // --------------------------------------------------------------- Storage
    this.incidents = new dynamodb.TableV2(this, 'Incidents', {
      tableName: `${slug}-rural-shield-incidents`,
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billing: dynamodb.Billing.onDemand(),
      encryption: dynamodb.TableEncryptionV2.customerManagedKey(props.key),
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      deletionProtection: true,
      timeToLiveAttribute: 'ttl',
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const signingSecret = new secretsmanager.Secret(this, 'ApprovalSigningSecret', {
      secretName: `${slug}/rural-shield/approval-signing`,
      description: 'HMAC key for single-use approval links (rotated by RuralShield)',
      encryptionKey: props.key,
      generateSecretString: { passwordLength: 48, excludePunctuation: true },
    });

    // -------------------------------------------------------------- Guardrail
    const guardrail = new bedrock.CfnGuardrail(this, 'Guardrail', {
      name: `${slug}-rural-shield-triage`,
      description: 'Blocks prompt-injection carried in attacker-controlled finding fields and masks PII/PHI identifiers',
      blockedInputMessaging: 'Input blocked by RuralShield guardrail.',
      blockedOutputsMessaging: 'Output blocked by RuralShield guardrail.',
      contentPolicyConfig: {
        filtersConfig: [
          { type: 'PROMPT_ATTACK', inputStrength: 'HIGH', outputStrength: 'NONE' },
          { type: 'HATE', inputStrength: 'MEDIUM', outputStrength: 'MEDIUM' },
          { type: 'INSULTS', inputStrength: 'MEDIUM', outputStrength: 'MEDIUM' },
          { type: 'SEXUAL', inputStrength: 'HIGH', outputStrength: 'HIGH' },
          { type: 'VIOLENCE', inputStrength: 'MEDIUM', outputStrength: 'MEDIUM' },
          { type: 'MISCONDUCT', inputStrength: 'MEDIUM', outputStrength: 'MEDIUM' },
        ],
      },
      sensitiveInformationPolicyConfig: {
        piiEntitiesConfig: [
          { type: 'US_SOCIAL_SECURITY_NUMBER', action: 'ANONYMIZE' },
          { type: 'EMAIL', action: 'ANONYMIZE' },
          { type: 'PHONE', action: 'ANONYMIZE' },
          { type: 'NAME', action: 'ANONYMIZE' },
          { type: 'ADDRESS', action: 'ANONYMIZE' },
          { type: 'CREDIT_DEBIT_CARD_NUMBER', action: 'ANONYMIZE' },
        ],
      },
    });
    const guardrailVersion = new bedrock.CfnGuardrailVersion(this, 'GuardrailVersion', {
      guardrailIdentifier: guardrail.attrGuardrailId,
      description: 'v1',
    });

    // --------------------------------------------------------------- Lambdas
    const common = {
      INCIDENTS_TABLE: this.incidents.tableName,
      ALERTS_TOPIC_ARN: props.alerts.topicArn,
      ORG_NAME: cfg.organization.name,
      ENVIRONMENT: cfg.organization.environment,
      MODEL_ID: ai.modelId,
      GUARDRAIL_ID: guardrail.attrGuardrailId,
      GUARDRAIL_VERSION: guardrailVersion.attrVersion,
      AUTO_CONTAINMENT: String(ai.autoContainment),
      APPROVAL_TIMEOUT_HOURS: String(ai.approvalTimeoutHours ?? 24),
      SIGNING_SECRET_ARN: signingSecret.secretArn,
      LOG_ARCHIVE_BUCKET: props.logArchive.bucketName,
      PROTECTED_TAG: 'rural-shield:protected',
    };

    const triage = this.fn('Triage', 'triage', props, common, { timeout: 120, memory: 1024 });
    const approvalRequest = this.fn('ApprovalRequest', 'approval_request', props, common, { timeout: 30, memory: 256 });
    const approvalApi = this.fn('ApprovalApi', 'approval_api', props, common, { timeout: 15, memory: 256 });
    const contain = this.fn('Contain', 'contain', props, common, { timeout: 120, memory: 512 });
    const report = this.fn('Report', 'report', props, common, { timeout: 300, memory: 1024 });

    const rotate = this.fn('RotateApprovalSigningKey', 'rotate_approval_secret', props,
      { SIGNING_SECRET_ARN: signingSecret.secretArn }, { timeout: 30, memory: 256 });
    props.key.grantEncryptDecrypt(rotate);
    const rotationGrant = iam.Grant.addToPrincipal({
      grantee: rotate,
      actions: ['secretsmanager:DescribeSecret', 'secretsmanager:GetSecretValue',
        'secretsmanager:PutSecretValue', 'secretsmanager:UpdateSecretVersionStage'],
      resourceArns: [signingSecret.secretArn],
    });
    const rotationPermission = new lambda.CfnPermission(this, 'AllowSecretRotation', {
      action: 'lambda:InvokeFunction', functionName: rotate.functionArn,
      principal: 'secretsmanager.amazonaws.com', sourceAccount: stack.account,
      sourceArn: signingSecret.secretArn,
    });
    // L1 avoids a reverse dependency on the shared Foundation key policy.
    const rotation = new secretsmanager.CfnRotationSchedule(this, 'SigningKeyRotation', {
      secretId: signingSecret.secretArn, rotationLambdaArn: rotate.functionArn,
      rotationRules: { automaticallyAfterDays: 30 }, rotateImmediatelyOnUpdate: true,
    });
    rotation.node.addDependency(rotationPermission);
    rotationGrant.applyBefore(rotation);

    for (const f of [triage, approvalRequest, approvalApi, contain, report]) {
      this.incidents.grantReadWriteData(f);
      props.alerts.grantPublish(f);
      props.key.grantEncryptDecrypt(f);
    }
    // KMS access is granted above. Secret.grantRead would also mutate the shared
    // Foundation key policy with Sentinel role ARNs, creating a stack dependency cycle.
    for (const f of [approvalRequest, approvalApi]) {
      f.addToRolePolicy(new iam.PolicyStatement({
        actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
        resources: [signingSecret.secretArn],
      }));
    }
    // KMS access is already granted above. Keep this grant on the Sentinel role
    // rather than adding a reverse reference to Foundation's key policy.
    report.addToRolePolicy(new iam.PolicyStatement({
      actions: ['s3:PutObject'], resources: [props.logArchive.arnForObjects('posture-reports/*')],
    }));

    const bedrockInvoke = new iam.PolicyStatement({
      sid: 'BedrockInvoke',
      actions: ['bedrock:InvokeModel', 'bedrock:InvokeModelWithResponseStream'],
      resources: ai.modelResourceArns?.length ? [
        ai.modelId.startsWith('arn:') ? ai.modelId
          : `arn:${stack.partition}:bedrock:${stack.region}:${stack.account}:inference-profile/${ai.modelId}`,
        ...ai.modelResourceArns,
      ] : [ai.modelId.startsWith('arn:') ? ai.modelId
        : `arn:${stack.partition}:bedrock:${stack.region}::foundation-model/${ai.modelId}`],
    });
    const guardrailApply = new iam.PolicyStatement({
      sid: 'BedrockGuardrail',
      actions: ['bedrock:ApplyGuardrail'],
      resources: [guardrail.attrGuardrailArn],
    });
    triage.addToRolePolicy(bedrockInvoke);
    triage.addToRolePolicy(guardrailApply);
    report.addToRolePolicy(bedrockInvoke);
    report.addToRolePolicy(guardrailApply);

    // Read-only enrichment for triage; write-back of notes/workflow NOTIFIED (never SUPPRESSED).
    triage.addToRolePolicy(new iam.PolicyStatement({
      sid: 'EnrichAndAnnotate',
      actions: [
        'securityhub:GetFindings', 'securityhub:BatchUpdateFindings',
        'guardduty:GetFindings', 'guardduty:ListDetectors',
        'cloudtrail:LookupEvents',
        'iam:GetUser', 'iam:GetRole', 'iam:ListAccessKeys', 'iam:ListUserTags', 'iam:ListRoleTags',
        's3:GetBucketTagging', 's3:GetBucketPublicAccessBlock', 's3:GetBucketPolicyStatus',
        'lambda:GetFunction', 'lambda:ListTags',
      ],
      resources: ['*'],
    }));

    // Containment permissions are scoped by resource tag: anything tagged rural-shield:protected=true
    // (the framework's own roles, the ALB security group, the workload function) can never be acted upon.
    const notProtected = { StringNotEquals: { 'aws:ResourceTag/rural-shield:protected': 'true' } };
    contain.addToRolePolicy(new iam.PolicyStatement({
      sid: 'ContainIam',
      actions: ['iam:UpdateAccessKey', 'iam:ListAccessKeys', 'iam:PutRolePolicy', 'iam:DeleteRolePolicy', 'iam:GetRole', 'iam:GetUser', 'iam:TagRole', 'iam:TagUser', 'iam:ListUserTags', 'iam:ListRoleTags'],
      resources: [`arn:${stack.partition}:iam::${stack.account}:user/*`, `arn:${stack.partition}:iam::${stack.account}:role/*`],
      conditions: notProtected,
    }));
    contain.addToRolePolicy(new iam.PolicyStatement({
      sid: 'ContainS3',
      actions: ['s3:PutBucketPublicAccessBlock', 's3:GetBucketPublicAccessBlock', 's3:GetBucketTagging'],
      resources: [`arn:${stack.partition}:s3:::*`],
      conditions: { StringEquals: { 's3:ResourceAccount': stack.account } },
    }));
    contain.addToRolePolicy(new iam.PolicyStatement({
      sid: 'ContainLambda',
      actions: ['lambda:PutFunctionConcurrency', 'lambda:GetFunctionConcurrency', 'lambda:DeleteFunctionConcurrency', 'lambda:GetFunction', 'lambda:ListTags'],
      resources: [`arn:${stack.partition}:lambda:${stack.region}:${stack.account}:function:*`],
      conditions: notProtected,
    }));
    contain.addToRolePolicy(new iam.PolicyStatement({
      sid: 'ContainSecurityGroups',
      actions: ['ec2:RevokeSecurityGroupIngress'],
      resources: [`arn:${stack.partition}:ec2:${stack.region}:${stack.account}:security-group/*`],
      conditions: notProtected,
    }));
    contain.addToRolePolicy(new iam.PolicyStatement({
      sid: 'DescribeForContainment',
      actions: ['ec2:DescribeSecurityGroups', 'ec2:DescribeSecurityGroupRules', 'securityhub:BatchUpdateFindings'],
      resources: ['*'],
    }));

    approvalApi.addToRolePolicy(new iam.PolicyStatement({
      sid: 'CompleteApprovalTask',
      actions: ['states:SendTaskSuccess', 'states:SendTaskFailure'],
      resources: ['*'], // task tokens are not ARN-addressable
    }));

    report.addToRolePolicy(new iam.PolicyStatement({
      sid: 'ReadPosture',
      actions: [
        'securityhub:GetFindings', 'securityhub:DescribeStandards', 'securityhub:GetEnabledStandards',
        'guardduty:ListDetectors', 'guardduty:GetFindingsStatistics',
        'config:DescribeComplianceByConfigRule', 'config:GetComplianceSummaryByConfigRule',
        'backup:ListBackupJobs', 'backup:ListRestoreJobs', 'backup:ListCopyJobs',
        'inspector2:ListFindingAggregations',
        'macie2:GetFindingStatistics',
      ],
      resources: ['*'],
    }));

    // ---------------------------------------------------------- State machine
    const sfnLogs = new logs.LogGroup(this, 'StateMachineLogs', {
      logGroupName: `/rural-shield/${slug}/sentinel/state-machine`,
      encryptionKey: props.key,
      retention: props.appLogRetention,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const triageTask = new tasks.LambdaInvoke(this, 'TriageFinding', {
      lambdaFunction: triage.currentVersion,
      payloadResponseOnly: true,
      resultPath: '$.triage',
      retryOnServiceExceptions: true,
    });
    triageTask.addRetry({ errors: ['ThrottlingException', 'ModelNotReadyException', 'ServiceUnavailableException'], interval: cdk.Duration.seconds(10), maxAttempts: 4, backoffRate: 2 });

    const containTask = new tasks.LambdaInvoke(this, 'ExecutePlaybook', {
      lambdaFunction: contain.currentVersion,
      payloadResponseOnly: true,
      resultPath: '$.containment',
    });

    const requestApproval = new tasks.LambdaInvoke(this, 'RequestHumanApproval', {
      lambdaFunction: approvalRequest.currentVersion,
      integrationPattern: sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
      payload: sfn.TaskInput.fromObject({
        taskToken: sfn.JsonPath.taskToken,
        incident: sfn.JsonPath.entirePayload,
      }),
      resultPath: '$.approval',
      taskTimeout: sfn.Timeout.duration(cdk.Duration.hours(ai.approvalTimeoutHours ?? 24)),
    });

    const notifyOnly = new tasks.SnsPublish(this, 'NotifyOnly', {
      topic: props.alerts,
      subject: sfn.JsonPath.format('[RuralShield] {} - no automated action taken', sfn.JsonPath.stringAt('$.triage.title')),
      message: sfn.TaskInput.fromJsonPathAt('$.triage.email_body'),
      resultPath: sfn.JsonPath.DISCARD,
    });
    const notifyDenied = new tasks.SnsPublish(this, 'NotifyDenied', {
      topic: props.alerts,
      subject: sfn.JsonPath.format('[RuralShield] {} - containment declined by approver', sfn.JsonPath.stringAt('$.triage.title')),
      message: sfn.TaskInput.fromJsonPathAt('$.triage.email_body'),
      resultPath: sfn.JsonPath.DISCARD,
    });
    const notifyTimeout = new tasks.SnsPublish(this, 'EscalateApprovalTimeout', {
      topic: props.alerts,
      subject: sfn.JsonPath.format('[RuralShield] ESCALATION: no decision on {} within the approval window', sfn.JsonPath.stringAt('$.triage.title')),
      message: sfn.TaskInput.fromJsonPathAt('$.triage.email_body'),
      resultPath: sfn.JsonPath.DISCARD,
    });
    requestApproval.addCatch(notifyTimeout, { errors: ['States.Timeout', 'States.TaskFailed'], resultPath: '$.approvalError' });

    const done = new sfn.Succeed(this, 'Done');
    const approvedChoice = new sfn.Choice(this, 'WasApproved?')
      .when(sfn.Condition.booleanEquals('$.approval.approved', true), containTask)
      .otherwise(notifyDenied);

    const route = new sfn.Choice(this, 'RouteByPolicy')
      .when(sfn.Condition.stringEquals('$.triage.action_mode', 'AUTO'), containTask)
      .when(sfn.Condition.stringEquals('$.triage.action_mode', 'APPROVAL'), requestApproval.next(approvedChoice))
      .otherwise(notifyOnly);

    containTask.next(done);
    notifyOnly.next(done);
    notifyDenied.next(done);
    notifyTimeout.next(done);

    this.stateMachine = new sfn.StateMachine(this, 'StateMachine', {
      stateMachineName: `${slug}-rural-shield-sentinel`,
      definitionBody: sfn.DefinitionBody.fromChainable(triageTask.next(route)),
      timeout: cdk.Duration.hours((ai.approvalTimeoutHours ?? 24) + 1),
      tracingEnabled: true,
      logs: { destination: sfnLogs, level: sfn.LogLevel.ALL, includeExecutionData: true },
    });
    props.key.grantEncryptDecrypt(this.stateMachine);

    // -------------------------------------------------------------- EventBridge
    const ruleDlq = new sqs.Queue(this, 'RuleDlq', {
      queueName: `${slug}-rural-shield-events-dlq`,
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: props.key,
      enforceSSL: true,
      retentionPeriod: cdk.Duration.days(14),
    });
    NagSuppressions.addResourceSuppressions(ruleDlq, [{
      id: 'AwsSolutions-SQS3',
      reason: 'This queue is the dead-letter destination of three EventBridge targets, not a source queue. Its backlog is alarmed for operator redrive.',
    }]);
    const deliveryFailure = new cloudwatch.Alarm(this, 'EventDeliveryFailure', {
      metric: ruleDlq.metricApproximateNumberOfMessagesVisible(), threshold: 1,
      evaluationPeriods: 1, treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'RuralShield EventBridge delivery failed; inspect and redrive the event DLQ.',
    });
    deliveryFailure.addAlarmAction(new cwActions.SnsAction(props.alerts));
    const severities = ai.minimumSeverity === 'MEDIUM'
      ? ['MEDIUM', 'HIGH', 'CRITICAL']
      : ai.minimumSeverity === 'CRITICAL' ? ['CRITICAL'] : ['HIGH', 'CRITICAL'];

    new events.Rule(this, 'SecurityHubFindings', {
      ruleName: `${slug}-rural-shield-securityhub`,
      description: 'Route new high-severity Security Hub findings (ASFF) to the RuralShield triage pipeline',
      eventPattern: {
        source: ['aws.securityhub'],
        detailType: ['Security Hub Findings - Imported'],
        detail: {
          findings: {
            RecordState: ['ACTIVE'],
            Workflow: { Status: ['NEW'] },
            Severity: { Label: severities },
          },
        },
      },
      targets: [new targets.SfnStateMachine(this.stateMachine, { deadLetterQueue: ruleDlq, retryAttempts: 3 })],
    });
    new events.Rule(this, 'GuardDutyAttackSequences', {
      ruleName: `${slug}-rural-shield-attack-sequences`,
      description: 'Route GuardDuty Extended Threat Detection attack sequences directly (lowest latency)',
      eventPattern: {
        source: ['aws.guardduty'],
        detailType: ['GuardDuty Finding'],
        detail: { type: [{ prefix: 'AttackSequence' }] },
      },
      targets: [new targets.SfnStateMachine(this.stateMachine, { deadLetterQueue: ruleDlq, retryAttempts: 3 })],
    });

    // ------------------------------------------------------------- Approval API
    this.approvalApi = this.createApprovalApi(approvalApi, props, slug);
    approvalRequest.addEnvironment('APPROVAL_BASE_URL', this.approvalApi.url);

    // ------------------------------------------------------------ Weekly report
    if (cfg.security.compliance.weeklyReport) {
      new events.Rule(this, 'WeeklyReport', {
        ruleName: `${slug}-rural-shield-weekly-report`,
        description: 'Monday 09:00 (US Central) plain-English security posture report',
        schedule: events.Schedule.cron({ weekDay: 'MON', hour: '14', minute: '0' }),
        targets: [new targets.LambdaFunction(report, { deadLetterQueue: ruleDlq, retryAttempts: 2 })],
      });
    }

    // Mark our own functions and roles as protected so containment can never turn on the framework.
    for (const f of this.functions) {
      cdk.Tags.of(f).add('rural-shield:protected', 'true');
    }

    new cdk.CfnOutput(this, 'SentinelStateMachineArn', { value: this.stateMachine.stateMachineArn });
    new cdk.CfnOutput(this, 'IncidentsTable', { value: this.incidents.tableName });
  }

  private fn(id: string, dir: string, props: AiSentinelProps, env: Record<string, string>, opts: { timeout: number; memory: number }): lambda.Function {
    const slug = props.config.organization.slug!;
    const logGroup = new logs.LogGroup(this, `${id}Logs`, {
      logGroupName: `/rural-shield/${slug}/sentinel/${dir}`,
      encryptionKey: props.key,
      retention: props.appLogRetention,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const dlq = new sqs.Queue(this, `${id}Dlq`, {
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: props.key,
      enforceSSL: true,
      retentionPeriod: cdk.Duration.days(14),
    });
    const f = new lambda.Function(this, id, {
      functionName: `${slug}-rural-shield-${dir.replace(/_/g, '-')}`,
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.ARM_64,
      handler: 'handler.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', '..', 'src', 'lambda', dir)),
      timeout: cdk.Duration.seconds(opts.timeout),
      memorySize: opts.memory,
      reservedConcurrentExecutions: 10,
      environment: env,
      environmentEncryption: props.key,
      tracing: lambda.Tracing.ACTIVE,
      deadLetterQueue: dlq,
      logGroup,
      description: `RuralShield AI Sentinel - ${dir}`,
    });
    this.functions.push(f);
    return f;
  }

  private createApprovalApi(handler: lambda.Function, props: AiSentinelProps, slug: string): apigw.RestApi {
    const accessLogs = new logs.LogGroup(this, 'ApprovalApiAccessLogs', {
      logGroupName: `/rural-shield/${slug}/sentinel/approval-api-access`,
      encryptionKey: props.key,
      retention: props.appLogRetention,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const clientCert = new apigw.CfnClientCertificate(this, 'ApprovalClientCert');
    const api = new apigw.RestApi(this, 'ApprovalRestApi', {
      restApiName: `${slug}-rural-shield-approvals`,
      description: 'Single-use, HMAC-signed approve/deny links for RuralShield containment actions',
      endpointConfiguration: { types: [apigw.EndpointType.REGIONAL] },
      cloudWatchRole: true,
      deployOptions: {
        stageName: 'v1',
        loggingLevel: apigw.MethodLoggingLevel.INFO,
        dataTraceEnabled: false,
        metricsEnabled: true,
        tracingEnabled: true,
        accessLogDestination: new apigw.LogGroupLogDestination(accessLogs),
        accessLogFormat: apigw.AccessLogFormat.jsonWithStandardFields({
          caller: true, httpMethod: true, ip: true, protocol: true, requestTime: true,
          resourcePath: true, responseLength: true, status: true, user: true,
        }),
        throttlingRateLimit: 5,
        throttlingBurstLimit: 10,
        clientCertificateId: clientCert.attrClientCertificateId,
      },
    });
    const validator = new apigw.RequestValidator(this, 'ApprovalValidator', {
      restApi: api,
      validateRequestParameters: true,
      validateRequestBody: true,
    });
    api.root.addResource('decision').addMethod('GET', new apigw.LambdaIntegration(handler), {
      // Authentication is the single-use HMAC token in the link; the approver is not logged in to AWS.
      authorizationType: apigw.AuthorizationType.NONE,
      requestValidator: validator,
      requestParameters: {
        'method.request.querystring.id': true,
        'method.request.querystring.action': true,
        'method.request.querystring.sig': true,
      },
    });

    const acl = new wafv2.CfnWebACL(this, 'ApprovalWaf', {
      name: `${slug}-rural-shield-approvals`,
      scope: 'REGIONAL',
      defaultAction: { allow: {} },
      visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: `${slug}-approvals` },
      rules: [
        {
          name: 'AWSManagedRulesCommonRuleSet', priority: 0, overrideAction: { none: {} },
          statement: { managedRuleGroupStatement: { vendorName: 'AWS', name: 'AWSManagedRulesCommonRuleSet' } },
          visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: 'Common' },
        },
        {
          name: 'AWSManagedRulesAmazonIpReputationList', priority: 1, overrideAction: { none: {} },
          statement: { managedRuleGroupStatement: { vendorName: 'AWS', name: 'AWSManagedRulesAmazonIpReputationList' } },
          visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: 'IpRep' },
        },
        {
          name: 'RateLimit', priority: 10, action: { block: {} },
          statement: { rateBasedStatement: { limit: 100, aggregateKeyType: 'IP' } },
          visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: 'RateLimit' },
        },
      ],
    });
    new wafv2.CfnWebACLAssociation(this, 'ApprovalWafAssoc', { resourceArn: api.deploymentStage.stageArn, webAclArn: acl.attrArn });
    const wafLogs = new logs.LogGroup(this, 'ApprovalWafLogs', {
      logGroupName: `aws-waf-logs-${slug}-rural-shield-approvals`,
      encryptionKey: props.key,
      retention: props.appLogRetention,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    new wafv2.CfnLoggingConfiguration(this, 'ApprovalWafLogging', { resourceArn: acl.attrArn, logDestinationConfigs: [wafLogs.logGroupArn] });
    return api;
  }
}
