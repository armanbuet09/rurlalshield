/** Isolated synthetic workflow. This entry point is never imported by the pilot app. */
import * as cdk from 'aws-cdk-lib';
import {Construct} from 'constructs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as events from 'aws-cdk-lib/aws-events';
import * as eventTargets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secrets from 'aws-cdk-lib/aws-secretsmanager';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import * as tasks from 'aws-cdk-lib/aws-stepfunctions-tasks';
import * as path from 'path';
import * as fs from 'fs';
import {execFileSync} from 'child_process';

export interface AiWorkflowProps extends cdk.StackProps {
  assetPath: string;
  apiSecretArn: string;
  alertEmail: string;
  enabled?: boolean;
  finalArchive?: string;
}

export const SUITE = 'ruralshield-external-workflow-20261031';
export const MODEL_CASES = ['posture', 'lambda_threat', 'lambda_injection', 'weekly_narration'];
export const CONTROL_CASES = ['control_notify', 'control_approve', 'control_deny', 'control_timeout', 'control_model_failure'];

export class AiWorkflowStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: AiWorkflowProps) {
    super(scope, id, props);
    const arn = /^arn:aws:secretsmanager:([\w-]+):(\d{12}):secret:[\w/+=.@-]+$/.exec(props.apiSecretArn);
    if (!arn || arn[1] !== this.region || arn[2] !== this.account) {
      throw new Error('Provide one exact same-account, same-region API secret ARN');
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(props.alertEmail)) throw new Error('Provide the research alert email');
    let archiveHash = 'not-activated';
    if (props.enabled) {
      if (!props.finalArchive) throw new Error('Activation requires the independently verified final archive');
      const result = JSON.parse(execFileSync(path.resolve('.venv/Scripts/python.exe'),
        [path.resolve('scripts/verify-ai-workflow-gate.py'), '--archive', path.resolve(props.finalArchive)],
        {encoding: 'utf8'}));
      archiveHash = result.manifest_sha256;
      if (!/^[a-f0-9]{64}$/.test(archiveHash)) throw new Error('Invalid final archive verification result');
    }
    const table = new dynamodb.Table(this, 'Incidents', {
      partitionKey: {name:'pk', type:dynamodb.AttributeType.STRING},
      billingMode:dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption:dynamodb.TableEncryption.AWS_MANAGED,
      removalPolicy:cdk.RemovalPolicy.RETAIN, deletionProtection:true,
    });
    const topic = new sns.Topic(this, 'ResearchAlerts', {enforceSSL:true});
    topic.addSubscription(new subscriptions.EmailSubscription(props.alertEmail));
    const signing = new secrets.Secret(this, 'ApprovalSigning', {
      description:'Separate synthetic experiment approval signing key',
      generateSecretString:{passwordLength:48, excludePunctuation:true},
      removalPolicy:cdk.RemovalPolicy.RETAIN,
    });
    // No workload, user credentials or traffic can depend on this disposable target.
    const targetRole = new iam.Role(this, 'DisposableRole', {assumedBy:new iam.ServicePrincipal('lambda.amazonaws.com')});
    const disposable = new lambda.Function(this, 'DisposableTarget', {
      role:targetRole, runtime:lambda.Runtime.PYTHON_3_13, architecture:lambda.Architecture.ARM_64,
      handler:'index.handler', code:lambda.Code.fromInline('def handler(event, context):\n    return {"synthetic": True}\n'),
      reservedConcurrentExecutions:1, timeout:cdk.Duration.seconds(3), retryAttempts:0,
    });
    cdk.Tags.of(disposable).add('rural-shield:experiment-target',SUITE);
    cdk.Tags.of(disposable).add('rural-shield:protected','false');
    const common = {
      SUITE_ID:SUITE, WORKFLOW_ENABLED:String(props.enabled ?? false),
      MODEL_ESTIMATE_BUDGET_USD:'0.048631325',
      FINAL_ARCHIVE_MANIFEST_SHA256:archiveHash,
      INCIDENTS_TABLE:table.tableName, ALERTS_TOPIC_ARN:topic.topicArn,
      DISPOSABLE_TARGET_ARN:disposable.functionArn,
      ORG_NAME:'RuralShield separate synthetic AI research',
    };
    const functions: Record<string,lambda.Function> = {};
    for (const method of ['triage','request_approval','decision','contain','rollback','finish']) {
      const group = new logs.LogGroup(this, method+'Logs', {
        retention:logs.RetentionDays.ONE_WEEK, removalPolicy:cdk.RemovalPolicy.RETAIN,
      });
      const role = new iam.Role(this, method+'Role', {assumedBy:new iam.ServicePrincipal('lambda.amazonaws.com')});
      role.addToPolicy(new iam.PolicyStatement({actions:['logs:CreateLogStream','logs:PutLogEvents'], resources:[group.logGroupArn]}));
      role.addToPolicy(new iam.PolicyStatement({actions:['dynamodb:GetItem','dynamodb:PutItem','dynamodb:UpdateItem'], resources:[table.tableArn]}));
      const fn = new lambda.Function(this, method, {
        role, runtime:lambda.Runtime.PYTHON_3_13, architecture:lambda.Architecture.ARM_64,
        handler:'handlers.'+method, code:lambda.Code.fromAsset(props.assetPath),
        logGroup:group, memorySize:256, timeout:cdk.Duration.seconds(method==='triage'?60:30),
        reservedConcurrentExecutions:1, retryAttempts:0, environment:common,
      });
      cdk.Tags.of(fn).add('rural-shield:protected','true');
      cdk.Tags.of(role).add('rural-shield:protected','true');
      functions[method]=fn;
    }
    functions.triage.addEnvironment('API_SECRET_ARN', props.apiSecretArn);
    functions.triage.addToRolePolicy(new iam.PolicyStatement({actions:['secretsmanager:GetSecretValue'],resources:[props.apiSecretArn]}));
    for (const method of ['request_approval','decision']) {
      functions[method].addEnvironment('SIGNING_SECRET_ARN',signing.secretArn);
      signing.grantRead(functions[method]);
    }
    for (const method of ['request_approval','finish']) topic.grantPublish(functions[method]);
    functions.decision.addToRolePolicy(new iam.PolicyStatement({actions:['states:SendTaskSuccess'], resources:['*']}));
    for (const method of ['contain','rollback']) {
      functions[method].addToRolePolicy(new iam.PolicyStatement({
        actions:['lambda:ListTags','lambda:GetFunctionConcurrency','lambda:PutFunctionConcurrency'],
        resources:[disposable.functionArn],
      }));
    }
    const approvalUrl = functions.decision.addFunctionUrl({authType:lambda.FunctionUrlAuthType.NONE});
    functions.request_approval.addEnvironment('APPROVAL_URL',approvalUrl.url);
    const invoke = (name:string, method:string, resultPath:string, payload?:sfn.TaskInput) =>
      new tasks.LambdaInvoke(this,name,{lambdaFunction:functions[method],payloadResponseOnly:true,
        retryOnServiceExceptions:false,resultPath,...(payload?{payload}:{})});
    const triage = invoke('AssessSyntheticCase','triage','$.triage',sfn.TaskInput.fromObject({
      suite_id:sfn.JsonPath.stringAt('$.suite_id'),case_id:sfn.JsonPath.stringAt('$.case_id'),
    }));
    const finish = invoke('RecordAndNotifyOutcome','finish','$.result');
    const outcome = (name:string,status:string) => new sfn.Pass(this,name,{
      result:sfn.Result.fromObject({status}),resultPath:'$.outcome',
    }).next(finish);
    const failed = outcome('WorkflowError','WORKFLOW_FAILED');
    const timedOut = outcome('ApprovalExpired','APPROVAL_TIMEOUT');
    const denied = outcome('ApprovalDeclined','APPROVAL_DENIED');
    const refused = outcome('ContainmentRefused','CONTAINMENT_REFUSED');
    const rollbackFailed = outcome('RollbackFailed','ROLLBACK_FAILED');
    const restored = outcome('RollbackVerified','ROLLED_BACK');
    const contain = invoke('ExecuteDisposablePlaybook','contain','$.containment',sfn.TaskInput.fromObject({
      incident_id:sfn.JsonPath.stringAt('$.triage.incident_id'),approval_id:sfn.JsonPath.stringAt('$.approval.approval_id'),
    }));
    const rollback = invoke('RestoreDisposableTarget','rollback','$.rollback',sfn.TaskInput.fromObject({
      incident_id:sfn.JsonPath.stringAt('$.triage.incident_id'),
    }));
    rollback.addCatch(rollbackFailed,{resultPath:'$.task_error'});
    rollback.next(new sfn.Choice(this,'RollbackSucceeded')
      .when(sfn.Condition.stringEquals('$.rollback.status','ROLLED_BACK'),restored).otherwise(rollbackFailed));
    contain.addCatch(failed,{resultPath:'$.task_error'});
    contain.next(new sfn.Choice(this,'ActionVerified')
      .when(sfn.Condition.stringEquals('$.containment.status','CONTAINED'),rollback).otherwise(refused));
    const approved = new sfn.Choice(this,'HumanApproved')
      .when(sfn.Condition.booleanEquals('$.approval.approved',true),contain).otherwise(denied);
    const request = (name:string,seconds:number) => {
      const task = new tasks.LambdaInvoke(this,name,{
        lambdaFunction:functions.request_approval,
        integrationPattern:sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
        payload:sfn.TaskInput.fromObject({taskToken:sfn.JsonPath.taskToken,
          incident_id:sfn.JsonPath.stringAt('$.triage.incident_id')}),
        resultPath:'$.approval',retryOnServiceExceptions:false,
        taskTimeout:sfn.Timeout.duration(cdk.Duration.seconds(seconds)),
      });
      task.addCatch(timedOut,{errors:['States.Timeout'],resultPath:'$.task_error'});
      task.addCatch(failed,{resultPath:'$.task_error'});
      task.next(approved);
      return task;
    };
    const route = new sfn.Choice(this,'RouteByRecordedPolicy')
      .when(sfn.Condition.stringEquals('$.triage.route','STOP'),new sfn.Succeed(this,'StoppedWithoutSideEffects'))
      .when(sfn.Condition.stringEquals('$.triage.route','APPROVAL'),request('WaitForHuman',900))
      .when(sfn.Condition.stringEquals('$.triage.route','APPROVAL_TIMEOUT_CONTROL'),request('TimeoutControl',10))
      .when(sfn.Condition.stringEquals('$.triage.route','REPORT'),outcome('NarrationReady','REPORT_SENT'))
      .otherwise(outcome('NotificationOnly','NOTIFIED'));
    const machineLogs = new logs.LogGroup(this,'WorkflowLogs',{
      retention:logs.RetentionDays.ONE_WEEK,removalPolicy:cdk.RemovalPolicy.RETAIN,
    });
    const machine = new sfn.StateMachine(this,'Workflow',{
      definitionBody:sfn.DefinitionBody.fromChainable(triage.next(route)),
      timeout:cdk.Duration.minutes(20),
      logs:{destination:machineLogs,level:sfn.LogLevel.ERROR,includeExecutionData:false},
    });
    const bus = new events.EventBus(this,'SyntheticBus');
    const dlq = new sqs.Queue(this,'DeliveryFailures',{
      encryption:sqs.QueueEncryption.SQS_MANAGED,enforceSSL:true,
      retentionPeriod:cdk.Duration.days(7),removalPolicy:cdk.RemovalPolicy.RETAIN,
    });
    const rule = new events.Rule(this,'SyntheticCases',{
      eventBus:bus,enabled:props.enabled ?? false,
      eventPattern:{source:['ruralshield.synthetic'],detailType:['RuralShield Synthetic Case'],
        detail:{suite_id:[SUITE],case_id:[...MODEL_CASES,...CONTROL_CASES]}},
      targets:[new eventTargets.SfnStateMachine(machine,{
        input:events.RuleTargetInput.fromEventPath('$.detail'),retryAttempts:0,deadLetterQueue:dlq,
      })],
    });
    for (const [name,value] of Object.entries({WorkflowArn:machine.stateMachineArn,
      SyntheticBusName:bus.eventBusName,SyntheticRuleName:rule.ruleName,
      IncidentsTableName:table.tableName,AlertsTopicArn:topic.topicArn,
      SigningSecretArn:signing.secretArn,ApprovalUrl:approvalUrl.url,
      DisposableTargetArn:disposable.functionArn,FailureQueueUrl:dlq.queueUrl,SuiteId:SUITE})) {
      new cdk.CfnOutput(this,name,{value});
    }
    cdk.Tags.of(this).add('rural-shield:purpose','separate-synthetic-ai-workflow');
  }
}

if (require.main === module) {
  const app = new cdk.App({outdir:'cdk.out/ai-workflow-synth'});
  const assetPath = path.resolve('cdk.out/external-ai-workflow-asset');
  if (!fs.existsSync(path.join(assetPath,'source-manifest.json'))) throw new Error('Package the separate workflow first');
  execFileSync(path.resolve('.venv/Scripts/python.exe'),[path.resolve('scripts/package-ai-workflow.py'),'--verify'],{stdio:'pipe'});
  new AiWorkflowStack(app,'RuralShield-ExternalAiWorkflow',{
    env:{account:'123456789012',region:'us-east-2'},assetPath,
    apiSecretArn:app.node.tryGetContext('workflowApiSecretArn'),
    alertEmail:app.node.tryGetContext('workflowAlertEmail'),
    enabled:app.node.tryGetContext('workflowEnabled') === 'true',
    finalArchive:app.node.tryGetContext('workflowFinalArchive'),
    description:'Isolated synthetic external AI workflow; not the frozen non-AI pilot',
  });
  app.synth();
}
