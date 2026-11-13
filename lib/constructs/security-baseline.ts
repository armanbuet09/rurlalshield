import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as config from 'aws-cdk-lib/aws-config';
import * as guardduty from 'aws-cdk-lib/aws-guardduty';
import * as securityhub from 'aws-cdk-lib/aws-securityhub';
import * as macie from 'aws-cdk-lib/aws-macie';
import * as accessanalyzer from 'aws-cdk-lib/aws-accessanalyzer';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subs from 'aws-cdk-lib/aws-sns-subscriptions';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as cr from 'aws-cdk-lib/custom-resources';
import { RuralShieldConfig } from '../config';
import { LogDelivery } from './log-delivery';

export interface SecurityBaselineProps {
  readonly config: RuralShieldConfig;
}

/**
 * SecurityBaseline turns a bare AWS account into a HIPAA-aligned landing zone:
 *
 *  - One customer-managed KMS key (rotated) used for every encrypted resource.
 *  - An immutable (Object Lock, COMPLIANCE mode) log archive with 6-year retention:
 *    CloudTrail (all regions, file validation, S3 + Lambda data events), VPC flow logs,
 *    ALB/WAF logs, Config history.
 *  - Detection: GuardDuty (foundational + Extended Threat Detection + S3/Lambda/RDS plans),
 *    Security Hub (AFSBP, CIS, NIST 800-53 r5), Macie automated discovery, Inspector (Lambda/ECR),
 *    IAM Access Analyzer.
 *  - Account hardening: S3 account-level Block Public Access, IAM password policy.
 *  - CIS-style CloudWatch alarms on the CloudTrail log group (root use, no-MFA console login,
 *    IAM/KMS/CloudTrail/SG changes, unauthorized API calls) -> encrypted SNS topic -> e-mail.
 *
 * Everything here is AWS-managed: there is no agent, instance or OS to patch.
 */
export class SecurityBaseline extends Construct {
  public readonly key: kms.Key;
  public readonly logArchive: s3.Bucket;
  public readonly logDelivery: s3.Bucket;
  public readonly alerts: sns.Topic;
  public readonly trail?: cloudtrail.Trail;
  public readonly trailLogGroup?: logs.LogGroup;
  public readonly guardDutyDetector?: guardduty.CfnDetector;

  constructor(scope: Construct, id: string, props: SecurityBaselineProps) {
    super(scope, id);
    const cfg = props.config;
    const stack = cdk.Stack.of(this);
    const slug = cfg.organization.slug!;
    const existing = cfg.security.existingResources ?? {};

    // ------------------------------------------------------------------ KMS
    this.key = new kms.Key(this, 'Key', {
      alias: `alias/${slug}-rural-shield`,
      description: `RuralShield CMK for ${cfg.organization.name} (${cfg.organization.environment})`,
      enableKeyRotation: true,
      pendingWindow: cdk.Duration.days(30),
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    this.grantServicePrincipals(stack);

    // ------------------------------------------------------- Log archive (WORM)
    // Compatible log delivery is staged separately; the immutable archive uses the CMK.
    this.logArchive = new s3.Bucket(this, 'LogArchive', {
      bucketName: `${slug}-rshield-logs-${stack.account}-${stack.region}`,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.key,
      bucketKeyEnabled: true,
      enforceSSL: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      versioned: true,
      objectLockEnabled: true,
      // HIPAA §164.316(b)(2)(i): retain documentation six years. WORM protects audit trails from ransomware.
      objectLockDefaultRetention: s3.ObjectLockRetention.compliance(cdk.Duration.days(6 * 365)),
      lifecycleRules: [
        {
          id: 'tier-down',
          transitions: [
            { storageClass: s3.StorageClass.INFREQUENT_ACCESS, transitionAfter: cdk.Duration.days(90) },
            { storageClass: s3.StorageClass.GLACIER, transitionAfter: cdk.Duration.days(365) },
          ],
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(7),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // ----------------------------------------------------------- Alerts topic
    this.alerts = new sns.Topic(this, 'Alerts', {
      topicName: `${slug}-rural-shield-alerts`,
      displayName: `RuralShield alerts for ${cfg.organization.name}`,
      masterKey: this.key,
      enforceSSL: true,
    });
    this.alerts.addSubscription(new subs.EmailSubscription(cfg.organization.contactEmail));
    if (cfg.organization.secondaryContactEmail) {
      this.alerts.addSubscription(new subs.EmailSubscription(cfg.organization.secondaryContactEmail));
    }
    this.logDelivery = new LogDelivery(this, 'LogDelivery', {
      archive: this.logArchive, key: this.key, alerts: this.alerts,
      bucketName: `${slug}-rshield-delivery-${stack.account}-${stack.region}`,
    }).bucket;

    // -------------------------------------------------------------- CloudTrail
    if (!existing.cloudTrail) {
      this.trailLogGroup = new logs.LogGroup(this, 'TrailLogGroup', {
        logGroupName: `/rural-shield/${slug}/cloudtrail`,
        encryptionKey: this.key,
        retention: logs.RetentionDays.ONE_YEAR,
        removalPolicy: cdk.RemovalPolicy.RETAIN,
      });
      this.trail = new cloudtrail.Trail(this, 'Trail', {
        trailName: `${slug}-rural-shield`,
        bucket: this.logArchive,
        s3KeyPrefix: 'cloudtrail',
        encryptionKey: this.key,
        enableFileValidation: true,
        isMultiRegionTrail: true,
        includeGlobalServiceEvents: true,
        sendToCloudWatchLogs: true,
        cloudWatchLogGroup: this.trailLogGroup,
        insightTypes: [cloudtrail.InsightType.API_CALL_RATE, cloudtrail.InsightType.API_ERROR_RATE],
      });
      // Exclude writes to the audit delivery/archive buckets to avoid recursive
      // CloudTrail PutObject logging. Their reads remain audited separately.
      const auditBuckets = [`${this.logArchive.bucketArn}/`, `${this.logDelivery.bucketArn}/`];
      (this.trail.node.defaultChild as cloudtrail.CfnTrail).advancedEventSelectors = [
        { name: 'Management', fieldSelectors: [{ field: 'eventCategory', equalTo: ['Management'] }] },
        { name: 'WorkloadS3', fieldSelectors: [
          { field: 'eventCategory', equalTo: ['Data'] },
          { field: 'resources.type', equalTo: ['AWS::S3::Object'] },
          { field: 'resources.ARN', notStartsWith: auditBuckets },
        ] },
        { name: 'AuditBucketReads', fieldSelectors: [
          { field: 'eventCategory', equalTo: ['Data'] },
          { field: 'resources.type', equalTo: ['AWS::S3::Object'] },
          { field: 'resources.ARN', startsWith: auditBuckets },
          { field: 'readOnly', equalTo: ['true'] },
        ] },
        { name: 'LambdaInvocations', fieldSelectors: [
          { field: 'eventCategory', equalTo: ['Data'] },
          { field: 'resources.type', equalTo: ['AWS::Lambda::Function'] },
        ] },
      ];
      this.createCisAlarms(this.trailLogGroup);
    }

    // -------------------------------------------------------------- AWS Config
    if (cfg.security.compliance.configRules) {
      this.createConfig(existing.configRecorder ?? false);
    }

    // --------------------------------------------------------------- GuardDuty
    if (cfg.security.threatDetection.guardDuty && !existing.guardDutyDetector) {
      this.guardDutyDetector = new guardduty.CfnDetector(this, 'GuardDuty', {
        enable: true,
        findingPublishingFrequency: 'FIFTEEN_MINUTES',
        features: [
          { name: 'S3_DATA_EVENTS', status: 'ENABLED' },
          { name: 'LAMBDA_NETWORK_LOGS', status: 'ENABLED' },
          { name: 'RDS_LOGIN_EVENTS', status: 'ENABLED' },
          { name: 'EBS_MALWARE_PROTECTION', status: 'DISABLED' }, // no EC2 in a serverless estate
          { name: 'EKS_AUDIT_LOGS', status: 'DISABLED' },
          {
            name: 'RUNTIME_MONITORING',
            status: 'ENABLED',
            additionalConfiguration: [
              { name: 'ECS_FARGATE_AGENT_MANAGEMENT', status: 'ENABLED' }, // auto-injects the agent sidecar
              { name: 'EC2_AGENT_MANAGEMENT', status: 'DISABLED' },
              { name: 'EKS_ADDON_MANAGEMENT', status: 'DISABLED' },
            ],
          },
        ],
      });
      // Extended Threat Detection (attack-sequence correlation) is enabled automatically at no cost.
    }

    // ------------------------------------------------------------ Security Hub
    if (cfg.security.threatDetection.securityHub && !existing.securityHub) {
      const hub = new securityhub.CfnHub(this, 'SecurityHub', {
        enableDefaultStandards: true, // AWS Foundational Security Best Practices + CIS
        controlFindingGenerator: 'SECURITY_CONTROL',
        autoEnableControls: true,
        tags: { 'rural-shield:component': 'security-hub' },
      });
      const nist = new securityhub.CfnStandard(this, 'NistStandard', {
        standardsArn: `arn:${stack.partition}:securityhub:${stack.region}::standards/nist-800-53/v/5.0.0`,
      });
      nist.node.addDependency(hub);
      // NOTE: the enhanced Security Hub (OCSF, exposure findings, remediation plans) is enabled once
      // per organization from the console or `aws securityhub enable-security-hub-v2`; see README.
    }

    // ------------------------------------------------------------------- Macie
    if (cfg.security.threatDetection.macie && !existing.macieSession) {
      const session = new macie.CfnSession(this, 'Macie', {
        status: 'ENABLED',
        findingPublishingFrequency: 'FIFTEEN_MINUTES',
      });
      // Automated sensitive-data discovery samples objects continuously at low cost and feeds the
      // SENSITIVE_DATA indicator used by GuardDuty Extended Threat Detection and Security Hub exposures.
      const auto = new cr.AwsCustomResource(this, 'MacieAutomatedDiscovery', {
        onCreate: {
          service: 'Macie2',
          action: 'UpdateAutomatedDiscoveryConfiguration',
          parameters: { status: 'ENABLED' },
          physicalResourceId: cr.PhysicalResourceId.of(`${slug}-macie-auto-discovery`),
        },
        onDelete: {
          service: 'Macie2',
          action: 'UpdateAutomatedDiscoveryConfiguration',
          parameters: { status: 'DISABLED' },
        },
        policy: cr.AwsCustomResourcePolicy.fromStatements([
          new iam.PolicyStatement({ actions: ['macie2:UpdateAutomatedDiscoveryConfiguration'], resources: ['*'] }),
        ]),
        installLatestAwsSdk: false,
      });
      auto.node.addDependency(session);
    }

    // --------------------------------------------------------------- Inspector
    if (cfg.security.threatDetection.inspector) {
      const types = ['LAMBDA', 'LAMBDA_CODE', 'ECR'];
      new cr.AwsCustomResource(this, 'Inspector', {
        onCreate: {
          service: 'Inspector2',
          action: 'Enable',
          parameters: { resourceTypes: types },
          physicalResourceId: cr.PhysicalResourceId.of(`${slug}-inspector2`),
        },
        onDelete: {
          service: 'Inspector2',
          action: 'Disable',
          parameters: { resourceTypes: types },
        },
        policy: cr.AwsCustomResourcePolicy.fromStatements([
          new iam.PolicyStatement({
            actions: ['inspector2:Enable', 'inspector2:Disable', 'inspector2:ListAccountPermissions', 'iam:CreateServiceLinkedRole'],
            resources: ['*'],
          }),
        ]),
        installLatestAwsSdk: false,
      });
    }

    // ---------------------------------------------------- IAM Access Analyzer
    new accessanalyzer.CfnAnalyzer(this, 'AccessAnalyzer', {
      analyzerName: `${slug}-rural-shield-external`,
      type: 'ACCOUNT',
    });

    // ------------------------------------------------------ Account hardening
    new cr.AwsCustomResource(this, 'AccountPublicAccessBlock', {
      onCreate: {
        service: 'S3Control',
        action: 'PutPublicAccessBlock',
        parameters: {
          AccountId: stack.account,
          PublicAccessBlockConfiguration: {
            BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true,
          },
        },
        physicalResourceId: cr.PhysicalResourceId.of(`${slug}-s3-account-bpa`),
      },
      onUpdate: {
        service: 'S3Control',
        action: 'PutPublicAccessBlock',
        parameters: {
          AccountId: stack.account,
          PublicAccessBlockConfiguration: {
            BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true,
          },
        },
        physicalResourceId: cr.PhysicalResourceId.of(`${slug}-s3-account-bpa`),
      },
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({ actions: ['s3:PutAccountPublicAccessBlock', 's3:GetAccountPublicAccessBlock'], resources: ['*'] }),
      ]),
      installLatestAwsSdk: false,
    });

    const pwPolicy = {
      MinimumPasswordLength: 14,
      RequireSymbols: true,
      RequireNumbers: true,
      RequireUppercaseCharacters: true,
      RequireLowercaseCharacters: true,
      AllowUsersToChangePassword: true,
      MaxPasswordAge: 90,
      PasswordReusePrevention: 24,
      HardExpiry: false,
    };
    new cr.AwsCustomResource(this, 'IamPasswordPolicy', {
      onCreate: {
        service: 'IAM', action: 'UpdateAccountPasswordPolicy', parameters: pwPolicy,
        physicalResourceId: cr.PhysicalResourceId.of(`${slug}-iam-password-policy`),
      },
      onUpdate: {
        service: 'IAM', action: 'UpdateAccountPasswordPolicy', parameters: pwPolicy,
        physicalResourceId: cr.PhysicalResourceId.of(`${slug}-iam-password-policy`),
      },
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({ actions: ['iam:UpdateAccountPasswordPolicy'], resources: ['*'] }),
      ]),
      installLatestAwsSdk: false,
    });

    new cdk.CfnOutput(this, 'KmsKeyArn', { value: this.key.keyArn, description: 'RuralShield customer-managed key' });
    new cdk.CfnOutput(this, 'LogArchiveBucket', { value: this.logArchive.bucketName, description: 'Immutable audit log archive (6-year WORM)' });
    new cdk.CfnOutput(this, 'AlertsTopicArn', { value: this.alerts.topicArn });
  }

  /** Allow the AWS services that write encrypted data on our behalf to use the CMK. */
  private grantServicePrincipals(stack: cdk.Stack): void {
    const k = this.key;
    k.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowCloudTrailEncrypt',
      principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
      actions: ['kms:GenerateDataKey*', 'kms:DescribeKey'],
      resources: ['*'],
      conditions: {
        StringLike: { 'kms:EncryptionContext:aws:cloudtrail:arn': `arn:${stack.partition}:cloudtrail:*:${stack.account}:trail/*` },
      },
    }));
    k.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowCloudWatchLogs',
      principals: [new iam.ServicePrincipal(`logs.${stack.region}.amazonaws.com`)],
      actions: ['kms:Encrypt*', 'kms:Decrypt*', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:Describe*'],
      resources: ['*'],
      conditions: {
        ArnLike: { 'kms:EncryptionContext:aws:logs:arn': `arn:${stack.partition}:logs:${stack.region}:${stack.account}:log-group:*` },
      },
    }));
    // EventBridge and CloudWatch alarms publish to the KMS-encrypted alerts topic.
    k.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowEventsAndAlarmsToPublish',
      principals: [new iam.ServicePrincipal('events.amazonaws.com'), new iam.ServicePrincipal('cloudwatch.amazonaws.com')],
      actions: ['kms:Decrypt', 'kms:GenerateDataKey*'],
      resources: ['*'],
    }));
    // AWS Config delivers configuration snapshots to the archive; S3 flow logs / GuardDuty tag reads.
    k.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowConfigAndBackup',
      principals: [new iam.ServicePrincipal('config.amazonaws.com'), new iam.ServicePrincipal('backup.amazonaws.com')],
      actions: ['kms:Decrypt', 'kms:GenerateDataKey*', 'kms:DescribeKey', 'kms:CreateGrant'],
      resources: ['*'],
    }));
  }

  /** AWS Config recorder + delivery channel + HIPAA-aligned managed rules. */
  private createConfig(recorderExists: boolean): void {
    const stack = cdk.Stack.of(this);
    let recorder: config.CfnConfigurationRecorder | undefined;
    if (!recorderExists) {
      const role = new iam.Role(this, 'ConfigRole', {
        assumedBy: new iam.ServicePrincipal('config.amazonaws.com'),
        managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWS_ConfigRole')],
      });
      this.logDelivery.grantPut(role, 'config/*');
      this.logDelivery.grantRead(role);
      recorder = new config.CfnConfigurationRecorder(this, 'ConfigRecorder', {
        roleArn: role.roleArn,
        // Starting before the channel exists deadlocks CloudFormation stabilization.
        startedOnCreate: false,
        recordingGroup: { allSupported: true, includeGlobalResourceTypes: true },
      });
      const channel = new config.CfnDeliveryChannel(this, 'ConfigDelivery', {
        s3BucketName: this.logDelivery.bucketName,
        s3KeyPrefix: 'config',
        configSnapshotDeliveryProperties: { deliveryFrequency: 'TwentyFour_Hours' },
      });
      channel.node.addDependency(recorder);
      const startRecorder = new cr.AwsCustomResource(this, 'ConfigStartRecorder', {
        onCreate: {
          service: 'ConfigService', action: 'StartConfigurationRecorder',
          parameters: { ConfigurationRecorderName: recorder.ref },
          physicalResourceId: cr.PhysicalResourceId.of('config-recorder-started'),
        },
        onUpdate: {
          service: 'ConfigService', action: 'StartConfigurationRecorder',
          parameters: { ConfigurationRecorderName: recorder.ref },
        },
        policy: cr.AwsCustomResourcePolicy.fromStatements([
          new iam.PolicyStatement({ actions: ['config:StartConfigurationRecorder'], resources: [recorder.attrResourceArn] }),
        ]),
        installLatestAwsSdk: false,
      });
      startRecorder.node.addDependency(channel);

    }

    // Managed-rule identifiers are strings (see "AWS Config Managed Rules" reference). Each maps to a
    // HIPAA Security Rule citation in docs/CONTROL_MAPPING.md.
    const rules: Array<{ id: string; identifier: string; params?: Record<string, string> }> = [
      { id: 'S3Encryption', identifier: 'S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED' },
      { id: 'S3PublicRead', identifier: 'S3_BUCKET_PUBLIC_READ_PROHIBITED' },
      { id: 'S3PublicWrite', identifier: 'S3_BUCKET_PUBLIC_WRITE_PROHIBITED' },
      { id: 'S3Ssl', identifier: 'S3_BUCKET_SSL_REQUESTS_ONLY' },
      { id: 'S3Versioning', identifier: 'S3_BUCKET_VERSIONING_ENABLED' },
      { id: 'S3AccountBpa', identifier: 'S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC' },
      { id: 'CloudTrailEnabled', identifier: 'CLOUD_TRAIL_ENABLED' },
      { id: 'CloudTrailValidation', identifier: 'CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED' },
      { id: 'CloudTrailEncrypted', identifier: 'CLOUD_TRAIL_ENCRYPTION_ENABLED' },
      { id: 'CloudTrailMultiRegion', identifier: 'MULTI_REGION_CLOUD_TRAIL_ENABLED' },
      { id: 'LogGroupEncrypted', identifier: 'CLOUDWATCH_LOG_GROUP_ENCRYPTED' },
      { id: 'GuardDutyEnabled', identifier: 'GUARDDUTY_ENABLED_CENTRALIZED' },
      { id: 'SecurityHubEnabled', identifier: 'SECURITYHUB_ENABLED' },
      { id: 'RootMfa', identifier: 'ROOT_ACCOUNT_MFA_ENABLED' },
      { id: 'RootNoKeys', identifier: 'IAM_ROOT_ACCESS_KEY_CHECK' },
      { id: 'IamUserMfa', identifier: 'IAM_USER_MFA_ENABLED' },
      { id: 'IamUnusedCreds', identifier: 'IAM_USER_UNUSED_CREDENTIALS_CHECK', params: { maxCredentialUsageAge: '90' } },
      { id: 'IamKeysRotated', identifier: 'ACCESS_KEYS_ROTATED', params: { maxAccessKeyAge: '90' } },
      { id: 'IamPasswordPolicy', identifier: 'IAM_PASSWORD_POLICY' },
      { id: 'IamNoInlineUserPolicies', identifier: 'IAM_USER_NO_POLICIES_CHECK' },
      { id: 'KmsNotDeleting', identifier: 'KMS_CMK_NOT_SCHEDULED_FOR_DELETION' },
      { id: 'KmsRotation', identifier: 'CMK_BACKING_KEY_ROTATION_ENABLED' },
      { id: 'LambdaNotPublic', identifier: 'LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED' },
      { id: 'LambdaInVpc', identifier: 'LAMBDA_INSIDE_VPC' },
      { id: 'DynamoPitr', identifier: 'DYNAMODB_PITR_ENABLED' },
      { id: 'DynamoKms', identifier: 'DYNAMODB_TABLE_ENCRYPTED_KMS' },
      { id: 'DynamoInBackup', identifier: 'DYNAMODB_IN_BACKUP_PLAN' },
      { id: 'RdsEncrypted', identifier: 'RDS_STORAGE_ENCRYPTED' },
      { id: 'RdsNotPublic', identifier: 'RDS_INSTANCE_PUBLIC_ACCESS_CHECK' },
      { id: 'RdsDeletionProtection', identifier: 'RDS_CLUSTER_DELETION_PROTECTION_ENABLED' },
      { id: 'BackupEncrypted', identifier: 'BACKUP_RECOVERY_POINT_ENCRYPTED' },
      { id: 'BackupMinRetention', identifier: 'BACKUP_RECOVERY_POINT_MINIMUM_RETENTION_CHECK', params: { requiredRetentionDays: '35' } },
      { id: 'SecretsRotation', identifier: 'SECRETSMANAGER_ROTATION_ENABLED_CHECK' },
      { id: 'ApiGwLogging', identifier: 'API_GW_EXECUTION_LOGGING_ENABLED' },
      { id: 'ApiGwWaf', identifier: 'API_GW_ASSOCIATED_WITH_WAF' },
      { id: 'VpcFlowLogs', identifier: 'VPC_FLOW_LOGS_ENABLED' },
      { id: 'VpcDefaultSgClosed', identifier: 'VPC_DEFAULT_SECURITY_GROUP_CLOSED' },
      { id: 'WafLogging', identifier: 'WAFV2_LOGGING_ENABLED' },
    ];
    for (const r of rules) {
      const rule = new config.ManagedRule(this, `Rule${r.id}`, {
        identifier: r.identifier,
        configRuleName: `rural-shield-${r.id.replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase()}`,
        inputParameters: r.params,
      });
      if (recorder) rule.node.addDependency(recorder);
    }
    cdk.Annotations.of(this).addInfo(`AWS Config: ${rules.length} HIPAA-aligned managed rules deployed in ${stack.region}`);
  }

  /** CIS AWS Foundations Benchmark 4.x monitoring alarms (HIPAA §164.308(a)(1)(ii)(D), §164.312(b)). */
  private createCisAlarms(logGroup: logs.LogGroup): void {
    const alarms: Array<{ id: string; pattern: string; description: string }> = [
      { id: 'RootUsage', description: 'Root account used', pattern: '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' },
      { id: 'UnauthorizedApi', description: 'Unauthorized API calls', pattern: '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }' },
      { id: 'ConsoleNoMfa', description: 'Console sign-in without MFA', pattern: '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }' },
      { id: 'IamPolicyChange', description: 'IAM policy changed', pattern: '{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}' },
      { id: 'CloudTrailChange', description: 'CloudTrail configuration changed', pattern: '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }' },
      { id: 'KmsKeyChange', description: 'KMS key disabled or scheduled for deletion', pattern: '{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }' },
      { id: 'S3PolicyChange', description: 'S3 bucket policy changed', pattern: '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }' },
      { id: 'SecurityGroupChange', description: 'Security group changed', pattern: '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }' },
      { id: 'ConfigChange', description: 'AWS Config changed', pattern: '{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }' },
      { id: 'GuardDutyChange', description: 'GuardDuty detector modified', pattern: '{ ($.eventSource = guardduty.amazonaws.com) && (($.eventName = DeleteDetector) || ($.eventName = UpdateDetector) || ($.eventName = DisassociateFromMasterAccount) || ($.eventName = DeleteMembers)) }' },
    ];
    const ns = 'RuralShield/CIS';
    for (const a of alarms) {
      const mf = new logs.MetricFilter(this, `Mf${a.id}`, {
        logGroup,
        filterPattern: logs.FilterPattern.literal(a.pattern),
        metricNamespace: ns,
        metricName: a.id,
        metricValue: '1',
        defaultValue: 0,
      });
      const alarm = new cloudwatch.Alarm(this, `Alarm${a.id}`, {
        alarmName: `rural-shield-${a.id}`,
        alarmDescription: `${a.description} (CIS monitoring, HIPAA 164.312(b))`,
        metric: mf.metric({ statistic: 'Sum', period: cdk.Duration.minutes(5) }),
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      alarm.addAlarmAction(new cwActions.SnsAction(this.alerts));
    }
  }
}
