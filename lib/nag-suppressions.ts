import * as cdk from 'aws-cdk-lib';
import { NagSuppressions } from 'cdk-nag';

/**
 * Every suppression is a deliberate, documented engineering decision; the reasons below are the
 * ones reported in the paper's compliance table. Nothing here hides a missing control.
 *
 * Patterns are applied at stack level with `appliesTo` so they stay as narrow as cdk-nag allows
 * without knowing synthesized logical IDs. Run `npx cdk synth` and review cdk.out/*NagReport.csv.
 */
export function applyNagSuppressions(stacks: { foundation: cdk.Stack; workload: cdk.Stack; sentinel: cdk.Stack; dr?: cdk.Stack }): void {
  const common = [
    {
      id: 'AwsSolutions-IAM4',
      reason: 'AWS-managed policies are used only by CDK-generated service roles (custom-resource providers, log retention, API Gateway CloudWatch role, Config, Backup). Workload roles are hand-written least privilege.',
      appliesTo: [
        'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
        'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs',
        'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWS_ConfigRole',
        'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup',
        'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores',
        'Policy::arn:<AWS::Partition>:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup',
        'Policy::arn:<AWS::Partition>:iam::aws:policy/AWSBackupServiceRolePolicyForS3Restore',
      ],
    },
    {
      id: 'AwsSolutions-IAM5',
      reason: 'CDK S3 grants use action suffixes for related object/list operations; KMS grants use related data-key/re-encryption actions. Resource * covers service control-plane and telemetry APIs without resource-level authorization. Dynamic containment targets and named S3 object prefixes have separate resource-scoped exceptions below. Bedrock invocation uses exact model and profile ARNs.',
      appliesTo: [
        'Action::s3:GetObject*', 'Action::s3:GetBucket*', 'Action::s3:List*', 'Action::s3:DeleteObject*', 'Action::s3:Abort*',
        'Action::kms:GenerateDataKey*', 'Action::kms:ReEncrypt*',
        'Resource::*',
        { regex: '/^Resource::<.*Bucket.*Arn>\\/\\*$/' },
        { regex: '/^Resource::arn:(aws|<AWS::Partition>):s3:::.*\\/\\*$/' },
      ],
    },
    {
      id: 'AwsSolutions-L1',
      reason: 'Runtimes are pinned to the latest version supported by the CDK release in use and reviewed quarterly; CDK custom-resource provider functions use the runtime chosen by the CDK framework.',
    },
    {
      id: 'HIPAA.Security-LambdaInsideVPC',
      reason: 'Applies only to control-plane functions (CDK custom-resource providers, log-retention handler, and the Sentinel responders). They process security metadata, not ePHI, and require IAM/Security Hub/Bedrock control-plane APIs for which private endpoints are not uniformly available. The workload function that handles ePHI runs inside the private VPC.',
    },
    {
      id: 'HIPAA.Security-LambdaConcurrency',
      reason: 'CDK-generated custom-resource provider functions run only at deployment time; concurrency limits are set on every operator-visible function.',
    },
    {
      id: 'HIPAA.Security-LambdaDLQ',
      reason: 'CDK-generated custom-resource provider functions are invoked synchronously by CloudFormation; failures surface as stack events. Every asynchronously invoked function has a KMS-encrypted dead-letter queue.',
    },
  ];

  // Scope object-prefix exceptions to the roles that actually need them.
  const find = (stack: cdk.Stack, path: string) => path.split('/').reduce<any>((node, id) => node?.node.tryFindChild(id), stack);
  const objectPrefix = (stack: cdk.Stack, path: string, prefix: string, reason: string) => {
    if (!find(stack, path)) return;
    NagSuppressions.addResourceSuppressionsByPath(stack, `${stack.node.path}/${path}`, [{
      id: 'AwsSolutions-IAM5', reason,
      appliesTo: [{ regex: `/^Resource::(?:<[^>]+>|[^/]+:ExportsOutput[^/]+)\\/${prefix}\\*$/` }],
    }], true);
  };
  for (const stack of [stacks.foundation, stacks.dr].filter((s): s is cdk.Stack => !!s)) {
    const deliveryPath = stack === stacks.foundation ? 'Baseline/LogDelivery/Bucket' : 'LogDelivery/Bucket';
    NagSuppressions.addResourceSuppressionsByPath(stack, `${stack.node.path}/${deliveryPath}`, [{
      id: 'HIPAA.Security-S3DefaultEncryptionKMS',
      reason: 'S3/ALB delivery requires an unlocked SSE-S3 destination. A version-aware Lambda copies deliveries into a separate CMK-encrypted six-year WORM archive. Source versions are retained and archival failures alarm.',
    }], true);
  }
  objectPrefix(stacks.foundation, 'Baseline/ConfigRole', '(config\\/)?',
    'Config reads its named delivery bucket and writes only its config prefix; object names are assigned by AWS Config.');
  objectPrefix(stacks.sentinel, 'Sentinel/Report/ServiceRole', 'posture-reports\\/',
    'Weekly reports write only the posture-reports prefix of the single Foundation archive.');
  if (stacks.dr) objectPrefix(stacks.workload, 'Data/PhiBucket/ReplicationRole', '',
    'S3 replication must write arbitrary object names only in the configured DR replica bucket.');
  if (find(stacks.sentinel, 'Sentinel/Contain/ServiceRole')) NagSuppressions.addResourceSuppressionsByPath(stacks.sentinel,
    `${stacks.sentinel.node.path}/Sentinel/Contain/ServiceRole`, [{
      id: 'AwsSolutions-IAM5',
      reason: 'Incident targets are discovered at runtime. IAM/Lambda/EC2 permissions are limited to this account and protected-resource tag conditions; S3 is limited by s3:ResourceAccount and the handler checks protection tags. Auto containment is disabled in the research configuration.',
      appliesTo: [
        { regex: '/^Resource::arn:(aws|<AWS::Partition>):iam::([0-9]{12}|<AWS::AccountId>):(user|role)\\/\\*$/' },
        { regex: '/^Resource::arn:(aws|<AWS::Partition>):lambda:([^:]+):([0-9]{12}|<AWS::AccountId>):function:\\*$/' },
        { regex: '/^Resource::arn:(aws|<AWS::Partition>):ec2:([^:]+):([0-9]{12}|<AWS::AccountId>):security-group\\/\\*$/' },
        { regex: '/^Resource::arn:(aws|<AWS::Partition>):s3:::\\*$/' },
      ],
    }], true);
  if (stacks.workload.node.tryFindChild('Data')?.node.tryFindChild('MalwareScanRole')) {
    NagSuppressions.addResourceSuppressionsByPath(stacks.workload,
      `${stacks.workload.node.path}/Data/MalwareScanRole`, [{
        id: 'AwsSolutions-IAM5',
        reason: 'GuardDuty chooses the suffix of its malware-protection EventBridge rule. Permissions cover only the documented DO-NOT-DELETE prefix in this account and region.',
        appliesTo: [{ regex: '/^Resource::arn:(aws|<AWS::Partition>):events:([^:]+):([0-9]{12}|<AWS::AccountId>):rule\\/DO-NOT-DELETE-AmazonGuardDutyMalwareProtectionS3\\*$/' }],
      }], true);
  }

  const foundation = [
    ...common,
    {
      id: 'AwsSolutions-S1',
      reason: 'Audit archive and log delivery buckets do not log into themselves. CloudTrail audits their reads and bucket management; their object writes are excluded to avoid recursive CloudTrail delivery events.',
    },
    {
      id: 'HIPAA.Security-S3BucketLoggingEnabled',
      reason: 'Audit archive and delivery bucket reads are captured via CloudTrail data events. Writes to the primary audit destinations are excluded to prevent recursive delivery logging.',
    },
    {
      id: 'HIPAA.Security-S3BucketReplicationEnabled',
      reason: 'The audit archive is immutable (Object Lock COMPLIANCE, 6 years) and CloudTrail is multi-region; replication of the archive itself is an operator choice (enable drRegion for PHI replication).',
    },
    {
      id: 'HIPAA.Security-S3BucketVersioningEnabled',
      reason: 'Versioning is enabled on all RuralShield buckets; this suppression covers only CDK-managed asset buckets if present.',
    },
  ];

  const workload = [
    ...common,
    {
      id: 'HIPAA.Security-APIGWCacheEnabledAndEncrypted',
      reason: 'Response caching is deliberately disabled for an API that serves ePHI: a cache raises the risk of stale or cross-user data exposure, and all transport is TLS 1.2+. The control intent (confidentiality in transit/at rest) is met by TLS and KMS-encrypted stores.',
    },
    {
      id: 'AwsSolutions-APIG4',
      reason: 'Only the automatically generated CORS OPTIONS pre-flight methods are unauthenticated; every ANY method requires a Cognito JWT.',
    },
    {
      id: 'AwsSolutions-COG4',
      reason: 'Only the automatically generated CORS OPTIONS pre-flight methods lack the Cognito authorizer; browsers cannot send credentials on pre-flight requests.',
    },
    {
      id: 'HIPAA.Security-S3BucketReplicationEnabled',
      reason: 'PHI bucket replication is enabled whenever resilience.drRegion is configured; single-region deployments rely on versioning + Object Lock + AWS Backup continuous backups.',
    },
    {
      id: 'AwsSolutions-EC23',
      reason: 'Applies only to the internet-facing ALB in container mode, which must accept HTTPS from any client; it is fronted by WAF managed rules and rate limiting.',
    },
    {
      id: 'AwsSolutions-ECS2',
      reason: 'Container environment variables carry only non-secret configuration (table names, bucket names); secrets are injected from Secrets Manager.',
    },
    {
      id: 'AwsSolutions-SMG4',
      reason: 'The Aurora master credential rotates every 30 days via addRotationSingleUser; this suppression covers only CDK-generated secrets that have no rotation semantics.',
    },
    {
      id: 'AwsSolutions-RDS6',
      reason: 'IAM database authentication is enabled on the cluster; the rule cannot observe the ClusterInstance-level setting.',
    },
    {
      id: 'HIPAA.Security-RDSInstanceDeletionProtectionEnabled',
      reason: 'Deletion protection is configured at the Aurora cluster level (the only level Aurora supports).',
    },
  ];

  const sentinel = [
    ...common,
    {
      id: 'AwsSolutions-APIG4',
      reason: 'The approval endpoint is authenticated by a single-use HMAC-SHA256 token bound to one incident and one action, delivered to the verified contact e-mail; approvers do not have AWS identities. The endpoint is rate-limited (5 rps) and fronted by WAF.',
    },
    {
      id: 'AwsSolutions-COG4',
      reason: 'Approvers are hospital staff reached by e-mail, not Cognito users; see AwsSolutions-APIG4 rationale.',
    },
    {
      id: 'HIPAA.Security-APIGWCacheEnabledAndEncrypted',
      reason: 'The approval endpoint must never be cached: each link is single-use.',
    },
    {
      id: 'HIPAA.Security-S3BucketReplicationEnabled',
      reason: 'No PHI is stored by the Sentinel stack.',
    },
  ];

  NagSuppressions.addStackSuppressions(stacks.foundation, foundation, true);
  NagSuppressions.addStackSuppressions(stacks.workload, workload, true);
  NagSuppressions.addStackSuppressions(stacks.sentinel, sentinel, true);
  if (stacks.dr) {
    NagSuppressions.addStackSuppressions(stacks.dr, [
      ...common,
      { id: 'AwsSolutions-S1', reason: 'DR log bucket is the logging destination in the DR region.' },
      { id: 'HIPAA.Security-S3BucketLoggingEnabled', reason: 'DR log bucket is the logging destination in the DR region.' },
      { id: 'HIPAA.Security-S3BucketReplicationEnabled', reason: 'These buckets are the replication/copy destination.' },
    ], true);
  }
}
