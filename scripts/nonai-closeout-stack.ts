/** Separate post-test instrumentation; does not redeploy the frozen workload. */
import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as scheduler from 'aws-cdk-lib/aws-scheduler';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as fs from 'fs';

const plan = JSON.parse(fs.readFileSync('cdk.out/closeout/plan.json', 'utf8'));
const app = new cdk.App({outdir: 'cdk.out/closeout/synth'});
const stack = new cdk.Stack(app, plan.closeoutStack, {env: {account: plan.account, region: 'us-east-2'},
  description: 'Evidence-first RuralShield shutdown after the frozen five-day window'});
const rows = Object.entries(plan.regions).flatMap(([region, stacks]: [string, any]) =>
  stacks.flatMap((s: any) => s.resources.map((r: any) => ({...r, region}))));
const ofType = (type: string) => rows.filter((r: any) => r.ResourceType === type);
const arn = (service: string, region: string, resource: string) => `arn:aws:${service}:${region}:${plan.account}:${resource}`;
const key = kms.Key.fromKeyArn(stack, 'EvidenceKey', arn('kms', 'us-east-2', 'key/00000000-0000-4000-8000-000000000000'));
const group = new logs.LogGroup(stack, 'Logs', {encryptionKey: key, retention: logs.RetentionDays.ONE_YEAR, removalPolicy: cdk.RemovalPolicy.RETAIN});
const dlq = new sqs.Queue(stack, 'FailureQueue', {encryption: sqs.QueueEncryption.KMS, encryptionMasterKey: key, enforceSSL: true, retentionPeriod: cdk.Duration.days(14)});
const role = new iam.Role(stack, 'CloseoutRole', {assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com')});
const grant = (actions: string[], resources: string[], conditions?: any) => {
  if (resources.length) role.addToPrincipalPolicy(new iam.PolicyStatement({actions, resources, conditions}));
};
const readConditions = {StringEquals: {'aws:RequestedRegion': ['us-east-2', 'us-west-2']}};
// Inventory and evidence reads only. No GetSecretValue or object/key/vault deletion.
grant(['sts:GetCallerIdentity'], ['*']);
grant(['cloudformation:DescribeStacks', 'cloudformation:ListStacks', 'cloudformation:ListStackResources', 'cloudformation:GetTemplate',
  'lambda:ListFunctions', 'ec2:DescribeInstances', 'ec2:DescribeVpcEndpoints', 'ec2:DescribeFlowLogs',
  'rds:DescribeDBInstances', 'ecs:ListClusters', 'dynamodb:ListTables', 'logs:DescribeLogGroups',
  'cloudwatch:GetMetricData', 'cloudwatch:DescribeAlarms', 'backup:DescribeBackupVault', 'backup:ListRecoveryPointsByBackupVault',
  'backup:ListBackupSelections', 'backup:ListBackupPlans', 'backup:ListRestoreTestingPlans',
  'securityhub:GetFindings', 'securityhub:GetEnabledStandards', 'securityhub:DescribeHub',
  'inspector2:ListFindings', 'inspector2:BatchGetAccountStatus', 'guardduty:ListFindings', 'guardduty:GetFindings', 'guardduty:GetDetector',
  'macie2:ListFindings', 'macie2:GetFindings', 'macie2:GetMacieSession',
  'config:DescribeConfigRules', 'config:DescribeConfigRuleEvaluationStatus', 'config:GetComplianceDetailsByConfigRule',
  'config:DescribeConfigurationRecorderStatus', 'cloudtrail:GetTrailStatus'], ['*'], readConditions);
grant(['s3:ListAllMyBuckets'], ['*']);
const buckets = ofType('AWS::S3::Bucket').map((r: any) => 'arn:aws:s3:::' + r.PhysicalResourceId);
grant(['s3:ListBucket', 's3:ListBucketVersions', 's3:GetEncryptionConfiguration', 's3:GetBucketLogging'], buckets);
grant(['s3:PutBucketLogging'], ofType('AWS::S3::Bucket').filter((r: any) => r.PhysicalResourceId.includes('-rshield-phi-')).map((r: any) => 'arn:aws:s3:::' + r.PhysicalResourceId));
grant(['s3:GetObject'], [`arn:aws:s3:::${plan.evidenceBucket}/*`]);
grant(['s3:PutObject'], [`arn:aws:s3:::${plan.evidenceBucket}/closeout/*`]);
key.grantEncryptDecrypt(role);
grant(['kms:Decrypt', 'kms:DescribeKey'], ofType('AWS::KMS::Key').map((r: any) => arn('kms', r.region, 'key/' + r.PhysicalResourceId)));
group.grantWrite(role);
dlq.grantSendMessages(role);
const tables = [...new Set(ofType('AWS::DynamoDB::GlobalTable').map((r: any) => r.PhysicalResourceId))];
grant(['dynamodb:Scan', 'dynamodb:DescribeTable', 'dynamodb:DescribeContinuousBackups', 'dynamodb:DescribeContributorInsights', 'dynamodb:UpdateContributorInsights'],
  ['us-east-2', 'us-west-2'].flatMap(region => tables.map(table => arn('dynamodb', region, 'table/' + table))));
grant(['events:DisableRule', 'events:DescribeRule'], ofType('AWS::Events::Rule').map((r: any) => arn('events', r.region, 'rule/' + r.PhysicalResourceId)));
grant(['cognito-idp:AdminDisableUser', 'cognito-idp:AdminGetUser'], [arn('cognito-idp', 'us-east-2', 'userpool/' + plan.poolId)]);
grant(['apigateway:GET'], ['arn:aws:apigateway:us-east-2::/restapis']);
grant(['apigateway:DELETE'], [`arn:aws:apigateway:us-east-2::/restapis/${plan.apiId}`]);
grant(['apigateway:SetWebACL'], [`arn:aws:apigateway:us-east-2::/restapis/${plan.apiId}/stages/dev`]);
grant(['wafv2:GetWebACL', 'wafv2:DeleteWebACL', 'wafv2:DeleteLoggingConfiguration', 'wafv2:ListResourcesForWebACL', 'wafv2:DisassociateWebACL'],
  ofType('AWS::WAFv2::WebACL').map((r: any) => {const [name, id] = r.PhysicalResourceId.split('|'); return arn('wafv2', r.region, `regional/webacl/${name}/${id}`);}));
grant(['ec2:DeleteVpcEndpoints'], ofType('AWS::EC2::VPCEndpoint').map((r: any) => arn('ec2', r.region, 'vpc-endpoint/' + r.PhysicalResourceId)));
grant(['ec2:DeleteFlowLogs'], ofType('AWS::EC2::FlowLog').map((r: any) => arn('ec2', r.region, 'vpc-flow-log/' + r.PhysicalResourceId)));
grant(['backup:DeleteBackupSelection', 'backup:DeleteBackupPlan'], ofType('AWS::Backup::BackupPlan').map((r: any) => arn('backup', r.region, 'backup-plan:' + r.PhysicalResourceId)));
grant(['backup:DeleteRestoreTestingSelection', 'backup:DeleteRestoreTestingPlan'], ofType('AWS::Backup::RestoreTestingPlan').map((r: any) => arn('backup', r.region, 'restore-testing-plan:' + r.PhysicalResourceId + '-*')));
grant(['config:DeleteConfigRule'], plan.configRuleArns);
grant(['config:StopConfigurationRecorder'], plan.recorderArns);
grant(['guardduty:UpdateDetector'], ofType('AWS::GuardDuty::Detector').map((r: any) => arn('guardduty', r.region, 'detector/' + r.PhysicalResourceId)));
// These APIs control the owning account in Ohio; the runtime checks for new workloads first.
grant(['securityhub:DisableSecurityHub', 'inspector2:Disable', 'macie2:UpdateMacieSession'], ['*'], {StringEquals: {'aws:RequestedRegion': 'us-east-2'}});
grant(['cloudtrail:StopLogging'], ofType('AWS::CloudTrail::Trail').map((r: any) => arn('cloudtrail', r.region, 'trail/' + r.PhysicalResourceId)));
grant(['cloudwatch:DeleteAlarms'], ofType('AWS::CloudWatch::Alarm').map((r: any) => arn('cloudwatch', r.region, 'alarm:' + r.PhysicalResourceId)));
grant(['logs:PutRetentionPolicy'], [...ofType('AWS::Logs::LogGroup').flatMap((r: any) => [arn('logs', r.region, 'log-group:' + r.PhysicalResourceId), arn('logs', r.region, 'log-group:' + r.PhysicalResourceId + ':*')]),
  arn('logs', 'us-east-2', 'log-group:API-Gateway-Execution-Logs_' + plan.apiId + '/*')]);
grant(['secretsmanager:DeleteSecret'], [plan.authSecretArn]);
const scheduleArn = arn('scheduler', 'us-east-2', 'schedule/default/' + plan.scheduleName);
grant(['scheduler:DeleteSchedule'], [scheduleArn]);
const fn = new lambda.Function(stack, 'Closeout', {functionName: plan.closeoutFunction,
  runtime: lambda.Runtime.PYTHON_3_12, architecture: lambda.Architecture.ARM_64,
  handler: 'index.handler', code: lambda.Code.fromAsset('cdk.out/closeout/asset'), role, logGroup: group,
  memorySize: 1024, timeout: cdk.Duration.minutes(15), reservedConcurrentExecutions: 1,
  deadLetterQueue: dlq, retryAttempts: 2, maxEventAge: cdk.Duration.hours(1), environmentEncryption: key});
const scheduleRole = new iam.Role(stack, 'SchedulerRole', {assumedBy: new iam.ServicePrincipal('scheduler.amazonaws.com', {
  conditions: {StringEquals: {'aws:SourceAccount': plan.account}, ArnEquals: {'aws:SourceArn': arn('scheduler', 'us-east-2', 'schedule-group/default')}}})});
fn.grantInvoke(scheduleRole);
dlq.grantSendMessages(scheduleRole);
key.grantEncryptDecrypt(scheduleRole);
const end = new Date(plan.endAt);
const schedule = new scheduler.CfnSchedule(stack, 'CloseoutSchedule', {name: plan.scheduleName,
  description: 'After experiment deadline plus five-minute drain: verify/export evidence, then stop scoped services',
  scheduleExpression: 'rate(15 minutes)', scheduleExpressionTimezone: 'UTC',
  startDate: new Date(end.getTime() + 5 * 60000).toISOString(), endDate: new Date(end.getTime() + 24 * 3600000).toISOString(),
  flexibleTimeWindow: {mode: 'OFF'}, state: 'ENABLED',
  target: {arn: fn.functionArn, roleArn: scheduleRole.roleArn, input: JSON.stringify({mode: 'closeout'}),
    deadLetterConfig: {arn: dlq.queueArn}, retryPolicy: {maximumEventAgeInSeconds: 3600, maximumRetryAttempts: 3}}});
schedule.node.addDependency(scheduleRole);
new cdk.CfnOutput(stack, 'CloseoutFunction', {value: fn.functionName});
new cdk.CfnOutput(stack, 'ScheduleName', {value: schedule.name!});
new cdk.CfnOutput(stack, 'FailureQueueUrl', {value: dlq.queueUrl});
new cdk.CfnOutput(stack, 'FirstCloseoutAt', {value: new Date(end.getTime() + 5 * 60000).toISOString()});
cdk.Tags.of(stack).add('rural-shield:purpose', 'post-test evidence preservation and cost shutdown');
app.synth();
