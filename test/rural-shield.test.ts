import * as cdk from 'aws-cdk-lib';
import { Annotations, Match, Template } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks, HIPAASecurityChecks } from 'cdk-nag';
import { applyDefaults, validateConfig, RuralShieldConfig } from '../lib/config';
import { buildRuralShield } from '../lib/app-builder';
import { applyNagSuppressions } from '../lib/nag-suppressions';
import { RuralShieldChecks } from '../lib/aspects/rural-shield-aspects';
import * as fs from 'fs';
import * as yaml from 'js-yaml';

function exampleConfig(overrides: (c: RuralShieldConfig) => void = () => undefined): RuralShieldConfig {
  const raw = yaml.load(fs.readFileSync('rural-shield.example.yaml', 'utf8')) as RuralShieldConfig;
  raw.organization.account = '123456789012';
  overrides(raw);
  const cfg = applyDefaults(raw);
  validateConfig(cfg);
  return cfg;
}

function synth(cfg: RuralShieldConfig) {
  // Match the feature flags used by the CDK CLI (including policy-based S3 log delivery).
  const context = JSON.parse(fs.readFileSync('cdk.json', 'utf8')).context;
  const app = new cdk.App({ context });
  const stacks = buildRuralShield(app, cfg);
  cdk.Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  cdk.Aspects.of(app).add(new HIPAASecurityChecks({ verbose: true }));
  cdk.Aspects.of(app).add(new RuralShieldChecks(), { priority: cdk.AspectPriority.READONLY });
  applyNagSuppressions({ foundation: stacks.foundation, workload: stacks.workload, sentinel: stacks.sentinel ?? stacks.workload, dr: stacks.dr });
  app.synth();
  return stacks;
}

describe('RuralShield compliance-as-code', () => {
  const stacks = synth(exampleConfig());
  const all = [stacks.foundation, stacks.workload, stacks.sentinel!, stacks.dr!];

  test.each(all.map((s) => [s.stackName, s] as const))('%s has no unsuppressed HIPAA Security errors', (_name, stack) => {
    const errors = Annotations.fromStack(stack).findError('*', Match.stringLikeRegexp('HIPAA\\.Security-.*'));
    expect(errors.map((e) => e.entry.data)).toEqual([]);
  });

  test.each(all.map((s) => [s.stackName, s] as const))('%s has no unsuppressed AwsSolutions errors', (_name, stack) => {
    const errors = Annotations.fromStack(stack).findError('*', Match.stringLikeRegexp('AwsSolutions-.*'));
    expect(errors.map((e) => e.entry.data)).toEqual([]);
  });

  test.each(all.map((s) => [s.stackName, s] as const))('%s passes RuralShield healthcare checks', (_name, stack) => {
    const errors = Annotations.fromStack(stack).findError('*', Match.stringLikeRegexp('RuralShield-.*'));
    expect(errors.map((e) => e.entry.data)).toEqual([]);
  });

  test('PHI bucket is WORM-protected and KMS-encrypted', () => {
    const t = Template.fromStack(stacks.workload);
    t.hasResourceProperties('AWS::S3::Bucket', Match.objectLike({
      ObjectLockEnabled: true,
      BucketEncryption: Match.objectLike({ ServerSideEncryptionConfiguration: Match.arrayWith([Match.objectLike({ ServerSideEncryptionByDefault: Match.objectLike({ SSEAlgorithm: 'aws:kms' }) })]) }),
      VersioningConfiguration: { Status: 'Enabled' },
    }));
  });

  test('Cognito requires MFA with TOTP only', () => {
    Template.fromStack(stacks.workload).hasResourceProperties('AWS::Cognito::UserPool', Match.objectLike({
      MfaConfiguration: 'ON',
      EnabledMfas: ['SOFTWARE_TOKEN_MFA'],
    }));
  });

  test('GuardDuty detector enables serverless protection plans', () => {
    Template.fromStack(stacks.foundation).hasResourceProperties('AWS::GuardDuty::Detector', Match.objectLike({
      Enable: true,
      Features: Match.arrayWith([
        Match.objectLike({ Name: 'S3_DATA_EVENTS', Status: 'ENABLED' }),
        Match.objectLike({ Name: 'LAMBDA_NETWORK_LOGS', Status: 'ENABLED' }),
        Match.objectLike({ Name: 'RDS_LOGIN_EVENTS', Status: 'ENABLED' }),
      ]),
    }));
  });

  test('Backup vault is locked', () => {
    Template.fromStack(stacks.workload).hasResourceProperties('AWS::Backup::BackupVault', Match.objectLike({
      LockConfiguration: Match.objectLike({ MinRetentionDays: 35 }),
    }));
  });

  test('backup selection uses a role with backup, restore, S3, and KMS permissions', () => {
    const t = Template.fromStack(stacks.workload);
    const selections = t.findResources('AWS::Backup::BackupSelection');
    const selection = Object.values(selections)[0] as any;
    const roleId = selection.Properties.BackupSelection.IamRoleArn['Fn::GetAtt'][0];
    const role = t.findResources('AWS::IAM::Role')[roleId] as any;
    expect(JSON.stringify(role.Properties.AssumeRolePolicyDocument)).toContain('backup.amazonaws.com');
    for (const policy of [
      'service-role/AWSBackupServiceRolePolicyForBackup',
      'service-role/AWSBackupServiceRolePolicyForRestores',
      'AWSBackupServiceRolePolicyForS3Backup',
      'AWSBackupServiceRolePolicyForS3Restore',
    ]) {
      expect(JSON.stringify(role.Properties.ManagedPolicyArns)).toContain(policy);
    }
    t.hasResourceProperties('AWS::IAM::ManagedPolicy', {
      Roles: Match.arrayWith([{ Ref: roleId }]),
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([Match.objectLike({
          Effect: 'Allow',
          Action: Match.arrayWith(['kms:Decrypt', 'kms:Encrypt']),
        })]),
      }),
    });
  });

  test.each(all.map((s) => [s.stackName, s] as const))('%s uses managed policies with only the documented CDK provider exceptions', (_name, stack) => {
    const t = Template.fromStack(stack);
    t.resourceCountIs('AWS::IAM::Policy', 0);
    for (const [id, role] of Object.entries(t.findResources('AWS::IAM::Role')) as [string, any][]) {
      if (role.Properties.Policies) {
        expect(id).toMatch(/Custom(VpcRestrictDefaultSG|CrossRegionExport(Writer|Reader))CustomResourceProviderRole/);
        const document = JSON.stringify(role.Properties.Policies);
        expect(document).toMatch(/ec2:RevokeSecurityGroupIngress|ssm:GetParameters/);
        expect(document).not.toContain('"Resource":"*"');
      }
    }
    for (const policy of Object.values(t.findResources('AWS::IAM::ManagedPolicy')) as any[]) {
      expect(policy.Properties.Roles.length).toBeGreaterThan(0);
      expect(policy.Properties.PolicyDocument.Statement.length).toBeGreaterThan(0);
    }
  });

  test('approval key rotates with a scoped permission and a seven-day maximum approval window', () => {
    const t = Template.fromStack(stacks.sentinel!);
    t.hasResourceProperties('AWS::SecretsManager::RotationSchedule', {
      RotationRules: { AutomaticallyAfterDays: 30 }, RotateImmediatelyOnUpdate: true,
    });
    t.hasResourceProperties('AWS::Lambda::Permission', Match.objectLike({
      Principal: 'secretsmanager.amazonaws.com', SourceAccount: '123456789012',
      SourceArn: Match.objectLike({ Ref: Match.anyValue() }),
    }));
    expect(() => exampleConfig(c => { c.security.aiTriage.approvalTimeoutHours = 720; })).toThrow(/1-168/);
  });

  test('replication can read Object Lock metadata and decrypt destination Bucket Keys', () => {
    const policies = Template.fromStack(stacks.workload).findResources('AWS::IAM::ManagedPolicy');
    const replication: any = Object.entries(policies).find(([id]) => id.includes('ReplicationRoleDefaultPolicy'))![1];
    const statements = replication.Properties.PolicyDocument.Statement;
    for (const action of ['s3:GetObjectRetention', 's3:GetObjectLegalHold']) {
      expect(statements.some((s: any) => [s.Action].flat().includes(action))).toBe(true);
    }
    expect(statements.some((s: any) => [s.Action].flat().includes('kms:Decrypt') && JSON.stringify(s.Resource).includes('ExportsReader'))).toBe(true);
  });

  test('provided workload role has VPC networking and log delivery permissions before Lambda creation', () => {
    const t = Template.fromStack(stacks.workload);
    const policies = t.findResources('AWS::IAM::ManagedPolicy');
    const entry = Object.entries(policies).find(([id]) => id.startsWith('AppExecutionRoleDefaultPolicy'))!;
    const statements = entry[1].Properties.PolicyDocument.Statement;
    for (const action of ['ec2:CreateNetworkInterface', 'ec2:DeleteNetworkInterface', 'logs:PutLogEvents']) {
      expect(statements.some((s: any) => [s.Action].flat().includes(action))).toBe(true);
    }
    const fn: any = Object.values(t.findResources('AWS::Lambda::Function')).find((r: any) => r.Properties.VpcConfig);
    expect(fn.DependsOn).toContain(entry[0]);
  });

  test('Config recorder starts only after its delivery channel exists', () => {
    const t = Template.fromStack(stacks.foundation);
    t.hasResourceProperties('AWS::Config::ConfigurationRecorder', { StartedOnCreate: false });
    const channelId = Object.keys(t.findResources('AWS::Config::DeliveryChannel'))[0];
    const starters = Object.values(t.findResources('Custom::AWS')).filter((r: any) =>
      JSON.stringify(r.Properties.Create).includes('StartConfigurationRecorder'));
    expect(starters).toHaveLength(1);
    expect((starters[0] as any).DependsOn).toContain(channelId);
  });

  test('Bedrock invocation grants contain only exact configured models and profiles', () => {
    const policies = Template.fromStack(stacks.sentinel!).findResources('AWS::IAM::ManagedPolicy');
    const statements = (Object.values(policies) as any[]).flatMap(p => p.Properties.PolicyDocument.Statement);
    const invocation = statements.filter(s => JSON.stringify(s.Action).includes('bedrock:InvokeModel'));
    expect(invocation).toHaveLength(2);
    for (const statement of invocation) {
      expect(JSON.stringify(statement.Resource)).not.toContain('*');
      expect(JSON.stringify(statement.Resource)).toContain('foundation-model/openai.gpt-oss-20b-1:0');
    }
    expect(() => exampleConfig(c => { c.security.aiTriage.modelId = 'us.anthropic.claude-sonnet-5-5'; delete c.security.aiTriage.modelResourceArns; })).toThrow(/exact backing/);
  });

  test('log delivery is unlocked and separate from the six-year WORM archive', () => {
    const t = Template.fromStack(stacks.foundation);
    const buckets = t.findResources('AWS::S3::Bucket') as Record<string, any>;
    const archive = Object.values(buckets).find(b => b.Properties.ObjectLockEnabled);
    const delivery = Object.values(buckets).find(b => !b.Properties.ObjectLockEnabled);
    expect(archive.Properties.ObjectLockConfiguration.Rule.DefaultRetention).toEqual({ Mode: 'COMPLIANCE', Days: 2190 });
    expect(archive.Properties.BucketEncryption.ServerSideEncryptionConfiguration[0].ServerSideEncryptionByDefault.SSEAlgorithm).toEqual('aws:kms');
    expect(delivery.Properties.VersioningConfiguration).toEqual({ Status: 'Enabled' });
    expect(delivery.Properties.ObjectLockConfiguration).toBeUndefined();
    // Failed archival must not expire the only remaining source copy.
    expect(delivery.Properties.LifecycleConfiguration).toBeUndefined();
    const replica = Object.values(Template.fromStack(stacks.dr!).findResources('AWS::S3::Bucket') as Record<string, any>)
      .find(b => b.Properties.BucketName.includes('phi-dr'));
    expect(JSON.stringify(replica.Properties.LoggingConfiguration.DestinationBucketName)).toContain('LogDeliveryBucket');
  });

  test('triage pipeline never routes to containment without a policy decision', () => {
    const t = Template.fromStack(stacks.sentinel!);
    const sms = t.findResources('AWS::StepFunctions::StateMachine');
    const def = JSON.stringify((Object.values(sms)[0] as any).Properties.DefinitionString);
    expect(def).toContain('RouteByPolicy');
    expect(def).toContain('RequestHumanApproval');
    expect(def).toContain('WasApproved?');
  });

  test('config validation rejects weak retention', () => {
    expect(() => exampleConfig((c) => { c.security.resilience.backupRetentionDays = 7; })).toThrow(/35/);
  });

  test('single-region deployment synthesizes without a DR stack', () => {
    const s = synth(exampleConfig((c) => { delete c.security.resilience.drRegion; }));
    expect(s.dr).toBeUndefined();
  });
});
