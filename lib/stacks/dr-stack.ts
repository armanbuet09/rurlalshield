import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as backup from 'aws-cdk-lib/aws-backup';
import * as iam from 'aws-cdk-lib/aws-iam';
import { RuralShieldConfig } from '../config';
import { boundedResourceName } from '../resource-names';
import { LogDelivery } from '../constructs/log-delivery';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subs from 'aws-cdk-lib/aws-sns-subscriptions';

export interface RuralShieldDrStackProps extends cdk.StackProps {
  readonly config: RuralShieldConfig;
}

/** Deterministic resource names (the primary stacks receive the real objects via cross-region references). */
export function drNames(cfg: RuralShieldConfig, account: string, partition = 'aws') {
  const slug = cfg.organization.slug!;
  const region = cfg.security.resilience.drRegion!;
  const vaultName = boundedResourceName(`${slug}-rural-shield-${cfg.workload.name}-dr`, 50);
  const bucketName = `${slug}-rshield-phi-dr-${account}-${region}`;
  const alias = `alias/${slug}-rural-shield-dr`;
  return {
    region,
    vaultName,
    vaultArn: `arn:${partition}:backup:${region}:${account}:backup-vault:${vaultName}`,
    bucketName,
    bucketArn: `arn:${partition}:s3:::${bucketName}`,
    keyAlias: alias,
    keyAliasArn: `arn:${partition}:kms:${region}:${account}:${alias}`,
  };
}

/**
 * Secondary-region immutable copies: a vault-locked backup vault and a replica PHI bucket encrypted
 * with a separate CMK. A regional outage or a destructive attack in the primary region leaves this
 * copy intact; recovery is a `cdk deploy` of the workload stack into this region.
 */
export class RuralShieldDrStack extends cdk.Stack {
  public readonly key: kms.Key;
  public readonly vault: backup.BackupVault;
  public readonly replicaBucket: s3.Bucket;

  constructor(scope: Construct, id: string, props: RuralShieldDrStackProps) {
    super(scope, id, { ...props, description: `RuralShield disaster-recovery copies for ${props.config.organization.name}` });
    const cfg = props.config;
    const names = drNames(cfg, this.account, this.partition);
    const retention = cdk.Duration.days(cfg.security.resilience.backupRetentionDays);

    this.key = new kms.Key(this, 'DrKey', {
      alias: names.keyAlias,
      description: 'RuralShield DR region CMK',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    // S3 replication (running in the primary region) encrypts replicas with this key.
    this.key.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowCloudWatchLogs', principals: [new iam.ServicePrincipal(`logs.${this.region}.amazonaws.com`)],
      actions: ['kms:Encrypt*', 'kms:Decrypt*', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:Describe*'], resources: ['*'],
      conditions: { ArnLike: { 'kms:EncryptionContext:aws:logs:arn': `arn:${this.partition}:logs:${this.region}:${this.account}:log-group:*` } },
    }));
    this.key.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowS3ReplicationFromPrimary',
      principals: [new iam.AccountPrincipal(this.account)],
      actions: ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey*', 'kms:DescribeKey'],
      resources: ['*'],
      conditions: { StringEquals: { 'kms:ViaService': `s3.${this.region}.amazonaws.com` } },
    }));
    this.key.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowBackupCopy',
      principals: [new iam.ServicePrincipal('backup.amazonaws.com')],
      actions: ['kms:Decrypt', 'kms:GenerateDataKey*', 'kms:DescribeKey', 'kms:CreateGrant'],
      resources: ['*'],
    }));

    this.vault = new backup.BackupVault(this, 'DrVault', {
      backupVaultName: names.vaultName,
      encryptionKey: this.key,
      lockConfiguration: { minRetention: retention, changeableFor: cdk.Duration.days(3) },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const drLogs = new s3.Bucket(this, 'DrLogs', {
      bucketName: `${cfg.organization.slug}-rshield-logs-dr-${this.account}-${this.region}`,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.key,
      bucketKeyEnabled: true,
      enforceSSL: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      versioned: true,
      objectLockEnabled: true,
      objectLockDefaultRetention: s3.ObjectLockRetention.compliance(cdk.Duration.days(6 * 365)),
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const alerts = new sns.Topic(this, 'DrAlerts', { masterKey: this.key, enforceSSL: true });
    alerts.addSubscription(new subs.EmailSubscription(cfg.organization.contactEmail));
    this.key.addToResourcePolicy(new iam.PolicyStatement({
      principals: [new iam.ServicePrincipal('cloudwatch.amazonaws.com')],
      actions: ['kms:Decrypt', 'kms:GenerateDataKey*'], resources: ['*'],
    }));
    const delivery = new LogDelivery(this, 'LogDelivery', {
      archive: drLogs, key: this.key, alerts,
      bucketName: `${cfg.organization.slug}-rshield-delivery-dr-${this.account}-${this.region}`,
    });

    this.replicaBucket = new s3.Bucket(this, 'PhiReplica', {
      bucketName: names.bucketName,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.key,
      bucketKeyEnabled: true,
      enforceSSL: true,
      minimumTLSVersion: 1.2,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      versioned: true,
      objectLockEnabled: true,
      objectLockDefaultRetention: s3.ObjectLockRetention.governance(retention),
      serverAccessLogsBucket: delivery.bucket,
      serverAccessLogsPrefix: 'phi-replica/',
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    cdk.Tags.of(this.replicaBucket).add('DataClassification', 'PHI');

    new cdk.CfnOutput(this, 'DrVaultArn', { value: this.vault.backupVaultArn });
    new cdk.CfnOutput(this, 'PhiReplicaBucket', { value: this.replicaBucket.bucketName });
  }
}
