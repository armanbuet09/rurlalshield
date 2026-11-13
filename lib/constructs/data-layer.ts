import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as guardduty from 'aws-cdk-lib/aws-guardduty';
import { RuralShieldConfig } from '../config';

export interface DataLayerProps {
  readonly config: RuralShieldConfig;
  readonly key: kms.IKey;
  readonly vpc: ec2.IVpc;
  readonly dataSubnets: ec2.SubnetSelection;
  readonly logDelivery: s3.IBucket;
  readonly appLogRetention: logs.RetentionDays;
  /** Set when a DR region is configured: PHI objects replicate to this bucket, encrypted with this key. */
  readonly drReplication?: { readonly bucket: s3.IBucket; readonly key: kms.IKey };
}

/**
 * Every data store is encrypted with the organization's CMK, reachable only from the private
 * network, protected from deletion, backed up by AWS Backup (see ResilienceLayer) and tagged for
 * classification. The PHI bucket is additionally WORM-protected and malware-scanned on upload;
 * a bucket policy denies the application access to any object that has not been scanned clean
 * (GuardDuty tags objects with GuardDutyMalwareScanStatus).
 */
export class DataLayer extends Construct {
  public readonly table?: dynamodb.TableV2;
  public readonly cluster?: rds.DatabaseCluster;
  public readonly phiBucket?: s3.Bucket;
  public readonly dbSecurityGroup?: ec2.SecurityGroup;

  constructor(scope: Construct, id: string, props: DataLayerProps) {
    super(scope, id);
    const cfg = props.config;
    const stack = cdk.Stack.of(this);
    const slug = cfg.organization.slug!;
    const data = cfg.workload.data;

    // ---------------------------------------------------------------- DynamoDB
    if (data.dynamodb) {
      this.table = new dynamodb.TableV2(this, 'Table', {
        tableName: `${slug}-${cfg.workload.name}`,
        partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
        sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
        billing: dynamodb.Billing.onDemand(),
        encryption: dynamodb.TableEncryptionV2.customerManagedKey(props.key),
        pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true, recoveryPeriodInDays: 35 },
        deletionProtection: true,
        contributorInsights: true,
        removalPolicy: cdk.RemovalPolicy.RETAIN,
        timeToLiveAttribute: 'ttl',
      });
      cdk.Tags.of(this.table).add('DataClassification', cfg.workload.handlesPhi ? 'PHI' : 'Internal');
      cdk.Tags.of(this.table).add('rural-shield:backup', 'true');
    }

    // ----------------------------------------------------- Aurora Serverless v2
    if (data.aurora) {
      this.dbSecurityGroup = new ec2.SecurityGroup(this, 'DbSg', {
        vpc: props.vpc,
        description: 'RuralShield Aurora: ingress only from application security group',
        allowAllOutbound: false,
      });
      const version = data.auroraEngineVersion ?? '16.4';
      const major = version.split('.')[0];
      const engine = rds.DatabaseClusterEngine.auroraPostgres({
        version: rds.AuroraPostgresEngineVersion.of(version, major),
      });
      const parameterGroup = new rds.ParameterGroup(this, 'PgParams', {
        engine,
        description: 'RuralShield: force TLS, log connections and DDL',
        parameters: {
          'rds.force_ssl': '1',                 // encryption in transit is not optional for ePHI
          'log_connections': '1',
          'log_disconnections': '1',
          'log_statement': 'ddl',
          'log_min_duration_statement': '5000',
          'rds.log_retention_period': '10080',
        },
      });
      this.cluster = new rds.DatabaseCluster(this, 'Aurora', {
        clusterIdentifier: `${slug}-${cfg.workload.name}`,
        engine,
        parameterGroup,
        port: data.auroraPort,
        writer: rds.ClusterInstance.serverlessV2('writer', {
          autoMinorVersionUpgrade: true,
          enablePerformanceInsights: true,
          performanceInsightEncryptionKey: props.key,
          publiclyAccessible: false,
        }),
        readers: [rds.ClusterInstance.serverlessV2('reader', { scaleWithWriter: true, autoMinorVersionUpgrade: true, publiclyAccessible: false })],
        serverlessV2MinCapacity: data.auroraMinAcu ?? 0.5,
        serverlessV2MaxCapacity: data.auroraMaxAcu ?? 4,
        vpc: props.vpc,
        vpcSubnets: props.dataSubnets,
        securityGroups: [this.dbSecurityGroup],
        storageEncrypted: true,
        storageEncryptionKey: props.key,
        credentials: rds.Credentials.fromGeneratedSecret('rsadmin', { encryptionKey: props.key, excludeCharacters: '"@/\\ \'' }),
        iamAuthentication: true,
        deletionProtection: true,
        copyTagsToSnapshot: true,
        backup: { retention: cdk.Duration.days(35), preferredWindow: '03:00-04:00' },
        cloudwatchLogsExports: ['postgresql'],
        cloudwatchLogsRetention: props.appLogRetention,
        monitoringInterval: cdk.Duration.seconds(60),
        removalPolicy: cdk.RemovalPolicy.RETAIN,
      });
      // 30-day automatic rotation of the master credential (HIPAA.Security-SecretsManagerRotationEnabled).
      this.cluster.addRotationSingleUser({
        automaticallyAfter: cdk.Duration.days(30),
        vpcSubnets: props.dataSubnets,
        excludeCharacters: '"@/\\ \'',
      });
      cdk.Tags.of(this.cluster).add('DataClassification', cfg.workload.handlesPhi ? 'PHI' : 'Internal');
      cdk.Tags.of(this.cluster).add('rural-shield:backup', 'true');
    }

    // -------------------------------------------------------------- PHI bucket
    if (data.phiBucket) {
      const name = `${slug}-rshield-phi-${stack.account}-${stack.region}`;
      // The DR key already trusts this account for S3 replication. Import its ARN
      // so grants stay on the source role instead of creating a DR -> Workload cycle.
      const replicationKey = props.drReplication
        ? kms.Key.fromKeyArn(this, 'DrReplicationKey', props.drReplication.key.keyArn)
        : undefined;
      const replicationRules: s3.ReplicationRule[] | undefined = props.drReplication
        ? [{
            destination: props.drReplication.bucket,
            priority: 1,
            id: 'phi-dr-replication',
            kmsKey: replicationKey,
            sseKmsEncryptedObjects: true,
            deleteMarkerReplication: false, // ransomware deleting originals must not delete replicas
            replicationTimeControl: s3.ReplicationTimeValue.FIFTEEN_MINUTES,
            metrics: s3.ReplicationTimeValue.FIFTEEN_MINUTES,
          }]
        : undefined;

      this.phiBucket = new s3.Bucket(this, 'PhiBucket', {
        bucketName: name,
        encryption: s3.BucketEncryption.KMS,
        encryptionKey: props.key,
        bucketKeyEnabled: true,
        enforceSSL: true,
        minimumTLSVersion: 1.2,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
        versioned: true,
        objectLockEnabled: true,
        // GOVERNANCE lets break-glass admins with s3:BypassGovernanceRetention correct genuine mistakes
        // while still defeating credential-theft ransomware; set COMPLIANCE for stricter regimes.
        objectLockDefaultRetention: s3.ObjectLockRetention.governance(cdk.Duration.days(cfg.security.resilience.backupRetentionDays)),
        serverAccessLogsBucket: props.logDelivery,
        serverAccessLogsPrefix: `s3-access/${cfg.workload.name}/`,
        eventBridgeEnabled: true, // required by GuardDuty Malware Protection for S3
        lifecycleRules: [{
          id: 'noncurrent-cleanup',
          noncurrentVersionExpiration: cdk.Duration.days(cfg.security.resilience.backupRetentionDays + 30),
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(7),
        }],
        replicationRules,
        removalPolicy: cdk.RemovalPolicy.RETAIN,
      });
      if (replicationKey) {
        // Object Lock metadata and destination Bucket Keys need additional read/decrypt grants.
        const replicationRole = this.phiBucket.node.findChild('ReplicationRole') as iam.Role;
        replicationRole.addToPrincipalPolicy(new iam.PolicyStatement({
          actions: ['s3:GetObjectRetention', 's3:GetObjectLegalHold'],
          resources: [this.phiBucket.arnForObjects('*')],
        }));
        replicationKey.grantDecrypt(replicationRole);
      }
      cdk.Tags.of(this.phiBucket).add('DataClassification', 'PHI');
      cdk.Tags.of(this.phiBucket).add('rural-shield:backup', 'true');

      if (cfg.security.threatDetection.s3MalwareProtection && cfg.security.threatDetection.guardDuty) {
        this.addMalwareProtection(this.phiBucket, props.key, slug);
      }
    }
  }

  /**
   * Grants the workload role access to the data layer with least privilege. When malware scanning
   * is on, GetObject is additionally denied unless the object is tagged NO_THREATS_FOUND.
   */
  public grantWorkloadAccess(role: iam.IRole, appSecurityGroup?: ec2.ISecurityGroup): void {
    if (this.table) this.table.grantReadWriteData(role);
    if (this.phiBucket) {
      this.phiBucket.grantReadWrite(role);
      this.phiBucket.addToResourcePolicy(new iam.PolicyStatement({
        sid: 'DenyReadOfUnscannedOrInfectedObjects',
        effect: iam.Effect.DENY,
        principals: [new iam.ArnPrincipal(role.roleArn)],
        actions: ['s3:GetObject', 's3:GetObjectVersion'],
        resources: [this.phiBucket.arnForObjects('*')],
        conditions: { StringNotEquals: { 's3:ExistingObjectTag/GuardDutyMalwareScanStatus': 'NO_THREATS_FOUND' } },
      }));
    }
    if (this.cluster && this.dbSecurityGroup && appSecurityGroup) {
      this.dbSecurityGroup.addIngressRule(appSecurityGroup, ec2.Port.tcp(this.cluster.clusterEndpoint.port), 'App tier to Aurora (TLS forced)');
      this.cluster.secret?.grantRead(role);
      // IAM database authentication for the application user "app_user" (create it once with rds_iam).
      this.cluster.grantConnect(role, 'app_user');
    }
  }

  private addMalwareProtection(bucket: s3.Bucket, key: kms.IKey, slug: string): void {
    const stack = cdk.Stack.of(this);
    const role = new iam.Role(this, 'MalwareScanRole', {
      assumedBy: new iam.ServicePrincipal('malware-protection-plan.guardduty.amazonaws.com'),
      description: 'GuardDuty Malware Protection for S3 (scan-on-upload of PHI objects)',
    });
    // Permissions follow the GuardDuty "Malware Protection for S3 prerequisite IAM policy" documentation.
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowManagedRuleToSendS3EventsToGuardDuty',
      actions: ['events:PutRule', 'events:DeleteRule', 'events:PutTargets', 'events:RemoveTargets'],
      resources: [`arn:${stack.partition}:events:${stack.region}:${stack.account}:rule/DO-NOT-DELETE-AmazonGuardDutyMalwareProtectionS3*`],
      conditions: {
        StringLike: { 'events:ManagedBy': 'malware-protection-plan.guardduty.amazonaws.com' },
      },
    }));
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowGuardDutyToMonitorEventBridgeManagedRule',
      actions: ['events:DescribeRule', 'events:ListTargetsByRule'],
      resources: [`arn:${stack.partition}:events:${stack.region}:${stack.account}:rule/DO-NOT-DELETE-AmazonGuardDutyMalwareProtectionS3*`],
    }));
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowPostScanTag',
      actions: ['s3:PutObjectTagging', 's3:GetObjectTagging', 's3:PutObjectVersionTagging', 's3:GetObjectVersionTagging'],
      resources: [bucket.arnForObjects('*')],
    }));
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowEnableS3EventBridgeEvents',
      actions: ['s3:PutBucketNotification', 's3:GetBucketNotification'],
      resources: [bucket.bucketArn],
    }));
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowPutValidationObject',
      actions: ['s3:PutObject'],
      resources: [bucket.arnForObjects('malware-protection-resource-validation-object')],
    }));
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowCheckBucketOwnership',
      actions: ['s3:ListBucket'],
      resources: [bucket.bucketArn],
    }));
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowMalwareScan',
      actions: ['s3:GetObject', 's3:GetObjectVersion'],
      resources: [bucket.arnForObjects('*')],
    }));
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowDecryptForMalwareScan',
      actions: ['kms:GenerateDataKey', 'kms:Decrypt'],
      resources: [key.keyArn],
      conditions: { StringLike: { 'kms:ViaService': `s3.${stack.region}.amazonaws.com` } },
    }));

    const plan = new guardduty.CfnMalwareProtectionPlan(this, 'MalwareProtectionPlan', {
      role: role.roleArn,
      protectedResource: { s3Bucket: { bucketName: bucket.bucketName } },
      actions: { tagging: { status: 'ENABLED' } },
      tags: [{ key: 'rural-shield:component', value: 'malware-protection' }],
    });
    plan.node.addDependency(role);
    plan.node.addDependency(bucket);
  }
}
