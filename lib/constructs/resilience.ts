import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as backup from 'aws-cdk-lib/aws-backup';
import * as events from 'aws-cdk-lib/aws-events';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { RuralShieldConfig } from '../config';
import { boundedResourceName } from '../resource-names';

export interface ResilienceLayerProps {
  readonly config: RuralShieldConfig;
  readonly key: kms.IKey;
  readonly alerts: sns.ITopic;
  readonly table?: dynamodb.ITable;
  readonly cluster?: rds.IDatabaseCluster;
  readonly phiBucket?: s3.IBucket;
  /** Vault in the DR region (created by RuralShieldDrStack; passed via cross-region references). */
  readonly drVault?: backup.IBackupVault;
}

/**
 * Ransomware recovery is the single most important control for a hospital that cannot divert
 * patients. Recovery points are written to a vault with Vault Lock (WORM) so that stolen admin
 * credentials cannot delete them, copied to a second region when configured, and restore-tested
 * automatically every week so the "we have backups" claim is continuously verified
 * (HPH CPG Essential: Basic Incident Planning & Preparedness; HIPAA §164.308(a)(7); NPRM 72-hour restore).
 */
export class ResilienceLayer extends Construct {
  public readonly vault: backup.BackupVault;
  public readonly plan: backup.BackupPlan;

  constructor(scope: Construct, id: string, props: ResilienceLayerProps) {
    super(scope, id);
    const cfg = props.config;
    const slug = cfg.organization.slug!;
    const retention = cdk.Duration.days(cfg.security.resilience.backupRetentionDays);
    const stack = cdk.Stack.of(this);

    this.vault = new backup.BackupVault(this, 'Vault', {
      backupVaultName: boundedResourceName(`${slug}-rural-shield-${cfg.workload.name}`, 50),
      encryptionKey: props.key,
      notificationTopic: props.alerts,
      notificationEvents: [
        backup.BackupVaultEvents.BACKUP_JOB_FAILED,
        backup.BackupVaultEvents.COPY_JOB_FAILED,
        backup.BackupVaultEvents.RESTORE_JOB_FAILED,
        backup.BackupVaultEvents.RESTORE_JOB_COMPLETED,
      ],
      lockConfiguration: {
        minRetention: retention,
        // Compliance-mode lock after 3 days: enough time to validate the deployment, then immutable.
        changeableFor: cdk.Duration.days(3),
      },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const copyActions: backup.BackupPlanCopyActionProps[] | undefined = props.drVault
      ? [{ destinationBackupVault: props.drVault, deleteAfter: retention }]
      : undefined;

    this.plan = new backup.BackupPlan(this, 'Plan', {
      backupPlanName: `${slug}-rural-shield-${cfg.workload.name}`,
      backupVault: this.vault,
      backupPlanRules: [
        new backup.BackupPlanRule({
          ruleName: 'daily',
          backupVault: this.vault,
          scheduleExpression: events.Schedule.cron({ hour: '4', minute: '0' }),
          startWindow: cdk.Duration.hours(1),
          completionWindow: cdk.Duration.hours(4),
          deleteAfter: retention,
          // Point-in-time restore for DynamoDB / Aurora / S3; AWS caps continuous backups at 35 days.
          enableContinuousBackup: cfg.security.resilience.backupRetentionDays <= 35,
          copyActions,
        }),
        new backup.BackupPlanRule({
          ruleName: 'monthly-long-term',
          backupVault: this.vault,
          scheduleExpression: events.Schedule.cron({ day: '1', hour: '5', minute: '0' }),
          deleteAfter: cdk.Duration.days(365),
          moveToColdStorageAfter: cdk.Duration.days(90),
          copyActions,
        }),
      ],
    });

    const resources: backup.BackupResource[] = [];
    if (props.table) resources.push(backup.BackupResource.fromDynamoDbTable(props.table));
    if (props.cluster) resources.push(backup.BackupResource.fromRdsDatabaseCluster(props.cluster));
    if (props.phiBucket) resources.push(backup.BackupResource.fromArn(props.phiBucket.bucketArn));
    if (resources.length) {
      const selectionRole = new iam.Role(this, 'BackupSelectionRole', {
        assumedBy: new iam.ServicePrincipal('backup.amazonaws.com'),
      });
      this.plan.addSelection('Selection', {
        resources,
        allowRestores: true,
        role: selectionRole,
      });
      // S3 backups need these additional permissions on the selection role.
      if (props.phiBucket) {
        selectionRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('AWSBackupServiceRolePolicyForS3Backup'));
        selectionRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('AWSBackupServiceRolePolicyForS3Restore'));
      }
      props.key.grantEncryptDecrypt(selectionRole);
    }

    // Weekly automated restore test: proves recoverability instead of assuming it.
    if (cfg.security.resilience.restoreTesting && props.table) {
      const restoreRole = new iam.Role(this, 'RestoreTestRole', {
        assumedBy: new iam.ServicePrincipal('backup.amazonaws.com'),
        managedPolicies: [
          iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSBackupServiceRolePolicyForRestores'),
        ],
      });
      props.key.grantEncryptDecrypt(restoreRole);
      const testPlan = new backup.CfnRestoreTestingPlan(this, 'RestoreTestPlan', {
        restoreTestingPlanName: `${slug.replace(/-/g, '_')}_weekly_restore_test`,
        scheduleExpression: 'cron(0 6 ? * SUN *)',
        startWindowHours: 2,
        recoveryPointSelection: {
          algorithm: 'LATEST_WITHIN_WINDOW',
          includeVaults: [this.vault.backupVaultArn],
          recoveryPointTypes: ['SNAPSHOT', 'CONTINUOUS'],
          selectionWindowDays: 7,
        },
      });
      new backup.CfnRestoreTestingSelection(this, 'RestoreTestDynamo', {
        restoreTestingPlanName: testPlan.restoreTestingPlanName,
        restoreTestingSelectionName: 'dynamodb_tables',
        protectedResourceType: 'DynamoDB',
        iamRoleArn: restoreRole.roleArn,
        protectedResourceArns: [props.table.tableArn],
        validationWindowHours: 2,
      }).addDependency(testPlan);
    }

    new cdk.CfnOutput(this, 'BackupVaultArn', { value: this.vault.backupVaultArn });
    void stack;
  }
}
