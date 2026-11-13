import * as cdk from 'aws-cdk-lib';
import { IConstruct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as backup from 'aws-cdk-lib/aws-backup';
import * as apigw from 'aws-cdk-lib/aws-apigateway';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import { FRAMEWORK_VERSION, RuralShieldConfig } from '../config';

/** Tags every resource so cost, ownership and classification are queryable (HIPAA asset inventory). */
export function applyFrameworkTags(scope: IConstruct, cfg: RuralShieldConfig): void {
  const t = cdk.Tags.of(scope);
  t.add('rural-shield:version', FRAMEWORK_VERSION);
  t.add('rural-shield:organization', cfg.organization.slug!);
  t.add('rural-shield:workload', cfg.workload.name);
  t.add('Environment', cfg.organization.environment);
  t.add('ManagedBy', 'rural-shield-cdk');
}

/**
 * Healthcare-specific guardrails that go beyond the cdk-nag HIPAA pack. They run as a read-only
 * aspect (priority READONLY so tag aspects have already been applied) and fail `cdk synth` on error.
 */
export class RuralShieldChecks implements cdk.IAspect {
  public visit(node: IConstruct): void {
    // App-level aspects also visit App/Stage nodes, which do not belong to a stack.
    if (!(node instanceof cdk.CfnResource)) return;
    const stack = cdk.Stack.of(node);
    const resolve = (v: unknown) => stack.resolve(v);

    if (node instanceof s3.CfnBucket) {
      const classification = node.tags.tagValues()['DataClassification'];
      if (classification === 'PHI') {
        if (resolve(node.objectLockEnabled) !== true) {
          cdk.Annotations.of(node).addError('RuralShield-PHI1: PHI buckets must enable S3 Object Lock (WORM) to survive credential-theft ransomware.');
        }
        const enc = resolve(node.bucketEncryption) as any;
        const algo = enc?.serverSideEncryptionConfiguration?.[0]?.serverSideEncryptionByDefault?.sseAlgorithm;
        if (algo !== 'aws:kms') {
          cdk.Annotations.of(node).addError('RuralShield-PHI2: PHI buckets must use SSE-KMS with the organization CMK.');
        }
        if (!resolve(node.versioningConfiguration)) {
          cdk.Annotations.of(node).addError('RuralShield-PHI3: PHI buckets must be versioned.');
        }
      }
    }

    if (node instanceof cognito.CfnUserPool) {
      if (resolve(node.mfaConfiguration) !== 'ON') {
        cdk.Annotations.of(node).addError('RuralShield-IDN1: MFA must be required for every user (HIPAA Security Rule NPRM; HPH CPG Essential "Multifactor Authentication").');
      }
    }

    if (node instanceof logs.CfnLogGroup) {
      const days = resolve(node.retentionInDays);
      if (days !== undefined && typeof days === 'number' && days < 365) {
        cdk.Annotations.of(node).addError(`RuralShield-LOG1: log retention ${days}d < 365d; audit logs must be kept at least one year (6 years in the S3 archive).`);
      }
    }

    if (node instanceof backup.CfnBackupVault) {
      if (!resolve(node.lockConfiguration)) {
        cdk.Annotations.of(node).addError('RuralShield-BKP1: backup vaults must use Vault Lock so recovery points cannot be deleted by a compromised administrator.');
      }
    }

    if (node instanceof apigw.CfnStage) {
      const methods = (resolve(node.methodSettings) as any[]) ?? [];
      if (methods.some((m) => m?.dataTraceEnabled === true)) {
        cdk.Annotations.of(node).addError('RuralShield-API1: API Gateway data tracing logs full request/response bodies and may capture PHI; it must stay disabled.');
      }
    }

    if (node instanceof rds.CfnDBCluster) {
      if (resolve(node.storageEncrypted) !== true) {
        cdk.Annotations.of(node).addError('RuralShield-DB1: database storage must be encrypted.');
      }
      if (resolve(node.deletionProtection) !== true) {
        cdk.Annotations.of(node).addError('RuralShield-DB2: database clusters must have deletion protection.');
      }
    }

    if (node instanceof dynamodb.CfnGlobalTable || node instanceof dynamodb.CfnTable) {
      const pitr = resolve((node as any).pointInTimeRecoverySpecification ?? (node as any).replicas?.[0]?.pointInTimeRecoverySpecification) as any;
      if (pitr && pitr.pointInTimeRecoveryEnabled === false) {
        cdk.Annotations.of(node).addError('RuralShield-DB3: DynamoDB tables must enable point-in-time recovery.');
      }
    }

    if (node instanceof lambda.CfnFunction) {
      const tracing = resolve(node.tracingConfig) as any;
      if (!tracing || tracing.mode !== 'Active') {
        cdk.Annotations.of(node).addWarning('RuralShield-FN1: Lambda functions should enable X-Ray tracing for incident reconstruction.');
      }
    }
  }
}
