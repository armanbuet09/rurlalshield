import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as notifications from 'aws-cdk-lib/aws-s3-notifications';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as actions from 'aws-cdk-lib/aws-cloudwatch-actions';
import { NagSuppressions } from 'cdk-nag';
import * as path from 'path';
import { boundedResourceName } from '../resource-names';

/** AWS log delivery requires an unlocked SSE-S3 bucket. Copy each received
 * version into the WORM archive. Keep the source indefinitely for recovery
 * rather than expiring unarchived logs when delivery/processing fails. */
export class LogDelivery extends Construct {
  public readonly bucket: s3.Bucket;

  constructor(scope: Construct, id: string, props: {
    archive: s3.IBucket; key: kms.IKey; alerts: sns.ITopic; bucketName: string;
  }) {
    super(scope, id);
    this.bucket = new s3.Bucket(this, 'Bucket', {
      bucketName: boundedResourceName(props.bucketName, 63), encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true, blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      versioned: true, removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const dlq = new sqs.Queue(this, 'Dlq', {
      encryption: sqs.QueueEncryption.KMS, encryptionMasterKey: props.key,
      enforceSSL: true, retentionPeriod: cdk.Duration.days(14),
    });
    // Import recovery can pin an existing generated name without replacing its log data.
    const retainedNames = this.node.tryGetContext('retainedLogGroupNames') as Record<string, string> | undefined;
    const logGroup = new logs.LogGroup(this, 'Logs', {
      logGroupName: retainedNames?.[this.node.path],
      encryptionKey: props.key, retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const copier = new lambda.Function(this, 'Archive', {
      runtime: lambda.Runtime.PYTHON_3_13, architecture: lambda.Architecture.ARM_64,
      handler: 'handler.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', '..', 'src', 'lambda', 'archive_logs')),
      environment: { SOURCE_BUCKET: this.bucket.bucketName, ARCHIVE_BUCKET: props.archive.bucketName },
      environmentEncryption: props.key, logGroup, deadLetterQueue: dlq,
      reservedConcurrentExecutions: 10, timeout: cdk.Duration.minutes(2),
      tracing: lambda.Tracing.ACTIVE,
    });
    this.bucket.grantRead(copier);
    props.archive.grantPut(copier, 'service-delivery/*');
    props.key.grantEncryptDecrypt(copier);
    this.bucket.addEventNotification(s3.EventType.OBJECT_CREATED, new notifications.LambdaDestination(copier));
    cdk.Tags.of(copier).add('rural-shield:protected', 'true');
    cdk.Tags.of(copier.role!).add('rural-shield:protected', 'true');
    NagSuppressions.addResourceSuppressions(copier.role!, [{
      id: 'AwsSolutions-IAM5', reason: 'The archiver reads versions only in its delivery bucket and writes only the service-delivery prefix of its WORM archive.',
      appliesTo: [{ regex: '/^Resource::<[^>]+>\\/(service-delivery\\/)?\\*$/' }],
    }], true);
    const failed = new cloudwatch.Alarm(this, 'FailedArchive', {
      metric: dlq.metricApproximateNumberOfMessagesVisible(), threshold: 1,
      evaluationPeriods: 1, treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'Audit log archival failed. Redrive the DLQ; source object versions are retained.',
    });
    failed.addAlarmAction(new actions.SnsAction(props.alerts));
  }
}
