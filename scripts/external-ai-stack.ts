/** Standalone manual experiment. Never imported by the RuralShield app. */
import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as path from 'path';
import * as fs from 'fs';
import {Construct} from 'constructs';

export interface ExternalAiProps extends cdk.StackProps {
  secretArn: string;
  secretKeyArn?: string;
  assetPath: string;
}

export class ExternalAiStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ExternalAiProps) {
    super(scope, id, props);
    if (!/^arn:aws:secretsmanager:[\w-]+:\d{12}:secret:[\w/+=.@-]+$/.test(props.secretArn)) {
      throw new Error('Provide one exact Secrets Manager secret ARN, without wildcards');
    }
    if (props.secretKeyArn && !/^arn:aws:kms:[\w-]+:\d{12}:key\/[a-f0-9-]+$/.test(props.secretKeyArn)) {
      throw new Error('Provide one exact KMS key ARN');
    }
    const group = new logs.LogGroup(this, 'Logs', {
      retention: logs.RetentionDays.ONE_WEEK, removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const role = new iam.Role(this, 'ManualExperimentRole', {assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com')});
    role.addToPolicy(new iam.PolicyStatement({actions: ['logs:CreateLogStream', 'logs:PutLogEvents'], resources: [group.logGroupArn]}));
    role.addToPolicy(new iam.PolicyStatement({actions: ['secretsmanager:GetSecretValue'], resources: [props.secretArn]}));
    if (props.secretKeyArn) {
      role.addToPolicy(new iam.PolicyStatement({actions: ['kms:Decrypt'], resources: [props.secretKeyArn],
        conditions: {StringEquals: {'kms:ViaService': `secretsmanager.${this.region}.amazonaws.com`}}}));
    }
    const fn = new lambda.Function(this, 'ManualExperiment', {
      runtime: lambda.Runtime.PYTHON_3_13, architecture: lambda.Architecture.ARM_64,
      handler: 'handler.lambda_handler', code: lambda.Code.fromAsset(props.assetPath), role, logGroup: group,
      memorySize: 256, timeout: cdk.Duration.seconds(60), reservedConcurrentExecutions: 1, retryAttempts: 0,
      environment: {API_SECRET_ARN: props.secretArn, EXPERIMENT_ENABLED: 'false'},
    });
    new cdk.CfnOutput(this, 'ManualFunctionName', {value: fn.functionName});
    cdk.Tags.of(this).add('rural-shield:purpose', 'separate-external-ai-experiment');
  }
}

if (require.main === module) {
  const app = new cdk.App({outdir: 'cdk.out/external-ai-synth'});
  const assetPath = path.resolve('cdk.out/external-ai-asset');
  if (!fs.existsSync(path.join(assetPath, 'source-manifest.json'))) {
    throw new Error('Run the external experiment --package command first');
  }
  const secretArn = app.node.tryGetContext('externalAiSecretArn');
  if (!secretArn) throw new Error('Pass externalAiSecretArn explicitly; never pass an API key in CDK context');
  new ExternalAiStack(app, 'RuralShield-ExternalAiExperiment', {
    env: {account: '123456789012', region: 'us-east-2'}, secretArn,
    secretKeyArn: app.node.tryGetContext('externalAiSecretKeyArn'), assetPath,
    description: 'Disabled manual synthetic OpenAI experiment; separate from frozen non-AI pilot',
  });
  app.synth();
}
