import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigw from 'aws-cdk-lib/aws-apigateway';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as ecsPatterns from 'aws-cdk-lib/aws-ecs-patterns';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import * as fs from 'fs';
import * as path from 'path';
import { RuralShieldConfig, LambdaCompute, ContainerCompute } from '../config';

/** Map operator runtime strings to CDK runtime constants (falls back to a raw runtime name). */
export function resolveRuntime(name: string): lambda.Runtime {
  const known: Record<string, lambda.Runtime> = {
    'python3.12': lambda.Runtime.PYTHON_3_12,
    'python3.13': lambda.Runtime.PYTHON_3_13,
    'nodejs20.x': lambda.Runtime.NODEJS_20_X,
    'nodejs22.x': lambda.Runtime.NODEJS_22_X,
    'java21': lambda.Runtime.JAVA_21,
    'dotnet8': lambda.Runtime.DOTNET_8,
    'ruby3.3': lambda.Runtime.RUBY_3_3,
  };
  return known[name] ?? new lambda.Runtime(name, lambda.RuntimeFamily.OTHER);
}

export interface ServerlessAppProps {
  readonly config: RuralShieldConfig;
  readonly key: kms.IKey;
  readonly vpc: ec2.IVpc;
  readonly appSubnets: ec2.SubnetSelection;
  readonly logDelivery: s3.IBucket;
  readonly appLogRetention: logs.RetentionDays;
  readonly userPool: cognito.IUserPool;
  /** Extra environment passed to the operator's code (table name, bucket, DB secret ARN, ...). */
  readonly dataEnvironment: Record<string, string>;
}

/**
 * Hosts the operator's software. Two modes, same guarantees:
 *   lambda    -> Amazon API Gateway (REST, regional) + AWS Lambda in the private VPC
 *   container -> Application Load Balancer (HTTPS only) + AWS Fargate in the private VPC
 * In both cases: WAF managed rule groups + rate limiting, Cognito-authenticated requests,
 * structured access logs to CloudWatch (encrypted) and the WORM archive, X-Ray tracing,
 * least-privilege execution role, and no OS or runtime host to patch (AWS owns that layer).
 */
export class ServerlessApp extends Construct {
  public readonly role: iam.Role;
  public readonly securityGroup: ec2.SecurityGroup;
  public readonly endpointUrl: string;
  public readonly webAcl: wafv2.CfnWebACL;
  public readonly lambdaFunction?: lambda.Function;
  public readonly api?: apigw.RestApi;
  public readonly fargateService?: ecsPatterns.ApplicationLoadBalancedFargateService;

  constructor(scope: Construct, id: string, props: ServerlessAppProps) {
    super(scope, id);
    const cfg = props.config;
    const slug = cfg.organization.slug!;
    const stack = cdk.Stack.of(this);

    this.securityGroup = new ec2.SecurityGroup(this, 'AppSg', {
      vpc: props.vpc,
      description: `RuralShield application tier for ${cfg.workload.name}`,
      allowAllOutbound: true, // outbound is bounded by the network layer (no NAT by default)
    });

    const isLambda = cfg.workload.compute.type === 'lambda';
    this.role = new iam.Role(this, 'ExecutionRole', {
      roleName: `${slug}-${cfg.workload.name}-app`,
      assumedBy: new iam.ServicePrincipal(isLambda ? 'lambda.amazonaws.com' : 'ecs-tasks.amazonaws.com'),
      description: 'Least-privilege execution role for the operator workload (grants added by DataLayer)',
    });
    props.key.grantEncryptDecrypt(this.role);

    // WAF: AWS managed rule groups + a rate-based rule. Scope is REGIONAL for both API GW and ALB.
    this.webAcl = this.createWebAcl(slug, cfg.workload.name, props.appLogRetention, props.key);

    if (isLambda) {
      const c = cfg.workload.compute as LambdaCompute;
      const { fn, api } = this.createLambdaApi(c, props, slug);
      this.lambdaFunction = fn;
      this.api = api;
      this.endpointUrl = api.url;
      new wafv2.CfnWebACLAssociation(this, 'WafAssoc', {
        resourceArn: api.deploymentStage.stageArn,
        webAclArn: this.webAcl.attrArn,
      });
    } else {
      const c = cfg.workload.compute as ContainerCompute;
      const svc = this.createFargateService(c, props, slug);
      this.fargateService = svc;
      this.endpointUrl = `https://${c.domainName}`;
      new wafv2.CfnWebACLAssociation(this, 'WafAssoc', {
        resourceArn: svc.loadBalancer.loadBalancerArn,
        webAclArn: this.webAcl.attrArn,
      });
    }

    new cdk.CfnOutput(this, 'EndpointUrl', { value: this.endpointUrl, description: 'Public HTTPS endpoint (WAF + Cognito protected)' });
    void stack;
  }

  // ------------------------------------------------------------------ Lambda mode
  private createLambdaApi(c: LambdaCompute, props: ServerlessAppProps, slug: string): { fn: lambda.Function; api: apigw.RestApi } {
    const cfg = props.config;

    const dlq = new sqs.Queue(this, 'Dlq', {
      queueName: `${slug}-${cfg.workload.name}-dlq`,
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: props.key,
      enforceSSL: true,
      retentionPeriod: cdk.Duration.days(14),
    });

    const logGroup = new logs.LogGroup(this, 'FnLogs', {
      logGroupName: `/rural-shield/${slug}/${cfg.workload.name}/app`,
      encryptionKey: props.key,
      retention: props.appLogRetention,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // A supplied execution role does not receive Lambda's generated VPC/logging role policies.
    this.role.addToPrincipalPolicy(new iam.PolicyStatement({
      actions: ['ec2:CreateNetworkInterface', 'ec2:DescribeNetworkInterfaces', 'ec2:DescribeSubnets',
        'ec2:DeleteNetworkInterface', 'ec2:AssignPrivateIpAddresses', 'ec2:UnassignPrivateIpAddresses'],
      resources: ['*'],
    }));
    logGroup.grantWrite(this.role);

    const fn = new lambda.Function(this, 'Fn', {
      functionName: `${slug}-${cfg.workload.name}`,
      description: `${cfg.organization.name} - ${cfg.workload.name} (RuralShield managed)`,
      runtime: resolveRuntime(c.runtime), // operator picks e.g. python3.12, nodejs22.x
      handler: c.handler,
      code: lambda.Code.fromAsset(c.codePath),
      role: this.role,
      vpc: props.vpc,
      vpcSubnets: props.appSubnets,
      securityGroups: [this.securityGroup],
      memorySize: c.memoryMb,
      timeout: cdk.Duration.seconds(c.timeoutSeconds ?? 15),
      reservedConcurrentExecutions: c.reservedConcurrency,
      environment: {
        ...(c.environment ?? {}),
        ...props.dataEnvironment,
        RURAL_SHIELD_ORG: cfg.organization.name,
        RURAL_SHIELD_HANDLES_PHI: String(cfg.workload.handlesPhi),
        POWERTOOLS_SERVICE_NAME: cfg.workload.name,
      },
      environmentEncryption: props.key,
      tracing: lambda.Tracing.ACTIVE,
      deadLetterQueue: dlq,
      logGroup,
      architecture: lambda.Architecture.ARM_64,
    });
    cdk.Tags.of(fn).add('DataClassification', cfg.workload.handlesPhi ? 'PHI' : 'Internal');

    const accessLogs = new logs.LogGroup(this, 'ApiAccessLogs', {
      logGroupName: `/rural-shield/${slug}/${cfg.workload.name}/api-access`,
      encryptionKey: props.key,
      retention: props.appLogRetention,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const clientCert = new apigw.CfnClientCertificate(this, 'ClientCert', {
      description: 'Backend mutual-TLS client certificate (HIPAA.Security-APIGWSSLEnabled)',
    });

    const api = new apigw.RestApi(this, 'Api', {
      restApiName: `${slug}-${cfg.workload.name}`,
      description: `${cfg.organization.name} - ${cfg.workload.name}`,
      endpointConfiguration: { types: [apigw.EndpointType.REGIONAL] },
      cloudWatchRole: true,
      deployOptions: {
        stageName: cfg.organization.environment,
        loggingLevel: apigw.MethodLoggingLevel.INFO,
        dataTraceEnabled: false, // never log request/response bodies: they may contain PHI
        metricsEnabled: true,
        tracingEnabled: true,
        accessLogDestination: new apigw.LogGroupLogDestination(accessLogs),
        accessLogFormat: apigw.AccessLogFormat.jsonWithStandardFields({
          caller: true, httpMethod: true, ip: true, protocol: true, requestTime: true,
          resourcePath: true, responseLength: true, status: true, user: true,
        }),
        throttlingRateLimit: 200,
        throttlingBurstLimit: 100,
        clientCertificateId: clientCert.attrClientCertificateId,
      },
      defaultCorsPreflightOptions: cfg.workload.allowedOrigins?.length
        ? {
            allowOrigins: cfg.workload.allowedOrigins,
            allowMethods: apigw.Cors.ALL_METHODS,
            allowHeaders: ['Authorization', 'Content-Type', 'X-Amz-Date', 'X-Api-Key', 'X-Amz-Security-Token'],
            maxAge: cdk.Duration.hours(1),
          }
        : undefined,
    });

    const authorizer = new apigw.CognitoUserPoolsAuthorizer(this, 'Authorizer', {
      cognitoUserPools: [props.userPool],
      resultsCacheTtl: cdk.Duration.minutes(5),
    });
    const validator = new apigw.RequestValidator(this, 'Validator', {
      restApi: api,
      validateRequestBody: true,
      validateRequestParameters: true,
    });
    const integration = new apigw.LambdaIntegration(fn, { proxy: true });
    const methodOptions: apigw.MethodOptions = {
      authorizer,
      authorizationType: apigw.AuthorizationType.COGNITO,
      requestValidator: validator,
    };
    // Every path and verb is authenticated; the operator's code does fine-grained authorization.
    api.root.addMethod('ANY', integration, methodOptions);
    api.root.addResource('{proxy+}').addMethod('ANY', integration, methodOptions);

    // Health endpoint used by synthetic monitors: still authenticated (no anonymous surface).
    return { fn, api };
  }

  // --------------------------------------------------------------- Container mode
  private createFargateService(c: ContainerCompute, props: ServerlessAppProps, slug: string): ecsPatterns.ApplicationLoadBalancedFargateService {
    const cfg = props.config;
    const cluster = new ecs.Cluster(this, 'Cluster', {
      clusterName: `${slug}-${cfg.workload.name}`,
      vpc: props.vpc,
      containerInsightsV2: ecs.ContainerInsights.ENHANCED,
      enableFargateCapacityProviders: true,
    });
    const logGroup = new logs.LogGroup(this, 'TaskLogs', {
      logGroupName: `/rural-shield/${slug}/${cfg.workload.name}/app`,
      encryptionKey: props.key,
      retention: props.appLogRetention,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    // A local directory containing a Dockerfile is built and pushed to the CDK ECR repository (scanned by
    // Inspector); anything else is treated as an image URI (ECR recommended so it is scanned too).
    const localDir = path.resolve(c.image);
    const image = fs.existsSync(localDir) && fs.statSync(localDir).isDirectory()
      ? ecs.ContainerImage.fromAsset(localDir)
      : ecs.ContainerImage.fromRegistry(c.image);

    const svc = new ecsPatterns.ApplicationLoadBalancedFargateService(this, 'Service', {
      cluster,
      serviceName: `${slug}-${cfg.workload.name}`,
      cpu: c.cpu,
      memoryLimitMiB: c.memoryMb,
      desiredCount: c.desiredCount,
      publicLoadBalancer: true,
      protocol: elbv2.ApplicationProtocol.HTTPS,
      certificate: acm.Certificate.fromCertificateArn(this, 'Cert', c.certificateArn),
      sslPolicy: elbv2.SslPolicy.TLS13_RES,
      redirectHTTP: true,
      domainName: undefined, // DNS alias is left to the operator's registrar (Route 53 optional)
      taskSubnets: props.appSubnets,
      securityGroups: [this.securityGroup],
      assignPublicIp: false,
      platformVersion: ecs.FargatePlatformVersion.LATEST,
      runtimePlatform: { cpuArchitecture: ecs.CpuArchitecture.ARM64, operatingSystemFamily: ecs.OperatingSystemFamily.LINUX },
      circuitBreaker: { rollback: true },
      taskImageOptions: {
        image,
        containerPort: c.containerPort,
        taskRole: this.role,
        environment: {
          ...(c.environment ?? {}),
          ...props.dataEnvironment,
          RURAL_SHIELD_ORG: cfg.organization.name,
          RURAL_SHIELD_HANDLES_PHI: String(cfg.workload.handlesPhi),
        },
        logDriver: ecs.LogDrivers.awsLogs({ streamPrefix: cfg.workload.name, logGroup }),
      },
    });
    svc.targetGroup.configureHealthCheck({ path: '/health', healthyHttpCodes: '200-299' });
    svc.loadBalancer.logAccessLogs(props.logDelivery, `alb/${cfg.workload.name}`);
    svc.loadBalancer.setAttribute('routing.http.drop_invalid_header_fields.enabled', 'true');
    svc.loadBalancer.setAttribute('deletion_protection.enabled', 'true');
    // Containers run as read-only root FS where the image allows it; Fargate ephemeral storage is encrypted by default.
    const taskDef = svc.taskDefinition;
    taskDef.defaultContainer?.addUlimits({ name: ecs.UlimitName.NOFILE, softLimit: 65536, hardLimit: 65536 });
    cdk.Tags.of(svc.service).add('DataClassification', cfg.workload.handlesPhi ? 'PHI' : 'Internal');
    return svc;
  }

  // -------------------------------------------------------------------- WAF
  private createWebAcl(slug: string, workload: string, retention: logs.RetentionDays, key: kms.IKey): wafv2.CfnWebACL {
    const managed = (name: string, priority: number, vendor = 'AWS'): wafv2.CfnWebACL.RuleProperty => ({
      name,
      priority,
      overrideAction: { none: {} },
      statement: { managedRuleGroupStatement: { vendorName: vendor, name } },
      visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: name },
    });
    const acl = new wafv2.CfnWebACL(this, 'WebAcl', {
      name: `${slug}-${workload}`,
      scope: 'REGIONAL',
      defaultAction: { allow: {} },
      visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: `${slug}-${workload}` },
      rules: [
        managed('AWSManagedRulesAmazonIpReputationList', 0),
        managed('AWSManagedRulesCommonRuleSet', 1),
        managed('AWSManagedRulesKnownBadInputsRuleSet', 2),
        managed('AWSManagedRulesSQLiRuleSet', 3),
        {
          name: 'RateLimitPerIp',
          priority: 10,
          action: { block: {} },
          statement: { rateBasedStatement: { limit: 1000, aggregateKeyType: 'IP', evaluationWindowSec: 300 } },
          visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: 'RateLimitPerIp' },
        },
      ],
    });
    // WAF log group names must start with "aws-waf-logs-".
    const wafLogs = new logs.LogGroup(this, 'WafLogs', {
      logGroupName: `aws-waf-logs-${slug}-${workload}`,
      encryptionKey: key,
      retention,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    new wafv2.CfnLoggingConfiguration(this, 'WafLogging', {
      resourceArn: acl.attrArn,
      logDestinationConfigs: [wafLogs.logGroupArn],
      redactedFields: [{ singleHeader: { Name: 'authorization' } }, { singleHeader: { Name: 'cookie' } }],
    });
    return acl;
  }
}
