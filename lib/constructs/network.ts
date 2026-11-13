import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as s3 from 'aws-cdk-lib/aws-s3';

export interface PrivateNetworkProps {
  readonly logDelivery: s3.IBucket;
  /** Adds public subnets + a NAT gateway (outbound internet for the workload). Default false. */
  readonly allowInternetEgress: boolean;
  /** Container mode needs public subnets for the internet-facing ALB even without NAT. */
  readonly needsPublicSubnets: boolean;
  /** 'lambda' = Secrets Manager, KMS, Logs, X-Ray. 'container' adds ECR, ECR Docker, CloudWatch metrics. */
  readonly endpointSet: 'lambda' | 'container';
  /** Add a Bedrock Runtime endpoint when the operator's application itself calls Bedrock. */
  readonly includeBedrockEndpoint?: boolean;
}

/**
 * The default posture is "no internet": compute runs in isolated subnets and reaches AWS
 * services only through VPC endpoints. This removes NAT cost and, more importantly, removes
 * the egress path that ransomware staging and data exfiltration depend on.
 *
 * Interface endpoints cost roughly $7/month per AZ each, so the set is deliberately minimal
 * (see docs/COST_MODEL.md). Gateway endpoints for S3 and DynamoDB are free.
 */
export class PrivateNetwork extends Construct {
  public readonly vpc: ec2.Vpc;
  public readonly appSubnets: ec2.SubnetSelection;
  public readonly dataSubnets: ec2.SubnetSelection;

  constructor(scope: Construct, id: string, props: PrivateNetworkProps) {
    super(scope, id);

    const subnetConfiguration: ec2.SubnetConfiguration[] = [];
    if (props.needsPublicSubnets || props.allowInternetEgress) {
      subnetConfiguration.push({ name: 'public', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 26, mapPublicIpOnLaunch: false });
    }
    const appSubnetType = props.allowInternetEgress ? ec2.SubnetType.PRIVATE_WITH_EGRESS : ec2.SubnetType.PRIVATE_ISOLATED;
    subnetConfiguration.push({ name: 'app', subnetType: appSubnetType, cidrMask: 24 });
    subnetConfiguration.push({ name: 'data', subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 24 });

    const vpcCidr = '10.42.0.0/16';
    this.vpc = new ec2.Vpc(this, 'Vpc', {
      ipAddresses: ec2.IpAddresses.cidr(vpcCidr),
      maxAzs: 2,
      natGateways: props.allowInternetEgress ? 1 : 0,
      subnetConfiguration,
      restrictDefaultSecurityGroup: true, // CIS 5.4 / HIPAA.Security-VPCDefaultSecurityGroupClosed
      flowLogs: {
        toArchive: {
          destination: ec2.FlowLogDestination.toS3(props.logDelivery, 'vpc-flow-logs/'),
          trafficType: ec2.FlowLogTrafficType.ALL,
        },
      },
    });

    this.appSubnets = { subnetGroupName: 'app' };
    this.dataSubnets = { subnetGroupName: 'data' };

    this.vpc.addGatewayEndpoint('S3', { service: ec2.GatewayVpcEndpointAwsService.S3 });
    this.vpc.addGatewayEndpoint('DynamoDb', { service: ec2.GatewayVpcEndpointAwsService.DYNAMODB });

    const interfaces: Array<[string, ec2.InterfaceVpcEndpointAwsService]> = [
      ['SecretsManager', ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER],
      ['Kms', ec2.InterfaceVpcEndpointAwsService.KMS],
      ['Logs', ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS],
      ['Xray', ec2.InterfaceVpcEndpointAwsService.XRAY],
    ];
    if (props.endpointSet === 'container') {
      interfaces.push(['Ecr', ec2.InterfaceVpcEndpointAwsService.ECR]);
      interfaces.push(['EcrDocker', ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER]);
      interfaces.push(['Monitoring', ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_MONITORING]);
    }
    if (props.includeBedrockEndpoint) {
      interfaces.push(['Bedrock', ec2.InterfaceVpcEndpointAwsService.BEDROCK_RUNTIME]);
    }
    // When a NAT gateway exists the endpoints are still preferable: traffic stays on the AWS
    // backbone and endpoint policies can be used to pin access to this account's resources.
    const endpointSg = new ec2.SecurityGroup(this, 'EndpointSg', {
      vpc: this.vpc, description: 'Private HTTPS access to AWS service endpoints', allowAllOutbound: false,
    });
    // The literal matches IpAddresses above and lets static port/CIDR checks
    // evaluate the rule without an unresolved VPC CidrBlock intrinsic.
    endpointSg.addIngressRule(ec2.Peer.ipv4(vpcCidr), ec2.Port.tcp(443), 'VPC HTTPS only');
    for (const [name, service] of interfaces) {
      this.vpc.addInterfaceEndpoint(name, {
        service, privateDnsEnabled: true, subnets: this.appSubnets,
        open: false, securityGroups: [endpointSg],
      });
    }

    new cdk.CfnOutput(this, 'VpcId', { value: this.vpc.vpcId });
  }
}
