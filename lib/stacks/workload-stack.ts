import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as logs from 'aws-cdk-lib/aws-logs';
import { PrivateNetwork } from '../constructs/network';
import { WorkforceIdentity } from '../constructs/identity';
import { DataLayer } from '../constructs/data-layer';
import { ServerlessApp } from '../constructs/serverless-app';
import { ResilienceLayer } from '../constructs/resilience';
import * as backup from 'aws-cdk-lib/aws-backup';
import { RuralShieldConfig } from '../config';

export interface DrResources {
  readonly key: kms.IKey;
  readonly replicaBucket: s3.IBucket;
  readonly vault: backup.IBackupVault;
}

export interface RuralShieldWorkloadStackProps extends cdk.StackProps {
  readonly config: RuralShieldConfig;
  readonly key: kms.IKey;
  readonly logArchive: s3.IBucket;
  readonly logDelivery: s3.IBucket;
  readonly alerts: sns.ITopic;
  /** Resources from RuralShieldDrStack (requires crossRegionReferences on both stacks). */
  readonly dr?: DrResources;
}

export function retentionFromYears(years: number): logs.RetentionDays {
  switch (years) {
    case 2: return logs.RetentionDays.TWO_YEARS;
    case 3: return logs.RetentionDays.THREE_YEARS;
    case 5: return logs.RetentionDays.FIVE_YEARS;
    case 6: return logs.RetentionDays.SIX_YEARS;
    default: return logs.RetentionDays.ONE_YEAR;
  }
}

/** The operator's application plus everything it needs: network, identity, data, protection, recovery. */
export class RuralShieldWorkloadStack extends cdk.Stack {
  public readonly network: PrivateNetwork;
  public readonly identity: WorkforceIdentity;
  public readonly data: DataLayer;
  public readonly app: ServerlessApp;
  public readonly resilience: ResilienceLayer;

  constructor(scope: Construct, id: string, props: RuralShieldWorkloadStackProps) {
    super(scope, id, { ...props, description: `RuralShield workload ${props.config.workload.name} for ${props.config.organization.name}` });
    const cfg = props.config;
    const retention = retentionFromYears(cfg.security.compliance.appLogRetentionYears ?? 1);
    const isContainer = cfg.workload.compute.type === 'container';

    this.network = new PrivateNetwork(this, 'Network', {
      logDelivery: props.logDelivery,
      allowInternetEgress: cfg.workload.allowInternetEgress ?? false,
      needsPublicSubnets: isContainer,
      endpointSet: isContainer ? 'container' : 'lambda',
      includeBedrockEndpoint: cfg.workload.usesBedrock,
    });

    this.identity = new WorkforceIdentity(this, 'Identity', {
      slug: cfg.organization.slug!,
      workloadName: cfg.workload.name,
      allowedOrigins: cfg.workload.allowedOrigins ?? [],
    });

    this.data = new DataLayer(this, 'Data', {
      config: cfg,
      key: props.key,
      vpc: this.network.vpc,
      dataSubnets: this.network.dataSubnets,
      logDelivery: props.logDelivery,
      appLogRetention: retention,
      drReplication: props.dr ? { bucket: props.dr.replicaBucket, key: props.dr.key } : undefined,
    });

    const dataEnvironment: Record<string, string> = {};
    if (this.data.table) dataEnvironment.TABLE_NAME = this.data.table.tableName;
    if (this.data.phiBucket) dataEnvironment.PHI_BUCKET = this.data.phiBucket.bucketName;
    if (this.data.cluster) {
      dataEnvironment.DB_HOST = this.data.cluster.clusterEndpoint.hostname;
      dataEnvironment.DB_PORT = cdk.Token.asString(this.data.cluster.clusterEndpoint.port);
      dataEnvironment.DB_SECRET_ARN = this.data.cluster.secret?.secretArn ?? '';
      dataEnvironment.DB_NAME = 'postgres';
    }

    this.app = new ServerlessApp(this, 'App', {
      config: cfg,
      key: props.key,
      vpc: this.network.vpc,
      appSubnets: this.network.appSubnets,
      logDelivery: props.logDelivery,
      appLogRetention: retention,
      userPool: this.identity.userPool,
      dataEnvironment,
    });
    this.data.grantWorkloadAccess(this.app.role, this.app.securityGroup);

    // The public ALB security group legitimately allows 443 from the internet; containment must never touch it.
    if (this.app.fargateService) {
      cdk.Tags.of(this.app.fargateService.loadBalancer).add('rural-shield:protected', 'true');
      for (const sg of this.app.fargateService.loadBalancer.connections.securityGroups) {
        cdk.Tags.of(sg).add('rural-shield:protected', 'true');
      }
    }

    this.resilience = new ResilienceLayer(this, 'Resilience', {
      config: cfg,
      key: props.key,
      alerts: props.alerts,
      table: this.data.table,
      cluster: this.data.cluster,
      phiBucket: this.data.phiBucket,
      drVault: props.dr?.vault,
    });
  }
}
