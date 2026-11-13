import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sns from 'aws-cdk-lib/aws-sns';
import { AiSentinel } from '../constructs/ai-sentinel';
import { RuralShieldConfig } from '../config';
import { retentionFromYears } from './workload-stack';

export interface RuralShieldSentinelStackProps extends cdk.StackProps {
  readonly config: RuralShieldConfig;
  readonly key: kms.IKey;
  readonly logArchive: s3.IBucket;
  readonly alerts: sns.ITopic;
}

/** AI-assisted triage, policy-bounded containment, human approval and weekly reporting. */
export class RuralShieldSentinelStack extends cdk.Stack {
  public readonly sentinel: AiSentinel;

  constructor(scope: Construct, id: string, props: RuralShieldSentinelStackProps) {
    super(scope, id, { ...props, description: `RuralShield AI Sentinel for ${props.config.organization.name}` });
    this.sentinel = new AiSentinel(this, 'Sentinel', {
      config: props.config,
      key: props.key,
      alerts: props.alerts,
      logArchive: props.logArchive,
      appLogRetention: retentionFromYears(props.config.security.compliance.appLogRetentionYears ?? 1),
    });
    // The Sentinel's own roles must be immune to its containment actions.
    for (const f of this.sentinel.functions) {
      cdk.Tags.of(f.role!).add('rural-shield:protected', 'true');
    }
  }
}
