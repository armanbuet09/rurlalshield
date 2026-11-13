import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { SecurityBaseline } from '../constructs/security-baseline';
import { RuralShieldConfig } from '../config';

export interface RuralShieldFoundationStackProps extends cdk.StackProps {
  readonly config: RuralShieldConfig;
}

/** Account-level landing zone: KMS, immutable log archive, CloudTrail, Config, detection services. */
export class RuralShieldFoundationStack extends cdk.Stack {
  public readonly baseline: SecurityBaseline;

  constructor(scope: Construct, id: string, props: RuralShieldFoundationStackProps) {
    super(scope, id, { ...props, description: `RuralShield foundation for ${props.config.organization.name}` });
    this.baseline = new SecurityBaseline(this, 'Baseline', { config: props.config });
  }
}
