import * as cdk from 'aws-cdk-lib';
import { RuralShieldConfig } from './config';
import { RuralShieldFoundationStack } from './stacks/foundation-stack';
import { RuralShieldWorkloadStack } from './stacks/workload-stack';
import { RuralShieldSentinelStack } from './stacks/sentinel-stack';
import { RuralShieldDrStack } from './stacks/dr-stack';
import { applyFrameworkTags } from './aspects/rural-shield-aspects';
import { ManagedRolePolicies } from './aspects/managed-policies';

export interface RuralShieldStacks {
  foundation: RuralShieldFoundationStack;
  workload: RuralShieldWorkloadStack;
  sentinel?: RuralShieldSentinelStack;
  dr?: RuralShieldDrStack;
}

/** Builds the full stack set from a config. Used by the CLI entrypoint and by the tests. */
export function buildRuralShield(app: cdk.App, cfg: RuralShieldConfig): RuralShieldStacks {
  cdk.Aspects.of(app).add(new ManagedRolePolicies(), { priority: cdk.AspectPriority.MUTATING });
  const account = cfg.organization.account ?? process.env.CDK_DEFAULT_ACCOUNT;
  const env: cdk.Environment = { account, region: cfg.organization.region };
  const prefix = `RuralShield-${cfg.organization.slug}-${cfg.workload.name}`;

  const foundation = new RuralShieldFoundationStack(app, `${prefix}-Foundation`, { env, config: cfg });

  let dr: RuralShieldDrStack | undefined;
  if (cfg.security.resilience.drRegion) {
    dr = new RuralShieldDrStack(app, `${prefix}-DR`, {
      env: { account, region: cfg.security.resilience.drRegion },
      config: cfg,
      crossRegionReferences: true, // lets the workload stack reference the DR key, bucket and vault directly
    });
  }

  const workload = new RuralShieldWorkloadStack(app, `${prefix}-Workload`, {
    env,
    config: cfg,
    key: foundation.baseline.key,
    logArchive: foundation.baseline.logArchive,
    logDelivery: foundation.baseline.logDelivery,
    alerts: foundation.baseline.alerts,
    dr: dr ? { key: dr.key, replicaBucket: dr.replicaBucket, vault: dr.vault } : undefined,
    crossRegionReferences: !!dr,
  });
  workload.addDependency(foundation);
  if (dr) workload.addDependency(dr);

  let sentinel: RuralShieldSentinelStack | undefined;
  if (cfg.security.aiTriage.enabled) {
    sentinel = new RuralShieldSentinelStack(app, `${prefix}-Sentinel`, {
      env,
      config: cfg,
      key: foundation.baseline.key,
      logArchive: foundation.baseline.logArchive,
      alerts: foundation.baseline.alerts,
    });
    sentinel.addDependency(foundation);
  }

  applyFrameworkTags(app, cfg);
  return { foundation, workload, sentinel, dr };
}
