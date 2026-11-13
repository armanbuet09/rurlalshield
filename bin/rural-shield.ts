#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { AwsSolutionsChecks, HIPAASecurityChecks } from 'cdk-nag';
import { loadConfig } from '../lib/config';
import { buildRuralShield } from '../lib/app-builder';
import { applyNagSuppressions } from '../lib/nag-suppressions';
import { RuralShieldChecks } from '../lib/aspects/rural-shield-aspects';

const app = new cdk.App();
const cfg = loadConfig(app.node.tryGetContext('config'));
const stacks = buildRuralShield(app, cfg);

// Compliance-as-code at synth time: AWS Solutions + HIPAA Security rule packs (cdk-nag v2 API), then the
// healthcare-specific RuralShield checks. Any unsuppressed error fails `cdk synth`, so an insecure
// template can never be produced. (cdk-nag v3 users: Validations.of(app).addPlugins(new HIPAASecurityChecks(app)).)
cdk.Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true, reports: true }));
cdk.Aspects.of(app).add(new HIPAASecurityChecks({ verbose: true, reports: true }));
cdk.Aspects.of(app).add(new RuralShieldChecks(), { priority: cdk.AspectPriority.READONLY });

if (stacks.sentinel) {
  applyNagSuppressions({ foundation: stacks.foundation, workload: stacks.workload, sentinel: stacks.sentinel, dr: stacks.dr });
} else {
  applyNagSuppressions({ foundation: stacks.foundation, workload: stacks.workload, sentinel: stacks.workload, dr: stacks.dr });
}

app.synth();
