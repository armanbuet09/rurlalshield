#!/usr/bin/env node
/** Offline synthesis evidence; never contacts AWS or deploys resources. */
import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';
import * as cdk from 'aws-cdk-lib';
import { AwsSolutionsChecks, HIPAASecurityChecks } from 'cdk-nag';
import { loadConfig } from '../lib/config';
import { buildRuralShield } from '../lib/app-builder';
import { applyNagSuppressions } from '../lib/nag-suppressions';
import { RuralShieldChecks } from '../lib/aspects/rural-shield-aspects';

const configPath = process.argv[2] ?? 'rural-shield.example.yaml';
const cfg = loadConfig(configPath);
// A fixed synthetic account makes this reproducible before AWS credentials exist.
cfg.organization.account = '123456789012';
const outdir = path.resolve('cdk.out', 'local-verification');
const context = JSON.parse(fs.readFileSync('cdk.json', 'utf8')).context;
const app = new cdk.App({ outdir, context });
const stacks = buildRuralShield(app, cfg);
cdk.Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true, reports: true }));
cdk.Aspects.of(app).add(new HIPAASecurityChecks({ verbose: true, reports: true }));
cdk.Aspects.of(app).add(new RuralShieldChecks(), { priority: cdk.AspectPriority.READONLY });
applyNagSuppressions({ ...stacks, sentinel: stacks.sentinel ?? stacks.workload });
const assembly = app.synth();
const errors = assembly.stacks.flatMap(stack => stack.messages
  .filter(message => message.level === 'error')
  .map(message => ({ stack: stack.stackName, path: message.id, message: String(message.entry.data) })));
const warnings = assembly.stacks.flatMap(stack => stack.messages
  .filter(message => message.level === 'warning')
  .map(message => ({ stack: stack.stackName, path: message.id, message: String(message.entry.data) })));
const byRule: Record<string, number> = {};
for (const error of errors) {
  const rule = error.message.match(/^([\w.-]+)(?:\[|:)/)?.[1] ?? 'Other';
  byRule[rule] = (byRule[rule] ?? 0) + 1;
}
const result = {
  mode: 'offline-synthesis-only',
  verifiedAt: new Date().toISOString(),
  config: configPath,
  configSha256: createHash('sha256').update(fs.readFileSync(configPath)).digest('hex'),
  nodeVersion: process.version,
  cdkVersion: JSON.parse(fs.readFileSync(require.resolve('aws-cdk-lib/package.json'), 'utf8')).version,
  nagVersion: JSON.parse(fs.readFileSync(require.resolve('cdk-nag/package.json'), 'utf8')).version,
  stacks: assembly.stacks.map(stack => ({
    name: stack.stackName,
    resources: Object.keys(stack.template.Resources ?? {}).length,
  })),
  unsuppressedErrors: errors.length,
  warnings,
  errorsByRule: byRule,
  errors,
};
fs.writeFileSync(path.join(outdir, 'verification.json'), JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify({ outdir, stacks: result.stacks, unsuppressedErrors: errors.length, warnings: warnings.length, errorsByRule: byRule }, null, 2));
process.exitCode = errors.length ? 1 : 0;
