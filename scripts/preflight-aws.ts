#!/usr/bin/env node
/** Read-only account checks against a freshly synthesized research assembly.
 * Never creates resources, submits quota requests, or accepts billing/model terms. */
import * as fs from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { createHash } from 'crypto';
import { loadConfig } from '../lib/config';

const configPath = process.argv[2] ?? 'rural-shield.yaml';
const assemblyPath = process.argv[3] ?? 'cdk.out/research-preflight';
const profile = process.env.AWS_PROFILE ?? 'ruralshield-research';
const cfg = loadConfig(configPath);
const bundledCli = path.join(process.env.LOCALAPPDATA ?? '', 'Programs', 'Amazon', 'AWSCLIV2', 'aws.exe');
const cli = process.env.AWS_CLI_PATH ?? (fs.existsSync(bundledCli) ? bundledCli : 'aws');
const manifest = JSON.parse(fs.readFileSync(path.join(assemblyPath, 'manifest.json'), 'utf8'));
const reservations: Record<string, number> = {};
let synthesisErrors = 0;
for (const artifact of Object.values(manifest.artifacts) as any[]) {
  if (artifact.type !== 'aws:cloudformation:stack') continue;
  const [, account, region] = artifact.environment.match(/^aws:\/\/([^/]+)\/(.+)$/) ?? [];
  if (!region || account !== cfg.organization.account) throw new Error('Assembly account does not match config; synthesize it again.');
  const template = JSON.parse(fs.readFileSync(path.join(assemblyPath, artifact.properties.templateFile), 'utf8'));
  reservations[region] = (reservations[region] ?? 0) + (Object.values(template.Resources) as any[])
    .filter(resource => resource.Type === 'AWS::Lambda::Function')
    .reduce((sum, resource) => sum + (resource.Properties.ReservedConcurrentExecutions ?? 0), 0);
  synthesisErrors += (Object.values(artifact.metadata ?? {}) as any[][]).flat()
    .filter(entry => entry.type === 'aws:cdk:error').length;
}
const checks: { name: string; passed: boolean; detail: unknown }[] = [];
const check = (name: string, passed: boolean, detail: unknown) => checks.push({ name, passed, detail });
function read(service: string, operation: string, region: string, args: string[] = []): any {
  const result = spawnSync(cli, [service, operation, '--profile', profile, '--region', region,
    '--output', 'json', '--no-cli-pager', '--cli-connect-timeout', '10', '--cli-read-timeout', '15', ...args],
    { encoding: 'utf8', windowsHide: true, timeout: 45000,
      env: { ...process.env, AWS_MAX_ATTEMPTS: '2' } });
  if (result.error || result.status !== 0) throw new Error(result.error?.message ?? result.stderr.trim());
  return JSON.parse(result.stdout);
}
function attempt(name: string, fn: () => void) {
  try { fn(); } catch (error) { check(name, false, String(error)); }
}
check('synthesis annotations', synthesisErrors === 0, { unsuppressedErrors: synthesisErrors });
attempt('deployment identity', () => {
  const identity = read('sts', 'get-caller-identity', cfg.organization.region);
  check('deployment identity', identity.Account === cfg.organization.account, { account: identity.Account, arn: identity.Arn });
});
attempt('account plan', () => {
  const plan = read('freetier', 'get-account-plan-state', cfg.organization.region);
  check('account plan', plan.accountPlanStatus === 'ACTIVE', {
    type: plan.accountPlanType, status: plan.accountPlanStatus,
    remainingCredits: plan.accountPlanRemainingCredits,
  });
});
attempt('root account protections', () => {
  const summary = read('iam', 'get-account-summary', cfg.organization.region).SummaryMap;
  check('root account protections', summary.AccountMFAEnabled === 1 && summary.AccountAccessKeysPresent === 0,
    { rootMfaEnabled: summary.AccountMFAEnabled === 1, rootAccessKeysPresent: summary.AccountAccessKeysPresent });
});
attempt('research cost budget', () => {
  const budget = read('budgets', 'describe-budget', cfg.organization.region,
    ['--account-id', cfg.organization.account!, '--budget-name', 'RuralShield-Research-Monthly']).Budget;
  check('research cost budget', Number(budget.BudgetLimit.Amount) > 0 && budget.CostTypes.IncludeCredit === false,
    { name: budget.BudgetName, limit: budget.BudgetLimit, excludesCredits: budget.CostTypes.IncludeCredit === false });
});
for (const [region, requiredReserved] of Object.entries(reservations)) {
  attempt(`CDK bootstrap ${region}`, () => {
    const stack = read('cloudformation', 'describe-stacks', region, ['--stack-name', 'CDKToolkit']).Stacks[0];
    check(`CDK bootstrap ${region}`, ['CREATE_COMPLETE', 'UPDATE_COMPLETE'].includes(stack.StackStatus),
      { status: stack.StackStatus, version: stack.Outputs?.find((output: any) => output.OutputKey === 'BootstrapVersion')?.OutputValue });
  });
  attempt(`Lambda concurrency ${region}`, () => {
    const limits = read('lambda', 'get-account-settings', region).AccountLimit;
    check(`Lambda concurrency ${region}`, limits.UnreservedConcurrentExecutions >= requiredReserved + 100,
      { requiredReserved, minimumAccountQuota: requiredReserved + 100,
        currentAccountQuota: limits.ConcurrentExecutions, currentUnreserved: limits.UnreservedConcurrentExecutions });
  });
}
if (cfg.security.threatDetection.guardDuty) attempt('GuardDuty subscription', () => {
  const existing = read('guardduty', 'list-detectors', cfg.organization.region).DetectorIds;
  check('GuardDuty subscription', (cfg.security.existingResources?.guardDutyDetector === true) === (existing.length > 0),
    { accessible: true, existingDetectors: existing.length, note: 'Existing detectors require existingResources.guardDutyDetector=true.' });
});
if (cfg.security.aiTriage.enabled) {
  const ai = cfg.security.aiTriage;
  // Discovered through Service Quotas in the research account. These source-region
  // quotas apply to US profiles or the regional GPT OSS model; unknown models still require smoke:model.
  const tokenQuotaCodes: Record<string, string> = {
    'us.anthropic.claude-sonnet-5-5': 'L-94A31E46',
    'us.anthropic.claude-sonnet-4-6': 'L-15B8E632',
    'openai.gpt-oss-20b-1:0': 'L-036E14D8',
  };
  if (tokenQuotaCodes[ai.modelId]) attempt('Bedrock source token quota', () => {
    const quota = read('service-quotas', 'get-service-quota', cfg.organization.region,
      ['--service-code', 'bedrock', '--quota-code', tokenQuotaCodes[ai.modelId]]).Quota;
    check('Bedrock source token quota', quota.Value > 0,
      { name: quota.QuotaName, code: quota.QuotaCode, tokensPerMinute: quota.Value });
  });
  if (ai.modelId === 'openai.gpt-oss-20b-1:0') attempt('Bedrock regional request quota', () => {
    const quota = read('service-quotas', 'get-service-quota', cfg.organization.region,
      ['--service-code', 'bedrock', '--quota-code', 'L-AF7F0545']).Quota;
    check('Bedrock regional request quota', quota.Value > 0,
      { name: quota.QuotaName, code: quota.QuotaCode, requestsPerMinute: quota.Value });
  });
  const modelArns = ai.modelResourceArns ?? [ai.modelId.startsWith('arn:') ? ai.modelId
    : `arn:aws:bedrock:${cfg.organization.region}::foundation-model/${ai.modelId}`];
  for (const arn of modelArns) {
    const model = arn.split('foundation-model/')[1];
    const region = arn.split(':')[3];
    attempt(`Bedrock access ${region} ${model}`, () => {
      const access = read('bedrock', 'get-foundation-model-availability', region, ['--model-id', model]);
      check(`Bedrock access ${region} ${model}`,
        access.agreementAvailability?.status === 'AVAILABLE' && access.authorizationStatus === 'AUTHORIZED'
        && access.entitlementAvailability === 'AVAILABLE' && access.regionAvailability === 'AVAILABLE', access);
    });
  }
}
const result = {
  mode: 'read-only-account-preflight', checkedAt: new Date().toISOString(), profile,
  configSha256: createHash('sha256').update(fs.readFileSync(configPath)).digest('hex'),
  assemblyPath: path.resolve(assemblyPath),
  readyForDeploymentPrerequisites: checks.every(item => item.passed), checks,
  note: 'Other service limits, actual model invocation, email confirmation and live tests still require verification.',
};
const output = path.join(assemblyPath, 'aws-preflight.json');
fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result, null, 2));
console.log(`Saved ${output}`);
process.exitCode = result.readyForDeploymentPrerequisites ? 0 : 1;
