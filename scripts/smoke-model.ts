#!/usr/bin/env node
/** One billed, synthetic Converse request. Run only after accepting the model's terms. */
import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';
import { spawnSync } from 'child_process';
import { loadConfig } from '../lib/config';

const configPath = process.argv[2] ?? 'rural-shield.yaml';
const cfg = loadConfig(configPath);
if (!cfg.security.aiTriage.enabled) throw new Error('AI triage is disabled in this configuration.');
const profile = process.env.AWS_PROFILE ?? 'ruralshield-research';
const bundled = path.join(process.env.LOCALAPPDATA ?? '', 'Programs', 'Amazon', 'AWSCLIV2', 'aws.exe');
const cli = process.env.AWS_CLI_PATH ?? (fs.existsSync(bundled) ? bundled : 'aws');
const outdir = path.resolve('cdk.out/aws-setup');
fs.mkdirSync(outdir, { recursive: true });
const requestFile = path.join(outdir, 'model-smoke-request.json');
fs.writeFileSync(requestFile, JSON.stringify({
  modelId: cfg.security.aiTriage.modelId,
  messages: [{ role: 'user', content: [{ text: 'Reply with exactly RURALSHIELD_MODEL_OK. This is a connectivity test using synthetic data.' }] }],
  inferenceConfig: { maxTokens: 64, temperature: 0 },
}, null, 2));
const startedAt = new Date().toISOString();
const start = Date.now();
const call = spawnSync(cli, ['bedrock-runtime', 'converse', '--cli-input-json', `file://${requestFile}`,
  '--profile', profile, '--region', cfg.organization.region, '--output', 'json', '--no-cli-pager'],
  { encoding: 'utf8', windowsHide: true, timeout: 45000,
    env: { ...process.env, AWS_MAX_ATTEMPTS: '1' } });
let response: any;
let error = call.error?.message ?? (call.status !== 0 ? call.stderr.trim() : undefined);
if (!error) {
  try { response = JSON.parse(call.stdout); } catch { error = 'AWS CLI returned invalid JSON.'; }
}
const output = response?.output?.message?.content?.map((item: any) => item.text ?? '').join('').trim();
const passed = !error && output === 'RURALSHIELD_MODEL_OK';
const result = {
  mode: 'single-synthetic-model-smoke-test', startedAt, finishedAt: new Date().toISOString(),
  profile, region: cfg.organization.region, modelId: cfg.security.aiTriage.modelId,
  configSha256: createHash('sha256').update(fs.readFileSync(configPath)).digest('hex'),
  passed, cliElapsedMs: Date.now() - start, error,
  output, usage: response?.usage, metrics: response?.metrics, stopReason: response?.stopReason,
  note: 'Connectivity check only; excludes Guardrails, triage, EventBridge, containment and application tests.',
};
fs.writeFileSync(path.join(outdir, 'model-smoke-result.json'), JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result, null, 2));
process.exitCode = passed ? 0 : 1;
