> Historical research documentation. Dated entries describe the original study, not the state of a new deployment. Account identifiers and operator email addresses in this public snapshot are examples. Private evidence and account configuration are not distributed. See [public release notes](PUBLIC_RELEASE.md).

# Research deployment preflight

This guide supports the experiments in `paper/outline.md` and `docs/EVALUATION_PLAN.md`.
No live deployment or experimental results are claimed by the local checks below.

The planned active research run is **five days (120 hours)** after deployment and
initial functional readiness checks. Keep setup/activation time separate. Preserve
actual duration/load and incomplete experiment targets; the one-million-request
total remains a target within these five days. See `paper/manuscript.md` Section 6
and `docs/EVALUATION_PLAN.md` for the measurement protocol.

## Reproduce local evidence

From the repository root:

```powershell
npm ci
npm run build
npm test -- --runInBand
.\.venv\Scripts\python.exe -m unittest discover -s src/lambda/triage -p "test_*.py"
.\.venv\Scripts\python.exe -m unittest discover -s test -p "test_*.py"
npm run verify:local
```

Use a Python installation in place of the virtual-environment path if needed.
`verify:local` always substitutes a synthetic account ID, performs no deployment,
and exits nonzero when compliance errors remain. Its output under
`cdk.out/local-verification/` includes CloudFormation templates, nag CSV files,
exact CDK/nag/Node versions, the input configuration hash, resource counts and
unsuppressed error details. These are preflight artifacts, not live measurements.
Re-run the checks after any source or dependency change. `docs/STATUS.md` records
the last checked versions and unresolved gate findings.

## Create and prepare an AWS account

1. Use [AWS advanced signup](https://docs.aws.amazon.com/accounts/latest/reference/getting-started.html)
   for full account, IAM and region control. Create a dedicated research account
   using an email you control. Complete payment and verification steps directly
   with AWS. Select Basic Support unless you need paid support.
2. The full framework uses services outside a minimal free learning environment.
   Review the [Free/Paid account plan comparison](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/free-tier-plans.html)
   and choose a plan with the required service access. Paid plans can incur charges
   beyond eligible credits. A paid account plan and paid support are separate choices.
3. Enable root MFA and establish a separate deployment identity. Keep credentials
   out of source control and research artifacts. Do not create root access keys.
4. Create billing alerts and a research budget before deploying. Budget alerts
   do not automatically stop spending.
5. Configure a named AWS CLI profile, then verify its identity:

   ```powershell
   aws sts get-caller-identity --profile ruralshield-research
   ```

### Browser-based CLI login on Windows

The configured `ruralshield-login` profile holds the browser sign-in session.
`ruralshield-research` uses the CLI's `credential_process` provider to share those
temporary credentials with CDK, including SDK versions that do not directly
support `login_session`. No IAM access keys are needed.

To renew the session, use the updated per-user installation (an older system-wide
`aws` installation may still appear first on PATH):

```powershell
$taskAws = Join-Path $env:LOCALAPPDATA 'Programs\Amazon\AWSCLIV2\aws.exe'
& $taskAws login --profile ruralshield-login
aws sts get-caller-identity --profile ruralshield-research
```

This Windows machine uses Norton HTTPS inspection. The two profiles have
`ca_bundle` set to a local PEM containing the CLI's standard authorities and
the Norton root already trusted by Windows. Certificate verification stays on.
For CDK/Node commands in a new PowerShell session, also set:

```powershell
$env:NODE_EXTRA_CA_CERTS = Join-Path $env:USERPROFILE '.aws\ruralshield-ca-bundle.pem'
```

The CA bundle and login cache are machine-local files outside the repository.
The account-specific `cdk.context.json` lookup cache is ignored by Git. Preserve
an anonymized configuration and relevant lookup metadata separately for paper
reproducibility. Authentication was verified with STS and `cdk list --long`;
this does not itself establish bootstrap or deployment success. The current research
account has since been bootstrapped in both regions; see the status ledger.

## Deployment gates

The default static gate passes with documented exceptions. Keep the gate enabled;
review rule interpretation mismatches individually and record any justified
exceptions in the suppression ledger and paper. Preserve both raw findings and
exceptions in E1 results.

Before live deployment:

1. Copy `rural-shield.example.yaml` to the ignored `rural-shield.yaml` and set
   your account, organization, alert inbox and region. Start in Lambda mode with
   synthetic records and `autoContainment: false`. Only enable automatic actions
   for controlled experiments after approval/rollback behavior has been verified.
2. Verify a Bedrock model/profile in the target region and account. Do not treat
   the example model ID as evidence of availability. Pin the selected ID in the
   experimental configuration.
3. Review the two-region configuration and retention settings. Backup Vault Lock
   has a three-day grace period before compliance-mode immutability. Many data
   resources have RETAIN policies, so stack deletion is not complete cleanup.
   Archive objects are locked in COMPLIANCE mode for 2,190 days immediately on write;
   administrators cannot shorten existing retention. Delivery source versions are
   also retained for recovery. Include retained storage in measured research costs.
4. Bootstrap a new account/region pair once, then synthesize and inspect the diff:

   ```powershell
   # Replace the account ID and regions with your actual configuration.
   npx cdk bootstrap aws://123456789012/us-east-2 aws://123456789012/us-west-2 --profile ruralshield-research
   npx cdk synth --quiet --context config=rural-shield.yaml --output cdk.out/research-preflight --profile ruralshield-research
   npx cdk diff --app cdk.out/research-preflight --change-set false --profile ruralshield-research
   ```

For the configured research account, preserve a fresh account-specific assembly
and run the read-only prerequisite check before bootstrap/deployment:

```powershell
npx cdk synth --quiet --context config=rural-shield.yaml --output cdk.out/research-preflight --profile ruralshield-research
npm run preflight:aws
```

This script does not deploy, accept model terms or submit quota requests. It checks
identity, synthesis errors, account plan, root MFA/access keys, cost budget, regional
bootstrap status, Lambda capacity, GuardDuty access, known model token quotas and
Bedrock agreements/entitlement. Its JSON is saved beside the templates. Other service
limits and live operation still require verification. Positive model availability
metadata alone does not prove that inference works.

After accepting the configured model's terms, run a single billed, synthetic request:

```powershell
npm run smoke:model
```

This stores timestamps, model/profile/config hash, usage, latency or the API error in
`cdk.out/aws-setup/model-smoke-result.json`. It does not exercise Guardrails or Sentinel.
For deployment, use the gated Windows entry point:

```powershell
.\scripts\deploy-research.ps1 -Profile ruralshield-research
```

It synthesizes the local research configuration, requires a passing AWS preflight and
model smoke test, presents the diff, then invokes CDK deployment with security-change
approval enabled. It saves outputs to `cdk.out/deployment-outputs.json`. It does not
upgrade account/support plans, accept model terms, or request quotas.

The current account is on the Paid Plan with Basic Support, root MFA, a USD 25 monthly
cost alert and both regions bootstrapped. Paid Plan usage can incur charges beyond
credits; budget alerts do not stop spending. GuardDuty access and Anthropic agreements
are active. At the earlier setup cutoff deployment was blocked: regional Lambda quotas were 10 (minimum 220
Ohio / 110 Oregon), and Sonnet 5.5 inference is denied with an applied token quota of
zero. Two Lambda quota requests and one Bedrock allowlisting Support case are open.
AWS rejected low-volume quota requests against its higher published defaults; the
Bedrock case explicitly requests low-volume activation without paid Support. Preserve
the ignored local receipts and recheck actual quotas/inference after AWS responds.
The gates have not been bypassed and no RuralShield workload stacks are deployed.

## Evidence required for the paper

At the end of hour 120, the planned closeout stops synthetic load and experimental
invocations, records pending executions, and inventories running resources and
schedules. No automatic shutdown is implemented. Check weekly report/restore jobs
with separately labeled controlled on-demand tests if their schedule falls outside
the five-day window. Retained/locked storage and ongoing services may still bill;
record setup and post-run charges separately from the measured five-day total.

* E1: baseline/treatment nag reports, suppression reasons, live Security Hub and
  Config results after convergence. Static rules are not a HIPAA determination.
* E2: commit, lockfile, edited config, region, exact tools, deployment start/end
  timestamps and failed attempts. Resource counts exclude bootstrap resources
  unless explicitly stated otherwise.
* E3/E4: model/profile and prompt versions, deduplicated finding inputs, Step
  Functions histories, triage/approval/containment timestamps, fallback flags,
  actual action results and rollback verification. Sample findings demonstrate
  pipeline behavior; they do not establish real threat detection effectiveness.
* E5: actual billing exports, five-day test duration and achieved load. Keep modeled estimates and
  measured spending separate, and account for retained resources after tests.
* E6: practitioner-study results require actual participants and applicable
  institutional review; local developer testing does not establish usability.

The current outline's CRITICAL-only unattended-action claim needs qualification:
`BLOCK_S3_PUBLIC_ACCESS` is eligible at HIGH severity, and deterministic fallback
can permit AUTO when Bedrock is unavailable. Primary and DR audit archives now use
six-year Object Lock. CloudWatch logs retain their configured duration and are not
universally exported to S3. Container Cognito authentication and sample patient-level
authorization remain follow-up work. Do not report these as implemented or
validated controls. A zero observed false-AUTO count is an empirical result for
the tested dataset, not a proof that false automatic actions are impossible.

## GPT OSS migration update — 25 October 2026

Research and example configurations now select `openai.gpt-oss-20b-1:0` directly in Ohio. The Anthropic profile/backing ARN list was removed; IAM remains scoped to the selected foundation model. Both Sentinel callers retain Converse and existing generation settings. Automatic containment remains disabled in the local research configuration.

AWS access metadata reports availability and authorization, but the synthetic connectivity and exact forced `record_triage` schema probes both failed with `ThrottlingException` (too many tokens per day). Successful inference, tool compatibility and Guardrail integration remain pending. No Guardrail resource was created for these probes, and no workload was deployed. Lambda capacity was rechecked at 1,000 in both Ohio and Oregon; the earlier 10-concurrency values are historical. The five-day (120-hour) run begins only after deployment and readiness checks.

Local raw receipts are ignored: `cdk.out/aws-setup/model-smoke-gpt-oss-20b.json`, `gpt-oss-tool-request.json`, and `gpt-oss-tool-result.txt`. Failed CLI durations are not inference latency. Existing Sonnet Support correspondence and probes describe the former candidate and must not be interpreted as GPT OSS access approval.

The 25 October quota query also returned zero applied on-demand GPT OSS 20B tokens per minute (`L-036E14D8`) and requests per minute (`L-AF7F0545`) in Ohio. The AWS preflight now gates both quotas. These minute-level quota observations and the daily-token runtime error are separate observations; no daily-limit value was established.

## Non-AI deployment condition — 25 October 2026

While Bedrock access is blocked, a separately identified condition sets only `security.aiTriage.enabled: false` in the ignored `cdk.out/aws-setup/nonai-research.yaml`, copied from the operator configuration. The primary GPT OSS configuration remains intact. This omits the entire Sentinel stack, including model calls, triage/fallback, incidents, approvals, containment and weekly reporting. It does not test the forced-fallback Sentinel condition. Foundation, workload and DR controls remain enabled, including MFA, encryption, logging, backups and security subscriptions.

The synthesized deployment assembly contains 211 resources across three stacks (103 Foundation, 80 Workload, 28 DR), including CDK metadata. This differs from the earlier four-stack offline assembly and must not be substituted into its results. Account preflight passed for this condition; its artifact is `cdk.out/nonai-preflight/aws-preflight.json`. Model-specific gates are inapplicable only because the corresponding stack is absent; they remain required for the AI configuration.

Live smoke checks use `scripts/test-nonai-deployment.py --outputs cdk.out/nonai-outputs.json`. They check stack completion, rejection of an unauthenticated API request, and a bounded synthetic health/create/read round trip through direct Lambda invocation and DynamoDB. The synthetic claims in a direct invocation are not a Cognito login test. No patient data is used. Raw results will be stored under `cdk.out/nonai-tests/`. Successful deployment and smoke results must be recorded after completion; do not infer them from synthesis or preflight.

Deployment command after reviewed diff and passing non-AI preflight:

```powershell
npx cdk deploy --app cdk.out/nonai-preflight --all --profile ruralshield-research --outputs-file cdk.out/nonai-outputs.json
python scripts/test-nonai-deployment.py --outputs cdk.out/nonai-outputs.json
```

The planned full-model five-day experiment remains pending Bedrock access and readiness. Any non-AI observation must have its own start/end timestamps and configuration hash; provisioning and this bounded smoke test are setup evidence. Existing retention and deletion protection still apply, and the $25 monthly alert is not a spending cap.

### Non-AI deployment attempt (25 October 2026)

To test deployability while Bedrock quotas remain zero, the operator authorized a separate condition with `security.aiTriage.enabled: false`. This omits the entire Sentinel stack, including fallback triage, approval, containment and weekly reporting. It is not a completed model-assisted or forced-fallback experiment. The selected GPT OSS configuration remains unchanged for a future AI condition.

The non-AI account preflight passed. Its initial assembly contained 211 resources including CDK metadata across Foundation (103), Workload (80), and DR (28). AWS accepted the DR stack in Oregon (`CREATE_COMPLETE`). Foundation failed at `AWS::Config::ConfigurationRecorder` stabilization and rolled back; Workload did not deploy. Control-plane errors included `NoAvailableDeliveryChannelException`. The original template ordered delivery-channel creation after recorder stabilization. The implementation was corrected to create the recorder stopped and issue `StartConfigurationRecorder` only after channel creation, with permission scoped to that recorder ARN. A regression assertion checks the stopped-on-create setting and dependency order. TypeScript compilation and all 30 Jest tests passed; corrected non-AI synthesis reported zero unsuppressed errors and one provider warning. The revised assembly has 213 resources (105 Foundation, 80 Workload, 28 DR), including metadata. These static results do not establish that the corrected startup succeeds on AWS.

Five Foundation resources were retained by rollback: the encryption key, two log buckets and two log groups. A resource-import template and mapping were prepared to preserve these resources and restore their CloudFormation management. Automatic approval review required explicit operator approval before deleting the failed stack record and executing this recovery; those mutations were not executed at this cutoff. No workload endpoint, synthetic patient round trip, Cognito login, backup restore, or end-to-end Sentinel test succeeded or ran in this attempt. The bounded smoke script is prepared but has not been executed against a deployed workload. The planned five-day (120-hour) observation has not started. The completed DR resources and retained logging resources remain present and may accrue charges separately from any future measured experiment.


## Retained-resource recovery and workload retry

The operator explicitly approved both retained-resource recoveries. The five-resource Foundation import completed, the corrected Foundation update completed, and AWS Config reports active recording with last status SUCCESS. The original KMS key ID remains unchanged. The generated delivery log-group name is pinned through the ignored `cdk.context.json` `retainedLogGroupNames` mapping to avoid replacement after import; preserve this recovery context for future synthesis.

The first Workload attempt failed because the explicitly supplied Lambda execution role lacked EC2 network-interface permissions. The implementation now grants the Lambda VPC setup operations and write access to the precreated application log group. The policy document remains customer-managed, and Lambda depends on its attachment. Compilation and all 31 Jest tests pass, including the new regression assertions. A fresh corrected assembly is in `cdk.out/nonai-final`.

The nine-resource Workload import completed after explicit approval. The retry diff preserves all imported data, identity, backup and logging resources; Foundation and DR have no differences. The final retry and live smoke results must be read from `cdk.out/aws-setup/nonai-deploy-final.txt` and `cdk.out/nonai-tests/results.json` after completion. Earlier failure statements describe prior attempts, not the current recovery state. No five-day measurement has started merely because infrastructure was provisioned.

### Completed non-AI deployment and bounded AWS checks (25 October 2026)

Foundation, Workload and DR deployed successfully in the separately identified non-AI condition. Its configuration sets `security.aiTriage.enabled: false`; the entire Sentinel stack, including deterministic fallback, approvals, containment and weekly reporting, is absent. The primary GPT OSS configuration remains unchanged for future AI testing. This condition is neither the conventional comparison baseline nor a completed model-assisted evaluation.

Two failed provisioning attempts preceded success. Foundation initially failed Config recorder stabilization because channel creation waited for recorder completion. The implementation now creates the recorder stopped and starts it through a recorder-scoped SDK call after the delivery channel exists. Workload subsequently failed because its supplied Lambda role lacked network-interface permissions. Explicit VPC setup permissions and application-log write access were added, retaining the Lambda dependency on policy attachment. After operator-approved imports, five retained Foundation resources and nine retained Workload resources returned to CloudFormation management, preserving their data, identity settings and original encryption key. The generated Foundation delivery log-group name is pinned through a local recovery-context mapping to prevent replacement. These failures and imports are setup evidence and must remain in any later deployment-effort accounting.

The corrected non-AI assembly contains 213 resources, including CDK metadata (105 Foundation, 80 Workload, 28 DR), with zero unsuppressed synthesis errors and one provider warning. Compilation and all 31 Jest tests passed after the fixes. This assembly differs from the original four-stack offline artifact; its counts do not replace the historical local result.

At `2026-10-25T17:47:19.306418+00:00`, the bounded live script recorded 17/17 passing checks. This total includes three stack-state checks and separate observations of a single synthetic record round trip; it is not 17 independent experiments. GET `/health` without a token returned 401. Direct Lambda health/create/read calls returned 200/201/200, and the read matched the synthetic record. The direct calls supplied synthetic claims and therefore did not test authenticated Cognito login. Read-only checks observed required Cognito MFA, DynamoDB KMS encryption and PITR, S3 public-access blocking and 35-day GOVERNANCE retention, active Config recording, and CloudTrail logging. One delivered log object was observed with KMS encryption and COMPLIANCE retention in the audit archive; this does not establish archival completeness or recovery reliability. The archive's six-year policy is distinct from the PHI bucket's 35-day governance policy.

Raw evidence is saved in `cdk.out/nonai-tests/results.json`, deployment outputs in `cdk.out/nonai-outputs.json`, and attempt/import receipts under `cdk.out/aws-setup/`. The non-AI configuration SHA-256 is `d193e61be501c2bd4feaf8c801f2acb2d81b6c5a8e2d925d605be77f0a5d053d`; the result also records the deployed Lambda code hash. Synthetic data only was used. Email alert subscription confirmation remains pending, so notification delivery is not established. Bedrock inference, Guardrails, Sentinel, actual Cognito login, containment, load, backup restore, comparative outcomes and the five-day (120-hour) observation remain unmeasured. The deployment remains running; no automatic shutdown is implemented.

### Non-AI readiness and observation protocol update (25 October 2026)

Subsequent readiness tests completed real Cognito SRP/TOTP authentication and authenticated HTTPS health/create/read with matching synthetic data. The temporary readiness identity was deleted. The Ohio alert subscription was confirmed, a synthetic notification published, and its receipt confirmed by the operator. An AWS Backup job and restore job completed; the restored record matched the source, and the sample handler accepted it when run against the disposable restored table using the deployment identity. That table was deleted after validation. This does not establish application-role failover, a clinical recovery-time objective, or general backup reliability.

The first S3 probe failed. The source replication role lacked Object Lock metadata reads, and destination Bucket Key replication needed Decrypt. Scoped grants were added, 32 Jest tests passed, and the corrected Workload/DR policies deployed. A new synthetic probe was observed in Oregon with REPLICA status and matching SHA-256. Preserve the failed object and test attempts as setup evidence; this is one functional replication check, not a measured replication SLA.

A separate 12-resource AWS instrumentation stack implements the prospective non-AI pilot in `docs/NONAI_PILOT.md`. It targets one million authenticated synthetic requests within a frozen 120-hour window, with four concurrent clients and per-minute records. Five local worker tests passed, and a live pre-arm invocation returned not-armed while the schedule was disabled. Credentials for a dedicated synthetic SRP/TOTP identity are encrypted in Secrets Manager. The worker's absolute issuing deadline and early-stop rules do not require the desktop to remain open. Start/end timestamps and achieved counts come from the frozen manifest and actual records; no five-day result is inferred from readiness. Estimated account-day billing lacks exact 120-hour attribution. This is a single non-AI condition; no comparative or Sentinel result is claimed.


### Active pilot snapshot (25 October 2026, 18:33:54 UTC)

Latest status (25 October 2026, 18:33:54 UTC): non-AI readiness passed and the frozen pilot is active from 25 October 18:29 UTC to 30 October 18:29 UTC (1:29 PM Chicago on both dates). The first four minute records contain 555 attempts, 554 successes and one HTTP 404, with no missing fully elapsed slots at this snapshot. These are preliminary counts, not five-day results. Build, 32 Jest tests and five observation-worker tests pass; the earlier 17 bounded checks remain separately recorded. Bedrock/Sentinel and completed five-day outcomes remain pending. The modeled five-day gross planning range is USD 30-60 before credits and tax, excluding setup and post-run retained-resource charges; see `docs/COST_MODEL.md` (repository root). This is not a measured cost result. The USD 25 monthly alert is not a cap. The AWS load schedule stops independently of the desktop; a six-hour Codex follow-up checks progress and closeout when available. No restart, compensating traffic or protocol change is authorized during this frozen window.


### Scheduled evidence-preserving service shutdown (25 October 2026)

The operator authorized stopping billable research services after the five-day test while retaining paper evidence. A separate `RuralShield-NonAiCloseout` AWS stack is deployed. Traffic ends on 30 October at 18:29 UTC (1:29 PM Chicago); evidence-first closeout starts at 18:34 UTC (1:34 PM Chicago), retries for up to 24 hours and runs independently of the desktop or CLI login. It preserves encrypted evidence, original logs, synthetic data, backup recovery points and KMS keys. The final archive must pass checksum verification before scoped service removal. Existing storage, PITR, locked backups and keys remain billable. Shutdown is scheduled, not yet completed; require `closeout/completed.json` with successful checks before claiming success. See `docs/NONAI_CLOSEOUT.md` at the repository root. This changes post-run handling only; the frozen measurement deadline and target remain unchanged.


### Local evidence retention update (25 October 2026)

The operator authorized a local copy to reduce post-test AWS storage costs. A verified checkpoint was created at `research-evidence/checkpoint-20261025T192446Z`: 963 S3 object versions, 16 owned log groups with 176,679 events, and 1,015 payload files; ZIP size 23,795,882 bytes. This is partial evidence from the running pilot, not a completed five-day result. A final copy is gated on verified native closeout and at least 24 hours after both the window end and closeout timestamp. After independent file/ZIP/hash checks and a preview, the authorized local retirement can remove freshly rechecked CloudWatch copies, the unchanged synthetic table/PITR and exact archived unlocked duplicate versions. Locked originals, all keys/rotation and recovery points remain. Eight local archive safety/reporting tests and the eight native closeout safety tests pass; the updated native archive diagnostic again verified 73 records without stopping services. No cloud data deletion has run. See `docs/LOCAL_EVIDENCE.md` at the repository root; final archival, retirement and retention-cost savings remain pending.
