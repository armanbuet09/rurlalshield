> Historical research documentation. Dated entries describe the original study, not the state of a new deployment. Account identifiers and operator email addresses in this public snapshot are examples. Private evidence and account configuration are not distributed. See [public release notes](PUBLIC_RELEASE.md).

# Evaluation Plan (prospective protocol)

Updated 24 October 2026 (America/Chicago). The manuscript protocol and uncollected
result placeholders are in the private manuscript (not distributed here).
The evidence ledger is the private claim-evidence ledger (not distributed here).
This document describes planned collection, not experiments already run.
The active AWS run is **five days (120 hours)** after deployment and initial
readiness checks. Preparation/activation time and post-run retained-resource costs
are recorded separately. The non-AI worker stops issuing traffic at its absolute
deadline and disables the load schedule; infrastructure remains billable.

## Completed evidence and current boundary

The recorded local checks pass: TypeScript build, 29 Jest tests, 20 Python
normalization/policy tests, and seven mocked handler tests. Offline synthesis of
the example produces 282 resources and 38 Config rules, with zero unsuppressed
errors and one provider X-Ray warning after documented exceptions. See
[STATUS.md](STATUS.md) for versions and scope. These checks do not measure
deployment success, comparative control coverage, model quality, or operation.

Recorded AWS setup includes bootstrap in two regions and failed model-connectivity
probes. At the evidence cutoff, quotas/access still block RuralShield deployment.
All six E1â€“E6 result cells remain pending; no measured cost, latency, false-AUTO
rate, restore outcome, or practitioner score is available.

## Common protocol

Use the same synthetic sample workload, authentication requirement, data shape,
and inputs for a conventional CDK baseline and RuralShield treatment. The baseline
and full collection/analysis harness remain to be implemented. Freeze their
settings before collection; do not manufacture a weaker baseline after seeing
treatment results.

The initial treatment is Lambda + DynamoDB + PHI S3 + Sentinel + same-account DR
in us-east-2/us-west-2, with no Aurora/container variant and automatic containment
off for initial validation. Name separate model-backed, fallback, and simulated
automatic-policy conditions. Record code/archive and config hashes, dependencies,
templates, regions, prompt/schema/guardrail/model versions, timing boundaries,
observation windows, workloads, failures, and analysis revisions. Targets below
are provisional study sizes, not achieved observations or power calculations.
Load, latency, quality, and functional trials must fit within the five-day window;
report actual counts and incomplete targets rather than silently extending it.

## Experiments

### E1 â€” Selected configuration coverage (RQ1)

Run the same pinned static rule packs on both conditions. Enumerate compliant,
non-compliant, suppressed-with-reason, not-applicable, and unevaluated cases;
suppressed cases are not passes. Separate unique rules from ruleâ€“resource counts.
Record live Config/Security Hub observations at a planned 24-hour checkpoint and
document convergence rather than hiding pending/insufficient data. Define common
applicable denominators and list treatment-only resources/checks separately.
Review healthcare mappings independently of automated checks. This is diligence
evidence, not a HIPAA determination. Historical remediation counts are not E1 data.

**Result: [PENDING E1: counts, denominators, exceptions, deployed-state observations].**

### E2 â€” Deployment effort and reliability (RQ2)

Target five independent runs per condition where feasible. Define equivalent
starting states; retained resources and Object/Vault Lock mean teardown cannot
be assumed to reset an account. Separate activation/quota waiting, bootstrap,
synthesis, deployment, and functional acceptance. Record active operator time,
automatic time, edits, interventions, failed attempts, and retries. Updates are
not fresh deployments. Line/resource counts are proxies, not measured expertise.

**Result: [PENDING E2: attempted/completed runs, time, edits, interventions].**

### E3 â€” Pipeline latency and functional behavior (RQ3)

Target at least 100 unique scenario executions. Register expected event routes;
distinguish provider samples, replay, and any separately approved isolated attack
simulation. Direct workflow calls bypass EventBridge and belong in a separate
condition. Preserve original finding age, submission time, duplicate executions,
retries, and timeouts. Report completion/failure counts and median/p95 with actual n.

Measure workflow arrival, assessment, persistence, SNS publication, inbox arrival,
approval waiting, containment, and rollback separately. Existing
`triage_latency_ms` stops before persistence/notification; additional instrumentation
is required for model-only and end-to-end timing. SNS publication is not email
delivery, and failed CLI probe duration is not inference latency. Retain incomplete
executions as timeout/censored outcomes at a declared observation window.

Plan functional checks of approval/denial/expiry/replay, callback failure, pending
links across rotation, protected targets, partial action failure, rollback,
archival failure/redrive, scan-tag read restrictions, and backup restore. Use
disposable targets with prior-state capture. Validate restored data and application
behavior before making recovery/RTO claims. Mocked tests are not live trial passes.
The five-day window may miss weekly report/restore jobs and scheduled rotation.
Label controlled on-demand exercises separately from naturally scheduled jobs;
an unobserved scheduled execution remains untested.

**Result: [PENDING E3: delivery/completion, timing, functional and restore outcomes].**

### E4 â€” Triage quality and action safety (RQ4)

Target at least 200 scenarios, including non-threat, benign, ambiguous, protected,
and incompatible-target cases. Track exact duplicates and related variants by
scenario/hash rather than collapsing every finding type or assuming independent
production incidents. Freeze a labeling rubric after a separate pilot. Two raters
independently label acceptable action sets and unattended-action appropriateness,
without seeing model recommendations. Preserve disagreement and adjudication.
Report class counts, raw agreement, suitable nominal Cohen's kappa, model/action
agreement, fallback, invalid output, unsupported claims, and readability. Specify
confidence's joint target and treatment of unknown labels; eighth-grade output
is a prompt target, not a measured result or a clinical outcome.

Report inappropriate AUTO decisions / all AUTO decisions with counts and uncertainty.
Keep decisions and actual executions separate. No AUTO observations means an
undefined fraction, not zero. Zero errors in finite tests do not establish safety.

Target 50 clean/injected scenario pairs; record model and policy changes, guardrail
interventions, fallback, and unsupported targets. Fallback after blocking may still
permit AUTO when enabled. Planned model/fallback, guardrail, and rule-agreement
ablations use no live containment side effects for less restrictive variants.
The variants and analysis harness are planned work.

**Result: [PENDING E4: corpus/labels, agreement, safety counts, injection, ablations].**

### E5 â€” Cost (RQ5)

Target **five days (120 hours)** and one million synthetic authenticated requests
in total if feasible. The request target is unchanged; report actual achieved load.
Record actual duration/load, storage, findings, model tokens, and retries. Export
charges by service and available activated tags, including shared/untagged charges,
bootstrap, DR, and retained resources. Separate gross service charges from credits
and refunds. Refresh `COST_MODEL.md` before using any estimate; do not substitute
estimates for measured data. Label short-window monthly projections as modeled.
Budget alerts do not cap spending or establish affordability. Report the observed
five-day total as the primary result. Any monthly projection must be labeled
modeled and specify whether it assumes the observed request rate or a different
monthly workload. Record setup and post-run charges separately. At hour 120, the
planned closeout stops synthetic load and experimental invocations, then inventories
ongoing resources/schedules; no automatic shutdown is implemented.

**Result: [PENDING E5: five-day duration/load, gross charges, credits, setup/post-run retained cost].**

### E6 â€” Practitioner usability (RQ6)

Target five to eight rural/critical-access IT practitioners after recruitment,
consent, and applicable institutional review. Tasks cover deployment, explanation
interpretation, simulated approval, and report reading. Record completion/time,
errors, assistance, AWS experience, and feedback; distinguish author pilot tests.
Administer the ten-item SUS after use and follow original scoring. Its 0â€“100
composite is not a success percentage. No recruitment/test data are recorded.
Remove practitioner-validation claims if the study is not completed. Instrument
references and verification are recorded in the manuscript bibliography/ledger.

**Result: [PENDING E6: actual participants, task results, assistance, SUS, feedback].**

## Validity and release

Limit conclusions to the tested cloud, workload, versions, input distribution,
and observed duration. Account setup, retries, dependent scenarios, limited labels,
and small participant samples constrain inference. No clinical/staffing benefit
follows from a clean static gate or developer testing.
Five days cannot establish monthly cost stability, long-term reliability, or full
coverage of weekly/monthly schedules and retention behavior.

Freeze analysis/exclusion rules before test collection and log deviations.
Release anonymized code/config snapshots, raw local outputs, baseline, suppression
ledger, corpus/labels, histories, analysis, and billing assumptions where permitted.
Remove account IDs, contacts, bearer links, task tokens, credentials, and identifying
participant data. Preserve missing data as pending or explicitly unmeasurable,
never as fabricated estimates or successful zero-valued results.

## GPT OSS migration update — 25 October 2026

Research and example configurations now select `openai.gpt-oss-20b-1:0` directly in Ohio. The Anthropic profile/backing ARN list was removed; IAM remains scoped to the selected foundation model. Both Sentinel callers retain Converse and existing generation settings. Automatic containment remains disabled in the local research configuration.

AWS access metadata reports availability and authorization, but the synthetic connectivity and exact forced `record_triage` schema probes both failed with `ThrottlingException` (too many tokens per day). Successful inference, tool compatibility and Guardrail integration remain pending. No Guardrail resource was created for these probes, and no workload was deployed. Lambda capacity was rechecked at 1,000 in both Ohio and Oregon; the earlier 10-concurrency values are historical. The five-day (120-hour) run begins only after deployment and readiness checks.

Local raw receipts are ignored: `cdk.out/aws-setup/model-smoke-gpt-oss-20b.json`, `gpt-oss-tool-request.json`, and `gpt-oss-tool-result.txt`. Failed CLI durations are not inference latency. Existing Sonnet Support correspondence and probes describe the former candidate and must not be interpreted as GPT OSS access approval.

The 25 October quota query also returned zero applied on-demand GPT OSS 20B tokens per minute (`L-036E14D8`) and requests per minute (`L-AF7F0545`) in Ohio. The AWS preflight now gates both quotas. These minute-level quota observations and the daily-token runtime error are separate observations; no daily-limit value was established.

### Non-AI deployment attempt (25 October 2026)

To test deployability while Bedrock quotas remain zero, the operator authorized a separate condition with `security.aiTriage.enabled: false`. This omits the entire Sentinel stack, including fallback triage, approval, containment and weekly reporting. It is not a completed model-assisted or forced-fallback experiment. The selected GPT OSS configuration remains unchanged for a future AI condition.

The non-AI account preflight passed. Its initial assembly contained 211 resources including CDK metadata across Foundation (103), Workload (80), and DR (28). AWS accepted the DR stack in Oregon (`CREATE_COMPLETE`). Foundation failed at `AWS::Config::ConfigurationRecorder` stabilization and rolled back; Workload did not deploy. Control-plane errors included `NoAvailableDeliveryChannelException`. The original template ordered delivery-channel creation after recorder stabilization. The implementation was corrected to create the recorder stopped and issue `StartConfigurationRecorder` only after channel creation, with permission scoped to that recorder ARN. A regression assertion checks the stopped-on-create setting and dependency order. TypeScript compilation and all 30 Jest tests passed; corrected non-AI synthesis reported zero unsuppressed errors and one provider warning. The revised assembly has 213 resources (105 Foundation, 80 Workload, 28 DR), including metadata. These static results do not establish that the corrected startup succeeds on AWS.

Five Foundation resources were retained by rollback: the encryption key, two log buckets and two log groups. A resource-import template and mapping were prepared to preserve these resources and restore their CloudFormation management. Automatic approval review required explicit operator approval before deleting the failed stack record and executing this recovery; those mutations were not executed at this cutoff. No workload endpoint, synthetic patient round trip, Cognito login, backup restore, or end-to-end Sentinel test succeeded or ran in this attempt. The bounded smoke script is prepared but has not been executed against a deployed workload. The planned five-day (120-hour) observation has not started. The completed DR resources and retained logging resources remain present and may accrue charges separately from any future measured experiment.

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
