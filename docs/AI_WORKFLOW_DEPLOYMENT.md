> Historical research documentation. Dated entries describe the original study, not the state of a new deployment. Account identifiers and operator email addresses in this public snapshot are examples. Private evidence and account configuration are not distributed. See [public release notes](PUBLIC_RELEASE.md).

# Separate AWS AI workflow: deployment readiness

## Verified pre-implementation checkpoint on 31 October 2026

The operator requested deploying and testing the external AI workflow in AWS,
with AI measurements separate from the completed non-AI pilot. AWS CLI identity
was verified as ruralshield-deployer in the intended research account. A fresh
read of native closeout records passed all 24 checks and found the native archive
gate. No final local archive directory or local-retirement receipt exists yet.
The current readiness record is private:
research-evidence/ai-experiments/20261031T0625Z-workflow-readiness.json.

The existing final archive command was attempted and correctly refused the early
capture. No archive or resource mutation resulted. The completion object was
written 30 October at 18:40 UTC; the final evidence hold ends **31 October 2026 at
18:40 UTC (1:40 PM Chicago)**. This is the earliest eligible capture time, not a
promise of deployment at that time. Actual archival and independent verification
must succeed first. See [LOCAL_EVIDENCE.md](LOCAL_EVIDENCE.md).

No AI stack, cloud API-key secret, event trigger, approval endpoint or containment
permission has been deployed. The four successful desktop cases remain the only
successful live OpenAI results. This readiness work sent no new model requests.

## What the prepared stack actually tests

The standalone entry point scripts/external-ai-stack.ts provisions a disabled,
manually invoked Lambda with a fixed synthetic case selector. Its only runtime
permissions are reading one exact API-key secret and writing its own log streams.
It reuses the pure prompt/schema and decision policy and cannot collect findings,
send alerts, request approvals or execute containment. Packaging and offline
synthesis do not change AWS. A successful future Lambda invocation would establish
AWS-to-provider transport and policy simulation, not the full Sentinel workflow.

The complete Sentinel construct is lib/constructs/ai-sentinel.ts. Its deployed
handler path in src/lambda/triage/handler.py and its report handler still use
Bedrock. The optional external adapter is not wired into those handlers. Simply
enabling the manual Lambda or setting a different model ID cannot supply the
missing integration. The production-style construct also includes account-wide
finding rules, broader containment permissions, a public approval API and recurring
reports; deploying it unchanged would not be an isolated synthetic experiment.

## Required order for the AWS experiment

1. After the hold, run the existing final evidence capture. Independently verify
   the unpacked files, ZIP, frozen source and final cloud manifest. Preserve the
   private archive outside build output. Then run the authorized duplicate
   retirement preview, inspect changed/new-data skips, and execute only the
   guarded eligible retirement under LOCAL_EVIDENCE.md. New data must be retained
   and captured again. Never delete locked originals, keys, vaults or recovery
   points, or redeploy the closed pilot stacks.
2. Use the separate full-workflow entry point and cloud test configuration
   described below; its wiring is prepared and tested offline, not deployed.
   Reuse the existing pure policy and approval/containment behavior while wiring
   the direct OpenAI adapter explicitly. Use fixed synthetic inputs on a dedicated
   event bus or manual execution; do not subscribe to live account-wide findings
   or send real PHI/non-AI records to the provider. Preserve unknown/failure
   outcomes rather than reporting fallback as model success.
3. Create separate incidents, logs, workflow and notification resources, with a
   separate signing secret. Scope any actual action to an explicitly created,
   disposable test target; the deployment identity, retained paper evidence and
   old workload must be unreachable by its action permissions. Keep automatic
   containment disabled. A scripted control-path test must be labeled scripted;
   do not force a model result and call it observed AI routing.
4. Review the exact synthesized resource/IAM diff, secure API-key destination,
   model request bounds, cloud charges and cleanup plan before provisioning.
   Transfer the existing key only through a secure SDK path into the agreed exact
   secret; never place it in CDK context, command arguments, templates or Lambda
   environment plaintext. Use only the named separate stack, never deploy --all.
5. Verify the notification subscription. For each bounded synthetic execution,
   retain event delivery, execution history, model request/output/usage, incident
   writes and SNS acceptance separately from user-confirmed delivery. Test notify,
   approved, denied, replayed/expired approval and model-error paths. A live
   approval requires the operator's actual decision; a waiting execution is not
   a completed approval or successful containment test.
6. For a permitted disposable action, record prior state, actual change and an
   independently verified rollback. Otherwise report containment as simulated or
   untested. Test narration from invented counts separately; a manually invoked
   report is not evidence of a week-long scheduled report. Stop after the bounded
   cases, export/verify evidence, disable new triggers and remove only the new
   disposable services under their own cleanup plan.

## Claims and cost separation

Keep the frozen non-AI condition, its source archive, counts, missing minute,
native shutdown receipts and billing attribution unchanged. The current paper's
E7 results are four desktop compatibility samples, not AWS integration results.
The AWS phase needs separate source/configuration hashes, timestamps, provider
and returned model, client versus Lambda timings, action/approval outcomes and
limitations. Repeated samples and independent quality review remain uncollected.

Known token value from the four desktop successes is USD 0.001368675; the earlier
HTTP 429 cost remains unknown. Any new model calls must remain within the agreed
USD 0.05 estimate budget with missing usage causing a stop. This estimate guard
does not cap provider spending. AWS secret storage, logs, state transitions,
notifications and any approval API/WAF are additional and must not be attributed
to the frozen non-AI pilot or folded into the desktop token estimate. Do not claim
cash billing, Pro-credit redemption, end-to-end success or shutdown before their
actual evidence is collected.

See [EXTERNAL_AI_EXPERIMENT.md](EXTERNAL_AI_EXPERIMENT.md) for current fixtures,
results and provider limitations and [NONAI_CLOSEOUT.md](NONAI_CLOSEOUT.md) for
the verified native service shutdown scope.

## Full synthetic workflow implemented offline (31 October 2026)

The separate entry point is scripts/ai-workflow-stack.ts, stack
RuralShield-ExternalAiWorkflow. It is not imported by the application or the older
manual transport stack. Its runtime is src/external_ai_workflow/. It reuses the
existing adapter, pure prompt/policy and exact quarantine_lambda implementation;
the existing Bedrock handlers, pilot worker and default app remain unchanged.

The implemented path is a dedicated synthetic EventBridge bus and rule, Standard
Step Functions workflow, external model assessment, policy routing, incident
storage, SNS notification, human approval, one scoped disposable action, and a
separate rollback task. Narration uses invented counts and the same incident/SNS
evidence path. There is no live Security Hub/GuardDuty subscription, enrichment or
write-back, posture scanner, recurring report, workload deployment, new KMS key,
VPC, backup plan or account-wide API Gateway logging-role change.

The disabled offline synthesis has 52 resources, including seven Lambdas (six
workflow handlers and a no-dependency dummy target). The incident table, signing
secret, logs and delivery-failure queue are retained for later verified export.
The API key is not provisioned or copied by packaging/synthesis. The supplied
same-account/region API secret must use the standard AWS-managed Secrets Manager
key; customer-managed secret-key support is not implemented in this stack.

### Inputs and truthful result labels

Every execution accepts only suite_id and a fixed case_id. The fixed suite is
ruralshield-external-workflow-20261031. Each case is conditionally claimed once;
duplicate deliveries/executions cannot make another model call or repeat an action.
Starting a new suite would require an explicit source/configuration change and
new budget review, not a different event payload.

- Model cases: posture, lambda_threat, lambda_injection, weekly_narration.
  Lambda findings identify only the stack-created disposable function. These are
  new AWS-phase fixtures, not repetitions of the desktop credential fixture. An
  actual notify-only model recommendation stays notify-only. No control forces a
  model to recommend containment.
- Scripted controls: control_notify, control_approve, control_deny,
  control_timeout, control_model_failure. They make no model request. Their
  evidence_kind is scripted_control and model_valid is false. The approve/deny
  names describe the intended operator exercise; the actual human decision is
  respected. The timeout control waits ten seconds; other approvals wait fifteen
  minutes. A scripted failure is not an observed provider outage.

Unknown/invalid usage, model mismatch, failed credentials, failed inference or an
estimate above the per-call reserve cause notification only and block further
model calls. There is no automatic model retry or provider switch. A persisted
budget starts with USD 0.048631325 of known-estimate allowance after the four
desktop successes. It reserves USD 0.01 before a call, stores output before
settlement, and refunds only the known unused estimate. A failed/uncertain write
can leave INFLIGHT; invalid work sets BLOCKED. Neither resets automatically. This
is still an estimate guard, not a provider billing cap, and excludes the earlier
unknown-cost HTTP 429, tax and AWS services.

### Approval and disposable action boundaries

The approval interface is a separate Lambda Function URL, not the original
approval REST API/WAF. Its only public handler has no API-key access or containment
permission. HMAC links use a pinned signing-secret version. GET renders a
confirmation form and never consumes a decision. POST checks the signature and
atomically requires PENDING status and a future expiry. Replays/expired requests
fail. No event, bearer link or callback token is printed to logs. State-machine
logs exclude execution data; private execution history and incident/approval rows
still contain sensitive evidence and must not be published raw.

A callback failure is recorded FAILED_OR_UNCERTAIN and is not automatically
retried. Single-use decision storage and the Step Functions callback are separate
operations; this implementation does not claim transactional exactly-once callback
delivery. The Function URL has no WAF or per-user authentication: possession of
the HMAC link is authorization. It is a bounded synthetic research interface, not
a production security/compliance equivalence claim.

Automatic containment is always off. An approved incident must name exactly the
dummy Lambda, use QUARANTINE_LAMBDA_FUNCTION, match the recorded decision and
approval, have the expected suite tag and protected=false, and start at reserved
concurrency one. IAM only permits concurrency/tag reads and concurrency writes on
that exact ARN. The original playbook sets concurrency to zero, which is read
back. A separate rollback Lambda checks tags, journal and current zero state,
restores one and reads it back. Changed tags/state cause refusal. Duplicate or
uncertain action journals never trigger automatic repeat execution. A rollback
failure or a mutation followed by an interrupted write requires inspection of
that exact disposable target; it must not be reported as restored or resolved.

SNS acceptance IDs, outcome records and human-confirmed receipt are different
measures. Delivery is not inferred from publish acceptance. Model errors remain
errors, scripted branches remain scripted, and no approval/containment or cloud
latency result exists until observed in AWS.
An execution can also reach the stopped Succeed state after a duplicate or budget
refusal. Step Functions SUCCEEDED alone is therefore not a valid model-response or
completed-action count; use the recorded case, model and action outcomes.

### Offline preparation commands

    .venv/Scripts/python.exe scripts/package-ai-workflow.py
    .venv/Scripts/python.exe scripts/package-ai-workflow.py --verify
    .venv/Scripts/python.exe -m unittest discover -s test -p 'test_*.py' -q
    npm run build
    npx jest --runInBand
    npx cdk synth RuralShield-ExternalAiWorkflow --app "npx ts-node --prefer-ts-exts scripts/ai-workflow-stack.ts" --output cdk.out/ai-workflow-synth --no-lookups --context workflowApiSecretArn=arn:aws:secretsmanager:us-east-2:123456789012:secret:research/openai-EXAMPLE --context workflowAlertEmail=operator@example.invalid

The last command deliberately uses fictitious values and leaves the runtime and
rule disabled. It is not a deployment command or proof of a cloud secret/email
subscription. The packager copies exactly eight reviewed source files, rejects
foreign asset files and verifies both current-source and packaged-file hashes.
The entry point rechecks package freshness before synthesis.

Enabling with workflowEnabled=true additionally requires workflowFinalArchive
pointing to an existing final local archive. scripts/verify-ai-workflow-gate.py
independently verifies unpacked files and ZIP, account/window, the 24-hour hold at
both capture and verification time, the pinned completion receipt version/hashes,
the frozen source and all archived cloud-manifest exports. It writes nothing and
opens no AWS session. The constructor refuses enablement without that proof. A
disabled template alone is not evidence that a deployment is authorized; the
earlier operator gate still applies to provisioning either disabled or enabled.

Before later deployment, recheck native shutdown and the CLI identity, review the
actual named-stack diff, regional Lambda concurrency quota (seven reservations),
notification confirmation and secure API-key destination. Keep the API-key value
out of context and environment variables. After the bounded trial, disable the
synthetic rule and runtime, resolve any pending approvals/action journals, export
and verify the scoped table/history/logs and receipts, and then review removal of
only these new services. Existing pilot evidence and keys are outside that scope.

### Offline verification evidence

The runtime tests cover idempotency, blocked/uncertain costs, GET/POST approval,
expiry/replay, callback uncertainty, denial, exact-target/protected-tag refusal,
the reused playbook and independent rollback reads. Archive tests use a real small
ZIP to reject early/checkpoint/tampered/mismatched exports and receipt versions.
CDK tests inspect disabled inputs, task-token wiring, absent retries, exact action
resources, secret access isolation and activation/ARN validation. These are
offline/mocked checks, not live integration, robustness, usability or model-quality
results. Deployment and all cloud-phase observations remain pending.

Final local checks for this preparation passed: TypeScript build, 37 Jest tests
(three new workflow/template assertions), and 72 Python tests (34 new workflow,
archive and packaging checks, plus the existing 38 adapter/handler checks).
The separate disabled stack synthesized offline with fictitious secret/email
values. Existing CDK feature-flag notices remain. No AWS provisioning, approval,
model response or containment result is inferred from these checks.


## Completed separate AWS AI trial - 1 November 2026

This dated result supersedes the earlier preparation-only status for the full
workflow; the older manual-transport template was not deployed. The final non-AI
archive independently verified at 20:57:56 UTC before the new stack was enabled.
The reviewed 52-resource RuralShield-ExternalAiWorkflow stack deployed, with six
runtime handlers and one disposable Lambda target. The actual deployed ZIP and
six runtime code hashes matched the reviewed package. The frozen pilot, original
Bedrock handlers, protected resources and observation window were unchanged.

Four OpenAI direct Responses API requests each returned gpt-6-luna once: posture
NOTIFIED; weekly narration REPORT_SENT; Lambda threat NOTIFIED; and the hostile
Lambda fixture selected QUARANTINE_LAMBDA_FUNCTION, received an actual human
confirmation-page approve POST and ended ROLLED_BACK. Three assessments passed
schema validation; narration passed the nonempty-text contract. This is a single
sample per case, without independent quality review or robustness conclusions.

Five separate no-model controls exercised notification (operator-confirmed
email), actual human approval and denial, ten-second approval timeout and
scripted model failure. All nine specific outcomes and successful execution
statuses were checked. Exactly two action records (one scripted, one model
selected) read concurrency 1 -> 0 -> 1 on only the disposable Lambda. Denial and
timeout had no action record; the timeout's raw PENDING approval had expired.
Spent/expired link rejection was operator-reported, not an independently captured
HTTP measurement. Automatic containment stayed off. No real PHI or non-AI pilot
records were sent to OpenAI. The standalone workflow has no real finding
ingestion/enrichment, scheduled weekly report, approval WAF or per-user identity.

The AWS model cases used 4654 input and 1679 output tokens, including 4161 default
30-minute cache writes and zero reads. Independently recomputed known token
estimate: USD 0.001408925. Desktop successes remain a separate cohort at USD
0.001368675; combined known estimate USD 0.002777600. The historical HTTP 429 has
unknown usage/cost. The USD 0.05 estimate guard is not a provider-enforced cap or
an all-attempt invoice. AWS service/export charges and cash/credit reconciliation
are additional and uncollected. Do not pool desktop/provider client times with
the non-AI Ohio HTTPS latencies or human workflow durations.

After zero active executions and restored target concurrency were checked, the
new rule and six runtime handlers were disabled. The pre-removal private archive
verified 207 files and ZIP. The operator then explicitly approved removal of this
temporary trial. CloudFormation reached DELETE_COMPLETE. A separate post-removal
archive verified 226 files, including all seven retained log groups and the
unchanged 25-item table. Fresh ownership/version/content checks preceded deletion
of those seven logs, the table and an empty queue. The signing secret and cloud
API-key copy entered seven-day recoverable deletion. Eleven retained-resource
cleanup actions verified with zero skips at 21:52:59 UTC. The local API key and
provider project key remain; shared CDK bootstrap assets were retained.

The final private AI closeout archive verified 230 files and ZIP at 21:53:07 UTC:
research-evidence/ai-experiments/aws-workflow-closeout-evidence-20261101T215305368675Z.
Manifest SHA-256 84528a334ebded70db1af9afd509dc5b9dff3c08c0bf875d7f67c676d6d01528;
ZIP SHA-256 d42c4210e62bd8469871de59cb27a147c107178e9134fae6bb573f3b83a6901e.
These private archives contain signed links/task tokens and must not be published
or committed. ZIP and payload share one disk, not independent backup media.
Runtime teardown is verified; no zero-bill or exact attributed AWS-cost claim follows.


### Independent action cross-check - 1 November 2026, 22:06 UTC

A read-only CloudTrail management-history query matched four
PutFunctionConcurrency20171031 events from the exact trial containment/rollback
roles on the exact disposable target: two requests for zero and two for one,
with no recorded API errors. This supplements the archived action readbacks and
final target read, without establishing clinical recovery or complete audit
coverage. The initial lookup used the unversioned API name and matched zero;
the corrected event-source lookup retained exact role/target filters. Both query
receipts are preserved privately. No Lambda invocation or provider call occurred.
The trial remains removed and the local/provider API key remains available.
