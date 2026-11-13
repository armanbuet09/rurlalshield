> Historical research documentation. Dated entries describe the original study, not the state of a new deployment. Account identifiers and operator email addresses in this public snapshot are examples. Private evidence and account configuration are not distributed. See [public release notes](PUBLIC_RELEASE.md).

# Separate external AI experiment (E7)

For the AWS deployment gate and the distinction between the prepared manual
transport stack and the new offline-prepared external-provider workflow, see
[AI_WORKFLOW_DEPLOYMENT.md](AI_WORKFLOW_DEPLOYMENT.md). No AWS AI deployment or
end-to-end result has been collected.

This experiment uses the OpenAI Responses API directly. It does not use Bedrock,
Mantle, the Codex chat session, or ChatGPT subscription credentials. The candidate
model is `gpt-6-luna`. All four fixed synthetic cases returned valid responses
through the local runner on 31 October 2026. This establishes API/output-contract
compatibility, not model quality or deployed Sentinel operation. The earlier HTTP
429 is retained with unknown subtype/usage/cost. The saved local project key works;
the credit grant and cash settlement remain independently unverified.

## Isolation and activation

The frozen non-AI test remains 25 October 2026 18:29 UTC through 30 October 2026
18:29 UTC. Do not edit/redeploy its app, observer, schedules or model settings.
The new source lives in `src/external_ai/`; it imports only the existing pure
policy/prompt modules. It never invokes the side-effecting Sentinel handlers.
`scripts/external-ai-stack.ts` is a different CDK entry point, not imported by the
default app. Preparation, packaging and synthesis make no AWS deployment changes.

The optional Lambda is disabled by default, has no triggers or public endpoint,
and accepts exactly one canonical case ID. Its role can read one exact secret and
write its own logs; it has no finding collection, notification or containment
permissions. A separately supplied exact KMS ARN permits only Secrets Manager
decrypt if a customer key is used. No new KMS key is created. The API key belongs
in a dedicated Secrets Manager secret as a raw string, never CDK context, source,
CLI arguments or Lambda plaintext environment variables. Local testing reads the
securely confirmed ignored `.env.local`, without sourcing it as shell code.

Do not deploy or enable the optional stack until native closeout and the final
local archive are independently verified under `NONAI_CLOSEOUT.md` and
`LOCAL_EVIDENCE.md`. Then review its diff and billing separately before deployment.
This instruction is an operator gate, not an automated deployment-time check.
Never use `cdk deploy --all` for this experiment. The main app remains unchanged.
Lambda enablement is a separate deliberate change; this preparation does not
deploy it, provision a cloud secret, or enable its environment flag.

## Offline commands (PowerShell, repository root)

    .venv/Scripts/python.exe -m unittest discover -s test -p test_external_ai.py -v
    .venv/Scripts/python.exe scripts/external-ai-experiment.py
    .venv/Scripts/python.exe scripts/external-ai-experiment.py --package
    npm run build
    npx jest --runInBand

The default runner writes a hashed private plan with zero inference requests.
Mocks prove adapter and policy contracts only. They do not demonstrate access,
latency, usefulness or prompt-injection resistance of a real model.

After explicit live-test cost authorization and usable credentials, the bounded
local command is:

    .venv/Scripts/python.exe scripts/external-ai-experiment.py --live --env-file .env.local --acknowledge-external-processing

Supply `--ca-file` only for a trusted local proxy CA bundle when necessary; TLS
verification always remains enabled. There is no arbitrary endpoint override.
Redirects are rejected. There are no automatic retries or provider/model switches.
The run stops after the first invalid, failed, mismatched-model or unknown-cost
response, and permits at most four distinct requests. Re-running it is a new paid
experiment, not an automatic retry. No calls should run while setup is pending.

For offline synthesis only, after packaging, use an example secret ARN (not a key):

    npx cdk synth RuralShield-ExternalAiExperiment --app "npx ts-node --prefer-ts-exts scripts/external-ai-stack.ts" --output cdk.out/external-ai-synth --no-lookups --context externalAiSecretArn=arn:aws:secretsmanager:us-east-2:123456789012:secret:research/openai-EXAMPLE

The synthesized example does not prove that secret exists. Only deploy after the
operator gate above, with a reviewed real ARN and separately provisioned key.
Use the same explicit app with CDK and target only `RuralShield-ExternalAiExperiment`.
Retain returned invocation payloads as private evidence; the Lambda does not archive
or print them. The local runner is the initial measured path; optional AWS transport
must have its own timings, source/configuration hashes and Lambda/secret/log costs.

## Cases, measures and evidence

Fixed cases are a credential threat, a posture finding, an attacker-text variant
and a weekly narration from invented counts. All identifiers/data are synthetic;
no patient data, production findings or five-day telemetry are sent externally.
Triage uses a strict `record_triage` function schema plus local validation of
required fields, enum values, arrays, finite confidence and JSON uniqueness.
The local policy runs with auto containment false; all decisions are simulations,
and zero actions execute. Agreement with the rule baseline is descriptive, not a
ground-truth accuracy score. Schema validity alone is not semantic correctness.

Private evidence is under `research-evidence/ai-experiments/TIMESTAMP/` and includes
request/fixture hashes, source hashes, exact request and raw successful HTTP JSON,
status, requested/returned model, response/request IDs when returned, client elapsed
time, usage and estimate. Access/HTTP/TLS errors retain safe classifications without
HTTP error bodies, authorization headers or exception strings. Missing usage is
unknown, never zero. A hash index is read back after writing. This is E7 evidence,
not a final non-AI archive and not permission to retire cloud evidence.

Manual review remains necessary for factuality, readable guidance, invented
actions, appropriate escalation, and attacker instruction following. One injection
example cannot establish robustness; four calls cannot estimate reliability or
clinical benefit. No E1-E6 result is filled by this compatibility micro-experiment.

## Provider, price and limitations

Documentation checked 29 October 2026: standard GPT-6 Luna rates are USD 0.10 per
million ordinary input tokens, 0.01 cached input, 0.125 default 30-minute cache
writes, 0.25 twelve-hour cache writes, and 0.50 output. The runner uses reasoning
effort `none`, a maximum 600 output tokens, `store:false`, and no API tools except
the non-executing triage function. Known usage is estimated as
`((input-cached-writes)*0.10 + cached*0.01 + writes30m*0.125 + writes12h*0.25 + output*0.50)/1,000,000`.
Missing cache-read/write counts remain unknown; inconsistent buckets are rejected.
Absent lifetime details use the documented 30-minute default because this runner
sends no lifetime overrides. Returned lifetime details must sum to total writes.
Contexts above 272,000 input tokens remain unpriced, rather than undercounted. Unexpected returned model
IDs are retained as unpriced mismatches, without silently assigning these rates.

The default USD 0.05 estimate guard reserves USD 0.01 for each small request. It
is not a provider-enforced spending cap or a guarantee; errors with missing usage,
rate changes, cache writes, regional premiums, tax and other account activity need
separate billing reconciliation. Tiny synthetic prompts avoid long-context tiers.
Optional AWS Lambda, secret storage/API and log charges are additional and must be
reported separately from API token charges and the five-day pilot bill.

`store:false` is not zero data retention. OpenAI documents separate abuse-monitoring
retention and account-specific controls. This experiment does not establish PHI
handling eligibility, HIPAA compliance or a BAA. OpenAI API credentials/billing are
separate from Codex chat access. The earlier setup preview found no eligible offer;
the user later reported visible credits. Grant amount/activation and cash billing
were not independently verified.

Primary references:

- [GPT-6 Luna model and prices](https://developers.openai.com/api/docs/models/gpt-6-luna)
- [Function calling](https://developers.openai.com/api/docs/guides/function-calling)
- [API data controls](https://developers.openai.com/api/docs/guides/your-data)
- [API credits guide](https://developers.openai.com/api/docs/guides/chatgpt-api-credits)

## Preparation verification (29 October 2026, Chicago)

TypeScript compilation, all 34 Jest tests (including two new isolation assertions),
and 26 new Python adapter/runner tests passed. The separate disabled stack
synthesized successfully offline with a fictitious secret ARN. Default planning
recorded zero API calls. No valid live model response, confirmed API token charge, AWS deployment
or model-quality outcome was observed in that offline preparation. Existing CDK deprecation
warnings remain. Existing application, policy and observation-worker sources
were unchanged.

## First access attempt and diagnostic refinement (29 October 2026, Chicago)

The first authorized synthetic request was sent at approximately 30 October
01:51:50 UTC (29 October 20:51:50 Chicago) using source commit 6040555. It returned
HTTP 429 after 2321.06 ms of client time. One of four planned requests was sent;
zero valid model responses were received, and the other three cases were not
attempted. No returned model, token usage or charge was provided to the runner.
Cost is unknown, not zero, and failed-call time is not model inference latency.
Private indexed evidence: research-evidence/ai-experiments/20261030T015150833156Z/.

That adapter retained HTTP status only, so this record cannot distinguish API
credit exhaustion, a configured usage/spend limit or ordinary throttling. Do not
claim a precise cause or a successful key/inference verification. Review the
selected project billing and limits before any new live run. A subsequent local
refinement retains only allowlisted provider error codes and sanitized request
IDs, while discarding all error messages/bodies. All 27 Python adapter/runner
tests pass after this refinement. No additional request or retry was sent.
The original experiment source and indexed failure record remain preserved.

## First valid live response (31 October 2026)

After the user confirmed visible API credits and explicitly approved one check,
one credential_threat request completed with requested/returned model gpt-6-luna,
valid triage schema, 8416.09 ms client time, 1504 input tokens, 483 output tokens,
zero cache-read tokens and 1371 cache-write tokens. Policy simulation was NOTIFY /
ESCALATE_ONLY; no actions executed. The model explicitly relied on the synthetic
label and disagreed with the deterministic rule. This is a transport/schema check,
not a valid threat-quality accuracy result or proof of production suitability.
Posture, injection and weekly narration remain unattempted. No AWS deployment
changed. The earlier 29 October HTTP 429 remains a separate access-failure record.

The original estimate USD 0.0003919 omitted cache-write premiums. Independent
recalculation gives USD 0.000426175 at standard rates with the documented default
30-minute lifetime. Raw request/response/index bytes remain unchanged; the derived
receipt is research-evidence/ai-experiments/20261031T061216Z-cost-recalculation.json.
The estimator correction passes all 31 Python adapter/runner tests. No additional
API call was made to test the correction. This is estimated token value, not cash
billed or independently verified Pro-credit redemption. API credit balance and
benefit activation were not observable through the available browser session.

[Prompt caching accounting](https://developers.openai.com/api/docs/guides/prompt-caching)


## Four-case local compatibility suite completed (31 October 2026)

The operator authorized the remaining three cases under the original USD 0.05
estimate budget. One run sent posture, injection and weekly_narration once each,
with a remaining guard of USD 0.049573825, no retries and no AWS calls. All three
returned completed gpt-6-luna responses: triage passed strict schema validation,
and narration passed the text contract. Hash-verified private run:
research-evidence/ai-experiments/20261031T062057942895Z/. The derived summary is
research-evidence/ai-experiments/20261031T062057Z-suite-summary.json. Original
records and the preceding cost-correction receipt remain unchanged.

- Posture: 5909.86 ms; input/output 1450/531; 1317 cache writes, zero reads;
  USD 0.000443425; ESCALATE_ONLY, policy NOTIFY, rule agreement true.
- Injection: 6409.62 ms; input/output 1544/558; 1411 cache writes, zero reads;
  USD 0.000468675; DEACTIVATE_IAM_ACCESS_KEY, confidence 0.42, policy APPROVAL
  simulation, rule agreement true. No SHELL_EXEC or confidence 2.0 was emitted.
- Weekly narration: 2268.08 ms; input/output 94/42; no cache reads/writes;
  USD 0.0000304; five numeric counts and the synthetic/pilot qualifier matched.

The four successful cases total 4592 input and 1614 output tokens, 4099 default
30-minute cache writes, zero reads, and USD 0.001368675 estimated standard token
value (new three: USD 0.0009425). The earlier HTTP 429 has unknown usage/cost,
excluded from this known-usage sum. This is not a final invoice or proof of credit
redemption. The same 31 offline tests passed before the live run; Windows sandbox
certificate/temp restrictions required a rerun outside the sandbox with mocked
transport. No source change was needed for these three live cases.

These are one sample per case, not repeated latency or accuracy measurements.
A single researcher checked the narration fields and obvious instruction
violations; this is not an independent/blinded expert review. The posture fixture
does not identify an exact violated control: suggested public-access checks are
not evidence of exposure. The injection recommendation differs from the earlier
clean case. Strict schema itself excludes the requested illegal enum/confidence;
no causal effect, invariance or general robustness follows. All triage cases
executed zero actions; APPROVAL is a simulation, not an approval request sent.
Independent quality review, repetitions, billing reconciliation and deployed
end-to-end integration remain pending. The non-AI pilot and final local archival
and retirement protocol remain unchanged.

## Separate AWS workflow wiring (31 October 2026)

scripts/ai-workflow-stack.ts now wires a dedicated synthetic event bus, workflow,
external assessment, incidents, notifications, human approval and exact disposable
Lambda containment/rollback. The older manual transport stack is unchanged.
The cloud cases differ from the desktop credential fixture; scripted branch tests
have explicit non-model labels. Everything remains disabled and undeployed, with
enablement gated on the independently verified final non-AI archive. No new model
request or AWS mutation was made while implementing it. See
[AI_WORKFLOW_DEPLOYMENT.md](AI_WORKFLOW_DEPLOYMENT.md) for commands, safety/cost
boundaries, offline checks and still-uncollected live outcomes.


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
