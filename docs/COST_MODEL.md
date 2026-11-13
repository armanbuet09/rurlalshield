> Historical research documentation. Dated entries describe the original study, not the state of a new deployment. Account identifiers and operator email addresses in this public snapshot are examples. Private evidence and account configuration are not distributed. See [public release notes](PUBLIC_RELEASE.md).

# Cost Model (estimates — validate with the AWS Pricing Calculator before publishing figures)

## Five-day research run

The planned active AWS evaluation lasts **five days (120 hours)** after deployment
and initial readiness checks, with a target of one million synthetic authenticated
requests in total. Report actual achieved duration/load and measured charges; no
five-day cost has been measured. The target is a compressed test workload and is
distinct from the monthly reference scenario below.

Separate the observed five-day service charges, credits/refunds, setup charges, and
post-run retained-resource costs. At hour 120, stop synthetic load and experimental
invocations and inventory remaining resources and schedules. The non-AI pilot worker
has an absolute request deadline and disables its load schedule; infrastructure is
retained. A separate evidence-first service closeout is scheduled for the deadline
plus five minutes; see [NONAI_CLOSEOUT.md](NONAI_CLOSEOUT.md). Locked archives,
retained data, PITR/backups and encryption keys remain billable.

Do not divide the monthly total below by six to present a five-day measurement.
Usage, one-time work, and billing units differ. Any monthly extrapolation must be
labeled modeled and state its assumed traffic rate, storage, and service settings.

**Research cost result: [PENDING E5: measured five-day charges and setup/post-run costs].**

### Current non-AI pilot planning estimate (25 October 2026)

Allow **USD 30–60 before credits and tax** for the frozen 120-hour non-AI
condition targeting one million small authenticated API requests. USD 75 is a
prudent planning allowance, not a spending limit or a guaranteed maximum. This
estimate excludes earlier setup/recovery charges and charges after the window.
It assumes tiny synthetic data, no Aurora/Fargate/NAT, and no Bedrock/Sentinel
inference. It is not the older monthly reference scenario divided by six.

| Component | Five-day modeled USD | Basis / uncertainty |
|---|---:|---|
| VPC interface endpoint hours | 9.60 | Four services × two AZs × 120 hours × USD 0.01; excludes data processing |
| REST API requests | 3.50 | One million calls; excludes transfer |
| WAF | about 2.25 | One ACL, five rules/groups, one million requests; hourly prorated base charges |
| Lambda workload and observation worker | 1–3 | Planning allowance; actual billed durations and auxiliary functions vary |
| Config and security services | 10–25 | Allowance for checks, configuration changes and findings; not a measured usage forecast |
| Logs, audit events, tracing and metrics | 4–12 | Allowance; execution-log volume and sampling are not yet measured over five days |
| Storage, backup, keys, identity, secrets and small transfer | 1–4 | Tiny synthetic dataset; retained resources continue to bill afterward |
| **Rounded planning range** | **30–60** | **Modeled, not measured; variable items can exceed these allowances** |

Verified price basis: [PrivateLink pricing](https://aws.amazon.com/privatelink/pricing/),
[API Gateway pricing (includes Ohio)](https://aws.amazon.com/api-gateway/pricing/),
[WAF pricing](https://aws.amazon.com/waf/pricing/),
[Config pricing](https://aws.amazon.com/config/pricing/),
[Lambda pricing](https://aws.amazon.com/lambda/pricing/),
[CloudWatch pricing](https://aws.amazon.com/cloudwatch/pricing/), and
[Security Hub CSPM pricing](https://aws.amazon.com/security-hub/cspm/pricing/).
The AWS Price List API also returned USD 0.0100000000/Hrs for AmazonVPC,
location `US East (Ohio)`, usage type `USE2-VpcEndpoint-Hours` on 25 October.
Variable rows are engineering allowances, not prices quoted by AWS.

The 18:30 UTC Cost Explorer snapshot had only USD 0.000015 of estimated
whole-account usage for 25 October. This incomplete, lagging snapshot cannot
validate the forecast or establish that operation is effectively free. Previously
verified promotional credits may offset eligible charges; do not subtract them
from reported gross experimental cost or promise a zero invoice. The existing
USD 25 monthly budget sends alerts and does not stop spending.

### Estimated account-day billing after the completed window (verified 30 October Chicago)

**Estimated account-day billing after the window.** The refreshed Cost Explorer export, collected at the post-window reporter cutoff, lists whole-account UTC-day gross charges excluding credits/refunds: USD 2.6254 for 25 October, USD 4.7659 for 26 October, USD 4.2739 for 27 October, USD 4.4434 for 28 October, USD 5.2048 for 29 October and USD 3.3201 for 30 October (USD 24.6335 combined). All rows remain estimated and may change with reporting lag. The six calendar-day bins include setup, instrumentation/export overhead and retained resources; they are not exact attribution to the 120-hour experiment. This collection downloaded 729 new minute objects and 73 native exports; their attributable charges were not isolated. Credits/refunds are excluded and the export does not establish tax or a final invoice. Refresh billing after lag and separate residual storage/key/backup costs. This is neither a final attributed E5 cost nor a demonstrated retention saving or spending cap.

The private export is research-evidence/progress/20261031T025126Z/reports/account-day-costs.json, pinned by progress-index.json. The complete-window reporter records 999,861 attempts, 999,860 successes, one original HTTP 404 and one missing minute (139 unobserved scheduled requests). Native closeout completed with 24 passing checks; its S3 completion object was written at 18:40 UTC on 30 October. Fresh reads confirm API absence and disabled traffic/user. All 73 native exports and the 7,286-file checkpoint were independently verified. Earlier authentication failures and estimated values remain in dated evidence and the paper ledger.

The final all-source local archive is not eligible before 31 October 18:40 UTC (1:40 PM Chicago), and duplicate retirement has not run. Owned CloudWatch logs, the synthetic table/PITR, archived unlocked duplicates, locked S3, backups and two KMS keys still need separate residual accounting. The existing USD 3-5/month initial planning allowance remains unchanged; no measured retirement saving or zero bill is claimed. Reconcile billing again after lag. This local collection made no cloud mutations; the native scoped service removals occurred earlier and intentionally create CloudFormation drift. Do not redeploy the frozen stacks automatically.

## Post-test evidence retention estimate (25 October 2026)

After the now-verified native service shutdown, allow **USD 3–5/month initially**
before credits and tax, or approximately **USD 36–60 for the first year**. This is
a planning allowance, not observed post-test billing or a cap. It assumes the
retained synthetic data and compressed logs remain small (roughly no more than
10 GB in S3 plus 10 GB of billed CloudWatch storage), infrequent evidence access,
and no restarted application, scanners or backup schedules.

- The two current customer-managed KMS keys have a combined base cost of
  **USD 2/month**. Both have 365-day rotation enabled and their next rotation is
  scheduled for 25 October 2027. Each key's first and second rotations add USD
  1/month, so their combined key-only cost becomes approximately USD 4/month after
  the first annual rotations and USD 6/month after the second. Subsequent rotations
  add no further key-storage charge under today's pricing.
- Allow approximately **USD 1–3/month** for retained S3/log/table/PITR/backup storage,
  occasional requests and a buffer. This is an engineering allowance. Final sizes,
  storage classes, versions, backup expiry and access patterns determine the bill.
- Accordingly, a conservative unchanged-settings projection is USD 5–7/month in
  year two and USD 7–9/month from year three at current rates. CloudWatch retention
  and backup expiration can reduce variable storage before then.

The current AWS storage counters are not usable as final evidence: on 25 October,
daily S3 size metrics were unavailable and log/table/backup counters reported zero
despite known recorded data. Do not interpret these lagging counters as zero
storage or zero cost. The read-only inventory is saved privately in
`cdk.out/closeout/retention-cost-inventory.json`; refresh it after closeout and billing
lag before reporting measured retention costs in the paper.

Original backup expiry remains in force (the completed readiness snapshot has
35-day retention). Audit objects have six-year COMPLIANCE retention; retaining
their decrypting keys carries ongoing charges. This estimate does not authorize
changing rotation, deleting keys, bypassing locks or shortening evidence retention.
Local evidence copies have no AWS storage charge but are not a substitute for
the retained encrypted originals in this plan.

Rate sources: [KMS key and rotation pricing](https://aws.amazon.com/kms/pricing/),
[S3 pricing](https://aws.amazon.com/s3/pricing/),
[CloudWatch storage pricing](https://aws.amazon.com/cloudwatch/pricing/),
[DynamoDB pricing](https://aws.amazon.com/dynamodb/pricing/) and
[AWS Backup pricing](https://aws.amazon.com/backup/pricing/).

## Monthly reference scenario (modeled, not the experiment duration)

Reference assumptions: one critical-access hospital, one workload, `us-east-2`, ~1 million authenticated API requests/month,
~200 monthly active users, ~20 GB PHI objects, ~5 GB logs/month, ~100 security findings/month triaged.
Prices are public list prices observed October 2026 and rounded; several services use tiered pricing.
Figures below are **monthly USD estimates requiring refresh**, not a five-day
budget or measured research result. "Low" assumes minimal data/activity; "High"
assumes the upper end of the reference assumptions.

## Lambda mode (default example: DynamoDB + PHI bucket, no Aurora, DR enabled)

| Component | Driver | Low | High | Notes |
|---|---|---:|---:|---|
| GuardDuty (foundational + S3/Lambda/RDS plans) | CloudTrail events, flow/DNS logs, S3 data events | 15 | 60 | Extended Threat Detection included at no cost |
| Security Hub CSPM | ~300 controls × 1–2 checks/day | 15 | 30 | Enhanced Security Hub "Essentials" may add a per-resource charge |
| AWS Config | configuration items + 38 rule evaluations | 10 | 25 | Serverless estates record few CIs |
| CloudTrail | S3/Lambda data events, Insights, CW Logs copy | 5 | 20 | Management events (first trail) free |
| Macie automated discovery | GB inventoried/analyzed | 5 | 25 | Scales with PHI volume |
| Inspector | ~6 Lambda functions (standard + code), ECR images | 5 | 10 | |
| IAM Access Analyzer (external) | — | 0 | 0 | Unused-access analyzer is optional and billed per role |
| KMS | 1–2 keys + requests | 3 | 8 | |
| CloudWatch Logs + alarms | 5 GB ingest, 10 alarms | 5 | 15 | 1-year retention |
| VPC interface endpoints | 4 endpoints × 2 AZs | 58 | 58 | Largest fixed cost; see trade-off below |
| WAF | 2 web ACLs, 5 rule groups, ~1 M requests | 20 | 30 | |
| API Gateway (REST) | 1 M requests | 4 | 6 | |
| Lambda (workload + 5 Sentinel functions) | 1 M invocations, 512 MB, ARM | 3 | 10 | |
| DynamoDB on-demand + PITR | light traffic | 3 | 10 | |
| S3 (PHI + archive + replica) | 20 GB + logs | 2 | 6 | |
| AWS Backup (vault + DR copy + weekly restore test) | GB-months + restore jobs | 5 | 20 | |
| Cognito (Plus plan for threat protection) | 200 MAU | 5 | 15 | |
| Secrets Manager | 2–3 secrets + rotation | 2 | 3 | |
| Step Functions / SNS / EventBridge / SQS | low volume | 1 | 3 | |
| Amazon Bedrock (triage + weekly report) | ~100 findings × ~3k tokens | 2 | 8 | Historical Sonnet-class assumption; reprice GPT OSS 20B before use |
| **Total (Lambda mode)** | | **≈ 170** | **≈ 360** | |

## Optional add-ons

| Option | Low | High | Notes |
|---|---:|---:|---|
| Aurora Serverless v2 (0.5 ACU min, writer + reader) | 90 | 160 | `auroraMinAcu: 0` enables auto-pause for idle clinics (near-zero when paused) |
| Container mode (2 Fargate tasks 0.5 vCPU/1 GB ARM + ALB + 3 extra endpoints) | 95 | 140 | Replaces API Gateway/Lambda line items |
| NAT gateway (`allowInternetEgress: true`) | 35 | 60 | Plus data processing; avoid unless the app needs the internet |
| Bedrock Runtime endpoint (`usesBedrock: true`) | 15 | 15 | |

## Trade-offs the operator can make

* **Interface endpoints vs NAT.** Endpoints (~$58) are more expensive than a single NAT gateway (~$35) in a
  tiny account but remove the internet egress path entirely. For a PHI workload the security argument wins;
  for a dev environment, `allowInternetEgress: true` and removing endpoints is acceptable.
* **Macie.** The most variable line item. Scope stays at automated discovery (sampling); run full classification
  jobs only before an audit.
* **Log retention.** `appLogRetentionYears: 1` keeps CloudWatch costs low; the S3 archive holds 6 years cheaply.

## Context

Microsoft's assessments of 250+ rural hospitals estimated a baseline cybersecurity investment of $30–40 K per
independent 50-bed hospital on the endpoint/identity side. RuralShield addresses a different layer (cloud-hosted
applications and their data) at roughly $2–4 K per year including the AI triage layer, with no staff time for
patching, log retention, backup testing or compliance evidence collection. Both figures exclude application
development and staff training.

The selected research model is now `openai.gpt-oss-20b-1:0`. Existing Bedrock cost figures are historical assumptions, not verified prices or measured GPT OSS costs. No successful GPT OSS inference or five-day cost observation has been collected.


## Additional local-retention cost reduction (25 October 2026)

The operator subsequently authorized a verified local archive and retirement of redundant unlocked cloud copies, owned CloudWatch logs and the unused synthetic table/PITR after the test. See [LOCAL_EVIDENCE.md](LOCAL_EVIDENCE.md). This removes variable retention components from the USD 3-5/month initial planning allowance only after final archival and cleanup verification; no actual savings have been measured. The initial key-only floor remains USD 2/month plus protected S3/backups, control receipts and occasional access. Key rotation and all retention locks remain unchanged. Do not promise a zero bill or replace measured-cost placeholders with assumed savings.


## Separate external AI experiment E7 (initial plan, 29 October 2026)

The prepared OpenAI direct Responses API adapter is outside the frozen non-AI
pilot. Candidate GPT-6 Luna standard rates checked on 29 October are USD 0.10
per million input tokens, 0.01 cached input and 0.50 output; see
https://developers.openai.com/api/docs/models/gpt-6-luna. Up to four tiny
synthetic calls are planned, each bounded to 600 output tokens, with no automatic
retries. The USD 0.05 local estimate guard is not a provider billing cap.
One synthetic access attempt returned HTTP 429; no valid model output or token
usage was returned. Its cost is unknown, not zero.
The setup preview found no eligible API-credit offer. Usable API billing/credit
remain prerequisites; the selected project key is securely configured locally.

Report actual API usage and costs separately from the non-AI AWS account-day
charges. Optional standalone Lambda/secret/log costs would be additional; that
stack is disabled and has not been deployed. The initial plan excluded cache writes; the 31 October correction below includes
them. Estimates still exclude taxes, regional premiums and unrelated activity. Reconcile against
provider billing before reporting final costs. No avoided Bedrock charge or
retention saving is demonstrated by offline tests. Details: EXTERNAL_AI_EXPERIMENT.md.


### First valid separate E7 response and cost correction (31 October 2026)

The user confirmed visible API credits and approved one synthetic check. Direct
OpenAI gpt-6-luna returned a valid response: 1,504 input tokens, 483 output tokens,
zero cache reads and 1,371 cache writes. The initial USD 0.0003919 estimate omitted
write premiums; the corrected standard/default-30-minute estimate is USD
0.000426175: (133*0.10 + 1371*0.125 + 483*0.50)/1,000,000. The cache-aware
estimator now validates disjoint read/write buckets and write lifetime totals;
31 offline tests pass. The raw record retains the original estimate and the
separate derived recalculation is preserved.

This token value is outside the non-AI AWS account-day sum and is not verified cash
billing or proof of a Pro-credit grant. The benefit amount/activation remains
unverified. The earlier failed request has unknown usage/cost. No other case or
AWS AI stack was run. See EXTERNAL_AI_EXPERIMENT.md and the official prompt-cache
accounting guide at https://developers.openai.com/api/docs/guides/prompt-caching.


### Four successful E7 cases (31 October 2026)

The remaining three local calls completed: posture USD 0.000443425, injection USD
0.000468675, weekly narration USD 0.0000304; new sum USD 0.0009425. Including the
corrected first successful case, known standard-rate token value is USD
0.001368675, below the operator's USD 0.05 estimate budget. The sum uses 493
ordinary input tokens at USD 0.10/million, 4099 default-30-minute cache-write
tokens at USD 0.125/million, zero reads, and 1614 output tokens at USD 0.50/million.
Independent recomputation matched the new runner estimates, and all evidence
hashes were rechecked. No additional inference was used for analysis.

There are five dated requests overall: four valid responses and the earlier HTTP
429 whose usage/cost remain unknown. The known-success sum does not establish an
all-attempt invoice total or cash payment; the Pro grant/balance was not directly
inspected. These desktop calls created no AWS Lambda/secret/log charges and remain
separate from the non-AI account-day cost. The AI stack remains undeployed.
Provider billing reconciliation and attributed AWS cost remain pending.

**Billing refresh before AWS AI deployment - 1 November 2026.** A new pre-AI Cost Explorer export revises the estimated 30 October account-day charge to USD 4.1170462665. The six UTC-day bins for 25-30 October now total USD 25.4304198609; 31 October adds USD 0.0689321754, giving USD 25.4993520363 through 31 October. The 1 November row was USD 0 at retrieval and is incomplete, not evidence of free operation. All rows remain estimated gross unblended whole-account charges excluding credits/refunds. The earlier USD 24.6335 snapshot remains historical; neither snapshot is exact attribution to the frozen 120-hour window, export overhead or an AI experiment. Setup, instrumentation/downloads, retained resources, tax, cash settlement and final invoice reconciliation remain separate. The first all-source capture started on 1 November at 18:11 UTC and was interrupted before final verification after diagnosing repeated CLI credential retrieval. Its incomplete files were preserved. A corrected replacement started at 20:04:55 UTC and passed independent file/ZIP verification at 20:57:56 UTC. The frozen pilot remained stopped. Duplicate retirement and AWS AI observations require their own actual receipts and are reported separately. The private pre-AI billing record is research-evidence/ai-experiments/aws-workflow-20261101/pre-ai-account-day-costs.json.

**Verified final non-AI archive - 1 November 2026.** The corrected capture started at 20:04:55 UTC and passed independent file/ZIP verification at 20:57:56 UTC. It preserves 30,459 files, 30,399 S3 object versions from seven pinned buckets, 16 owned log groups with 20,203,422 returned events, and one synthetic table with 124 archived items. The ZIP contains 1,789,567,874 bytes. The separate offline activation gate also verified the frozen source, the pinned native completion receipt and all final cloud-manifest exports. These are archival inventory counts, not additional 120-hour requests or proof that AWS delivered every possible service log. The earlier interrupted capture is preserved as incomplete; only the local exporter was restarted. The frozen workload/worker and its observed counts were unchanged. Duplicate retirement requires its own fresh preview, unchanged-data checks and execution receipt. AWS AI results and costs are recorded separately. The final archive is research-evidence/final-20261101T200455Z. Its ZIP and unpacked files share one disk and are not an independent drive backup.


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


### Fresh local reporting and protection check - 1 November 2026, 21:58 UTC

The unchanged observation reporter reproduced 999,861 attempts, 999,860 successes,
one failure and missing slot 4420 from the independently verified local final
archive; the load rule remains DISABLED. The original rotating KMS keys remain
Enabled (two), the Object Lock buckets remain enabled (four), and the original
backup vaults remain present (two), with seven and ten recovery points observed
respectively. These are fresh read-only observations, not a new restore exercise
or proof of universal recoverability.

The refreshed whole-account UTC-day Cost Explorer estimate through 31 October
remains USD 25.4993520363. The incomplete 1 November row is now USD 0.0278194568,
giving USD 25.5271714931 across all retrieved bins. Every row is estimated gross
unblended cost, excluding credits/refunds. The current day contains original
retention, collection/cleanup overhead and the separate AI trial; it cannot be
assigned entirely to any one experiment. Reporting lag means this is not a final
invoice, precise five-day attribution or final AI AWS-service cost. Keep the
separately measured OpenAI token estimate outside this AWS sum. Collect billing
again after lag before reporting final charges or realized savings.


## Approved non-AI duplicate retirement verified - 1 November 2026, 22:22 UTC

The guarded execution exited successfully and its local/cloud receipts match.
Exactly 18,324 actions completed: 15 unchanged owned log groups, one unused
synthetic table/PITR and 18,308 exact archived unlocked S3 versions. No actions
went beyond the operator's explicit reviewed subset. The receipt is partial
because the API-access log was explicitly deferred; the other four skips preserve
every version in the four Object Lock buckets. All keys/rotation and backup
vaults/recovery points remain. There were no changed/new-data skips beyond that
deferred log in this execution. Actual retirement receipt timestamp:
2026-11-01T22:22:37.439399+00:00.

A new final capture is in progress, seeded from the independently verified
20:04:55 archive. It will retain the previous payload/provenance and collect the
remaining API-access log and current pinned versions. Do not claim that capture
verified until its actual file/ZIP/cloud-manifest gate exits successfully. The
deferred log is retained, with no additional deletion authorized by this step.
The original final archive remains safe; do not require retired cloud exports
through the old download helper. Existing reporting uses its verified local copy.
Cost savings and a zero bill are not established by deletion receipts; residual
locked S3/backups, two rotating keys, the deferred log and small control/bootstrap
objects still require retention accounting and lagged billing.


## Follow-up final archive independently verified - 1 November 2026

The seeded final archive final-20261101T222247Z verified at 2026-11-01T22:38:23.216889+00:00:
30,464 payload files and a 1,871,761,398-byte ZIP. The separate
activation/evidence gate also exited zero. The prior 30,459-file archive remains
unchanged and its verified data/provenance are carried forward, including the
retired copies; these are not all newly read live cloud objects or additional
pilot requests. The remaining API-access log was freshly read. All 7,199 minute
keys and raw hashes match the earlier capture, reproducing 999,861 attempts,
999,860 successes, one failure and missing slot 4420 (139 unobserved requests).

The follow-up read returned one additional historical API-access record, timestamped 2026-10-28T11:35:56.847000+00:00 and ingested 2026-10-28T11:36:16.894000+00:00; both precede the first final capture. All prior full record representations were retained in this comparison. The retrieval difference is unexplained and does not add a measured pilot request or fill the missing minute. Both copies remain preserved. Archive byte integrity does not prove that every existing service-log record was returned.

The approved subset remains fully removed (15 log groups, one synthetic table/PITR
and 18,308 exact unlocked versions). The deferred log remains in AWS. Fresh checks
found one owned non-AI group, the original table absent, two Enabled rotating KMS
keys, four Object Lock buckets and two backup vaults with seven/ten recovery
points. The original observer credential was already recoverably retired by
native closeout. No new deletion was performed by the follow-up capture.

Current pinned-bucket listings contain 12,093 versions; the
four locked buckets account for 12,011 versions and 575,522,075 listed object
bytes. The retained log reports 220285938 stored bytes. Vault APIs
report 39,889 backup bytes per vault across the observed points; these counters
are not an invoice, physical deduplicated storage or a full inventory of possible
DynamoDB system backups. Control receipts and shared bootstrap assets also remain.
Keep the initial USD 3-5/month planning allowance until lagged billing supports a
revision; do not claim a zero bill or measured savings. Rotation remains enabled.

Final non-AI follow-up manifest SHA-256: c883ac85a328459b80df8ff2e459a40a831cc95018236ed150350276ca79d644.
Final non-AI follow-up ZIP SHA-256: 84bbb3e2cf3c21022b0a612a9375eadca01b293a98db167f239b172405cc2001.
The separate consolidated AI closeout archive is aws-workflow-closeout-evidence-20261101T224227179190Z, with
257 independently verified files and ZIP. Its manifest SHA-256
is 8dea6914019dfb794002fb7637b67710bd85c565837802cb8e34738375ef968d; ZIP SHA-256 is b4075ee7b708947066c6f23bf99bf6a6b02f969f82792b625de6bc2e4a09a655. It includes the later
independent management-event and protection checks, without repeating model calls.
Both cohorts and all publication updates remain private/local. ZIP and unpacked
copies still share one disk, not independent backup media.
