> Historical research documentation. Dated entries describe the original study, not the state of a new deployment. Account identifiers and operator email addresses in this public snapshot are examples. Private evidence and account configuration are not distributed. See [public release notes](PUBLIC_RELEASE.md).

# Five-day non-AI operational pilot

The treatment configuration is `cdk.out/aws-setup/nonai-research.yaml`: Sentinel is absent. This is a single-condition operational pilot, not the conventional comparison baseline and not an AI/fallback evaluation. No real patient data is permitted.

Readiness passed on 25 October 2026: real USER_SRP_AUTH login and TOTP enrollment/challenge using the deployed Cognito client, authenticated HTTPS health/create/read and synthetic round trip, confirmed Ohio alert subscription and user-confirmed test-email receipt, a checksum-matched S3 replica in Oregon, and AWS Backup snapshot restoration into a disposable DynamoDB table. The restored record matched and the sample application handler returned the expected data under the deployment identity; this is not regional failover or restored application-role authorization. The disposable restore table was then deleted. Initial test attempts, the rejected TOTP reuse and backup-window parameters, and the failed pre-fix replication object remain in the evidence record.

Replication required source-object `GetObjectRetention`/`GetObjectLegalHold` and destination-key Decrypt permissions for Bucket Keys. Scope is the named buckets and keys. The correction passed build and 32 Jest tests, then deployed to Workload/DR. Five additional Node tests exercise the observation worker's start/end boundaries, deduplication, stop-on-authentication-error and final-slot request accounting.

The separate `RuralShield-NonAiObservation` stack has 12 instrumentation resources. A minute schedule invokes a Node.js 22 ARM64/512-MiB controller outside the workload VPC. A dedicated synthetic Cognito account uses SRP/TOTP; its password and TOTP secret are held only in CMK-encrypted Secrets Manager and memory, not source, reports or logs. This automated test account is not a model of human MFA usability. The controller caches its ID token with a two-minute expiry margin.

The frozen manifest sets an exact 120-hour start/end boundary and a target of 1,000,000 total authenticated HTTPS requests. Across 7,200 minute slots, each slot receives 138 or 139 requests with four concurrent clients. Hourly synthetic Patient create/read requests are included in that total; remaining requests call health. Report the achieved count, all failures, missing slots and any shortened duration. Do not silently catch up or extend the window. Duplicate minute events acquire no second claim. Per-minute records contain HTTP counts and client elapsed times; percentile summaries use nearest rank. The client runs in AWS Ohio, so its latencies do not represent a clinic WAN or human workflow.

The worker checks the absolute deadline before issuing each request, disables its schedule after the deadline, and stops early on authentication failure, unfinished minute work or excessive HTTP failure. In-flight requests may complete after the issuing deadline. The stop logic has local tests; the complete-window observations are now recorded below; no long-term reliability claim follows. The AWS runner operates independently of this desktop. Workload/security services, evidence, locked objects, backups and encrypted credentials are retained at traffic closeout and may continue billing. Closeout disables the synthetic account. A later operator instruction authorizes the scoped evidence-preserving service shutdown in [NONAI_CLOSEOUT.md](NONAI_CLOSEOUT.md); blanket data or infrastructure deletion remains outside scope.

`arm-nonai-observation.py` refuses to arm before readiness, archives source/config/context/template/dependency hashes in the private evidence bucket, and records start/end in `cdk.out/observation-state.json`. The source snapshot contains uncommitted source; use its archive hash, not a claim of a clean Git commit. `report-nonai-observation.py` caches the raw minute records and reports actual requests, errors, missing fully elapsed minutes and latency. Its `--closeout` mode is guarded by the end timestamp or an actual early-stop record and disables only the schedule and named synthetic account.

Cost Explorer snapshots are estimated whole-account UTC-day totals, excluding credits/refunds. They include setup and other retained resources and cannot establish exact attribution to a 120-hour window with partial UTC days. Keep infrastructure and instrumentation overhead distinct, disclose billing lag, and do not call account-day cost an exact five-day experimental cost. The USD 25 monthly alert does not cap spending.

The conventional baseline, repeated deployments, Sentinel, clinical outcomes, model quality, comprehensive recovery reliability, practitioner study and comparative claims remain outside this pilot. The manuscript's E1–E6 placeholders remain where corresponding outcomes have not been collected.

Commands:

```powershell
.venv/Scripts/python.exe scripts/report-nonai-observation.py
# Only after the frozen end timestamp or a recorded early stop:
.venv/Scripts/python.exe scripts/report-nonai-observation.py --closeout
```


### Active pilot snapshot (25 October 2026, 18:33:54 UTC)

Latest status (25 October 2026, 18:33:54 UTC): non-AI readiness passed and the frozen pilot is active from 25 October 18:29 UTC to 30 October 18:29 UTC (1:29 PM Chicago on both dates). The first four minute records contain 555 attempts, 554 successes and one HTTP 404, with no missing fully elapsed slots at this snapshot. These are preliminary counts, not five-day results. Build, 32 Jest tests and five observation-worker tests pass; the earlier 17 bounded checks remain separately recorded. Bedrock/Sentinel and completed five-day outcomes remain pending. The modeled five-day gross planning range is USD 30-60 before credits and tax, excluding setup and post-run retained-resource charges; see `docs/COST_MODEL.md` (repository root). This is not a measured cost result. The USD 25 monthly alert is not a cap. The AWS load schedule stops independently of the desktop; a six-hour Codex follow-up checks progress and closeout when available. No restart, compensating traffic or protocol change is authorized during this frozen window.


### Scheduled evidence-preserving service shutdown (25 October 2026)

The operator authorized stopping billable research services after the five-day test while retaining paper evidence. A separate `RuralShield-NonAiCloseout` AWS stack is deployed. Traffic ends on 30 October at 18:29 UTC (1:29 PM Chicago); evidence-first closeout starts at 18:34 UTC (1:34 PM Chicago), retries for up to 24 hours and runs independently of the desktop or CLI login. It preserves encrypted evidence, original logs, synthetic data, backup recovery points and KMS keys. The final archive must pass checksum verification before scoped service removal. Existing storage, PITR, locked backups and keys remain billable. Shutdown is scheduled, not yet completed; require `closeout/completed.json` with successful checks before claiming success. See `docs/NONAI_CLOSEOUT.md` at the repository root. This changes post-run handling only; the frozen measurement deadline and target remain unchanged.


The later local-copy authorization and guarded second-stage cleanup are documented in [LOCAL_EVIDENCE.md](LOCAL_EVIDENCE.md). The experiment window and AWS worker are unchanged.


## Complete-window result (verified 30 October 2026, Chicago)

The existing reporter collected the completed window at 31 October 02:51:26 UTC (30 October 21:51:26 Chicago): 7,199 of 7,200 minute records; 999,861 attempts, 999,860 successes and the original slot-0 HTTP 404. Slot 4420 remains absent, representing 139 unobserved scheduled requests. No scheduled requests were unsent inside recorded slots; no gap was replayed. Status totals: 200 = 999,740; 201 = 120; 404 = 1. Nearest-rank Ohio client p50/p95/p99: 28.57/53.01/110.77 ms.

The cutoff control record was written at 18:29:56.861 UTC on 30 October; the rule and synthetic user are disabled. This is not a measurement of the last request issue time. Native closeout has 24 passing checks and a completion object written at 18:40 UTC. Its retry schedule is absent. All 73 native exports and the 7,286-file post-window checkpoint were hash-verified locally under research-evidence/progress/20261031T025126Z/. Both failure queues were empty; deployed observer hash still matched. The frozen workload/worker was not redeployed or restarted. No AI request was made for this collection.

Final all-source archival and duplicate retirement remain pending until at least 31 October 18:40 UTC. Estimated account-day cost is reported separately in COST_MODEL.md; it is not exact 120-hour attribution. Historical active/scheduled snapshots above retain their original dates and are superseded by this result.
