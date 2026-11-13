> Historical research documentation. Dated entries describe the original study, not the state of a new deployment. Account identifiers and operator email addresses in this public snapshot are examples. Private evidence and account configuration are not distributed. See [public release notes](PUBLIC_RELEASE.md).

# Evidence-preserving post-test closeout

Later operator authorization adds a [verified local archive and duplicate
retirement stage](LOCAL_EVIDENCE.md). This document describes the AWS-native first
stage. Local retirement can subsequently remove rechecked log groups, the unused
synthetic table/PITR and archived unlocked duplicates, while preserving all keys,
locked objects and recovery points.

The operator authorized stopping billable RuralShield research services after the
five-day test on 25 October 2026. This replaces the earlier traffic-only closeout
instruction. The frozen experiment ends **30 October 2026 at 18:29 UTC (1:29 PM
Chicago)**. Traffic retains that deadline. The separate closeout schedule starts
five minutes later, at **18:34 UTC (1:34 PM Chicago)**, allowing in-flight requests
and evidence writes to drain. AWS Scheduler has minute-level invocation precision;
archival and service removal take additional time. This is not a promise that all
charges stop at exactly 1:34 PM.

## AWS-native execution

`RuralShield-NonAiCloseout` is separate instrumentation and does not redeploy the
frozen application or observation worker. Its Lambda packages a pinned account,
resource inventory and deadline in `plan.json`. It runs independently of desktop
availability and CLI login expiration. A native schedule retries every 15 minutes
for up to 24 hours, with Lambda retries and a failure queue. Successful completion
deletes the retry schedule. A six-hour Codex follow-up checks receipts, downloads
evidence and updates the paper; this is a separate verification path.

The Lambda refuses destructive work before the fixed deadline plus five minutes.
`preflight` performs ownership reads only. `archive-check` writes separately named
diagnostic exports but cannot open the final archival gate or call shutdown. An
archive diagnostic during the run is not a completed experiment or teardown.

## Evidence gate and preservation

Before stopping services, the worker exports and reads back SHA-256-verified JSON
for achieved request counts, all failed and missing intervals, nearest-rank client
latencies, deployed templates and resource inventories, security findings, Config
rules and evaluations, metrics, backup inventories, bucket versions/encryption and
the deployed synthetic table contents and explicit records of absent regional replicas. It retains the original raw minute
records and frozen source/configuration snapshot. Existing readiness, recovery and
replication receipts have also been copied into the encrypted evidence bucket.

The gate is `closeout/archive-verified.json` in the private observation bucket.
Each action has its own receipt under `closeout/actions/`; retries reuse completed
actions. `closeout/latest.json` records checks and blockers. Only verified success
writes `closeout/completed.json`. A deployed schedule is not proof that shutdown
has happened. Diagnostic exports live under `closeout/preflight/` and cannot
substitute for the final gate.

Preserved resources include:

- The versioned private evidence bucket, raw measurement files, configuration and
  source hashes, setup failures and recovery receipts.
- The original S3 audit archives, delivery buckets and synthetic PHI/replica
  objects, including Object Lock protections.
- Existing CloudWatch log groups, retained for at least one year after closeout,
  and metrics exported before service removal.
- DynamoDB synthetic data and existing AWS Backup recovery points, vaults and
  configured retention. Existing PITR/storage remains billable.
- Both regional KMS keys, IAM ownership and CloudFormation stack records. No key
  is disabled or scheduled for deletion. No object/vault deletion or retention
  bypass permission is granted to the closeout role.

The dedicated synthetic observer is disabled and its credential secret is retired
with a seven-day recovery window. Secret values are not paper evidence and are
never exported. Original encrypted data remains readable through its retained
keys. Recovery points still follow their original expiry; keeping results does
not extend every backup indefinitely.

## Services stopped after verified archival

- Disable synthetic traffic and the dedicated observer account.
- Remove the research REST API and WAF, then the pinned VPC endpoints. Delete
  workload flow-log collection, DynamoDB Contributor Insights and the deployed CloudWatch alarms.
- Cancel the research backup selection/plan and weekly restore-testing selection
  and plan. This prevents future scheduled jobs, while preserving existing data.
- Export and remove the 38 owned Config rules; stop the owned Config recorder.
- Suspend the owned GuardDuty detector, pause Macie, disable the enabled Inspector
  scanning types and Security Hub CSPM, and stop the owned multi-region trail.

Account-wide pauses are guarded by a fresh dedicated-account ownership check in
Ohio and Oregon. Unexpected workloads block these pauses and are reported instead
of being silently affected. Resources in other regions are not removed. API/WAF,
endpoint and schedule IDs are pinned; this is not an account-wide destroy script.
Service removals intentionally create CloudFormation drift. Do not redeploy the
frozen stacks automatically, because that could restart billing or recreate
services. Source and templates remain available for reproducibility.

## Costs and verification boundary

Stopping active services substantially reduces recurring charges; it does not
produce a zero AWS bill. S3, CloudWatch/DynamoDB storage, existing PITR and backups,
two KMS keys and small control-plane/evidence requests can remain billable. Locked
archives cannot be deleted before their retention expires. The USD 25 alert remains
an alert, not a cap. Inventory residual costs and refresh billing after AWS's
reporting lag, separating setup, active-window, instrumentation and post-run costs.

Local safety tests cover the time guard, five-minute drain, read-only preflight,
non-destructive archive diagnostic, wrong-account rejection, archive failure and
hash-change rejection, evidence-before-mutation ordering and incomplete-closeout
retry behavior. These do not establish that future AWS teardown will succeed.
Future completion requires actual action receipts and verification checks.

Preparation verification on 25 October: TypeScript build and eight local safety
tests passed. The separate stack deployed successfully. A live early-execution
probe returned `before-closeout-deadline`; read-only ownership checks found no
unrelated workloads. A live `archive-check` under the deployed role exported and
read-back verified 73 diagnostic JSON records with `shutdownPerformed: false`.
Earlier diagnostic failures (a missing inventory permission and an assumed Oregon
DynamoDB replica that is not deployed) were corrected; the experiment itself was
not stopped or redeployed. These diagnostics do not test future service deletion.

Read receipts without changing services, and download a hash-indexed local copy:

```powershell
.venv/Scripts/python.exe scripts/check-nonai-closeout.py
.venv/Scripts/python.exe scripts/check-nonai-closeout.py --download
```

The download target is `cdk.out/closeout/preserved-evidence/`; its index records
object version IDs and SHA-256 hashes. On final closeout, compare downloaded files
against the final verified archive manifest before updating the paper.

AWS documents [Scheduler timing](https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html),
[GuardDuty suspension](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_suspend-disable.html),
[Security Hub finding export before disable](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-disable.html)
and [continuous-backup stopping and retention](https://docs.aws.amazon.com/aws-backup/latest/devguide/point-in-time-recovery-stopping.html).


## Verified native completion (30 October 2026, checked after CLI renewal)

The completed receipt has 24 passing checks and reports 73 actions. Its S3 version was written at 18:40:00 UTC (1:40 PM Chicago); archive verification was written at 18:36:17 UTC. The retry schedule is absent. Both failure queues are empty at the fresh check. Read-only spot checks independently confirmed the scoped API is absent and the load rule/synthetic user are disabled. The original native exports (73 objects) were downloaded and independently compared to the cloud gate's hashes, inside a 7,286-file post-window checkpoint. No further native retry was needed.

This verifies native shutdown and export integrity. It does not establish a zero bill, complete raw-log local archival or independent-drive backup resilience. The actual completion-object write time, later than its reported handler timestamp, moves final local archival to no earlier than 31 October 18:40 UTC. The tested local guard pins its exact version/checksums/time and retirement rechecks them. Full capture and duplicate retirement have not run; locked objects, all keys/rotation and recovery points remain protected. See LOCAL_EVIDENCE.md. Do not automatically redeploy the drifted frozen stacks.


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
