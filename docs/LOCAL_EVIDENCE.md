> Historical research documentation. Dated entries describe the original study, not the state of a new deployment. Account identifiers and operator email addresses in this public snapshot are examples. Private evidence and account configuration are not distributed. See [public release notes](PUBLIC_RELEASE.md).

# Local paper evidence and lower post-test costs

On 25 October 2026 the operator authorized keeping the paper's evidence locally
to reduce ongoing AWS costs. This adds a local second stage to the AWS-native
closeout in [NONAI_CLOSEOUT.md](NONAI_CLOSEOUT.md). It does not change the frozen
five-day experiment, its target, or its October 30 deadline.

**Verified final non-AI archive - 1 November 2026.** The corrected capture started at 20:04:55 UTC and passed independent file/ZIP verification at 20:57:56 UTC. It preserves 30,459 files, 30,399 S3 object versions from seven pinned buckets, 16 owned log groups with 20,203,422 returned events, and one synthetic table with 124 archived items. The ZIP contains 1,789,567,874 bytes. The separate offline activation gate also verified the frozen source, the pinned native completion receipt and all final cloud-manifest exports. These are archival inventory counts, not additional 120-hour requests or proof that AWS delivered every possible service log. The earlier interrupted capture is preserved as incomplete; only the local exporter was restarted. The frozen workload/worker and its observed counts were unchanged. Duplicate retirement requires its own fresh preview, unchanged-data checks and execution receipt. AWS AI results and costs are recorded separately. The final archive is research-evidence/final-20261101T200455Z. Its ZIP and unpacked files share one disk and are not an independent drive backup.

## Current copy and final copy

`scripts/paper_evidence.py` writes a private archive under `research-evidence/` in
the repository workspace. This directory is outside `cdk.out`, is ignored by Git,
and must be preserved when cleaning build output or moving the repository. Each
snapshot contains an unpacked `payload/`, `manifest.json`, `evidence.zip`, and
`verification.json`. The ZIP and unpacked files are independently read and checked
against SHA-256 hashes. They are two representations on the same disk, not an
independent disaster-recovery backup; copy the ZIP to another drive for that.

The archive includes all versions present at listing time in the seven pinned
RuralShield buckets, including locked audit objects and the frozen source/config,
raw minute records, security/Config findings, metrics and recovery receipts. It
also collects raw events from the owned CloudWatch log groups, actual synthetic
table contents and metadata, and current paper/documentation sources. Original
bucket/key/version and log-group identities are retained in the manifest. Hashed
local filenames avoid Windows path limits. Credentials are not deliberately
retrieved or exported; keep the raw operational archive private.

A snapshot during the run is a **checkpoint**, not complete five-day evidence.
After verified AWS-native shutdown, the final copy must wait at least 24 hours
after the frozen deadline, the receipt's reported timestamp, and the S3 completion
object's actual LastModified time. The latter can be later than the Lambda's start
time. The final manifest pins the receipt version, raw checksum, document checksum
and write time; retirement rechecks that identity. Missing or changed metadata
cannot authorize cleanup. Existing checkpoints remain verifiable but cannot retire
cloud data.

The verified completion object was written on **October 30 at 18:40 UTC (1:40 PM
Chicago)**. Final local archival is therefore eligible no earlier than **October
31, 2026, 18:40 UTC (1:40 PM Chicago)**. This guard is locally tested (12 safety
tests, including delayed write and metadata mismatch cases). The replacement final
capture passed independent verification on 1 November at 20:57:56 UTC. Duplicate
retirement requires its own preview and execution receipt. Snapshots inventory
available data, not proof that AWS delivered every possible service log.

```powershell
# Safe during the run: create a checkpoint; deletes nothing in AWS.
.venv/Scripts/python.exe scripts/paper_evidence.py
# Offline integrity check:
.venv/Scripts/python.exe scripts/paper_evidence.py --verify research-evidence/<snapshot>
# After native closeout and the 24-hour guard:
.venv/Scripts/python.exe scripts/paper_evidence.py --final
```

## Cleanup only after final local verification

The local retirement step refuses checkpoints, an early timestamp, a changed
archive/ZIP, an unsuccessful native closeout or a mismatch with the final AWS
evidence manifest. It also verifies the frozen source hash, account/window,
disabled traffic schedule, absent application API and stopped audit trail.
Before deleting a log group it fetches its events again and requires the same
count and content hash. Before deleting the synthetic table it requires the same
data hash. New data blocks that deletion and requires another final archive.

The authorized second stage can then remove:

- Owned CloudWatch log groups whose full raw contents were independently copied
  and rechecked.
- The pinned unused synthetic DynamoDB table, including ongoing PITR. Table
  deletion protection is disabled only immediately before its guarded deletion.
- Exact, locally archived versions of unlocked evidence exports and delivery
  staging objects. Newly arrived versions are retained. Small cloud control,
  final archival, action and completion receipts are retained for traceability.

It never deletes or disables KMS keys, changes key rotation, deletes recovery
points/vaults, bypasses retention, or deletes any version in an Object Lock bucket.
It does not delete CloudFormation records or unrelated resources. Physical table
and log removal adds to the documented post-test CloudFormation drift. Native
closeout also stops access logging on the two research PHI buckets after archival,
so future administrative reads do not keep generating billable delivery logs.

```powershell
# Verify and preview; makes no cloud deletions:
.venv/Scripts/python.exe scripts/paper_evidence.py --retire research-evidence/<final-snapshot>
# Execute only after the preview and final integrity checks pass:
.venv/Scripts/python.exe scripts/paper_evidence.py --retire research-evidence/<final-snapshot> --execute
```

An append-only local action journal survives interrupted cleanup. The resulting
`retirement.json` and cloud `closeout/local-retirement.json` record actions, skipped
new data and retained locked resources. Do not call the cleanup complete if a
required data store was skipped for changed data; capture a new final archive and
finish the unaffected authorized work without bypassing the checks.

If preview detects a changed log group, explicitly retain it while retiring other
unchanged eligible copies with `--defer-log REGION LOG_GROUP`. A deferral is
accepted only for a group in the verified archive, never deletes that group, and
keeps retirement partial even if its next read might match. Capture another final
archive before considering the retained group's removal. The receipt records the
deferral; changed-content diagnostics include both counts and hashes.

An in-progress cloud receipt points reporting to the verified local archive
before the first deletion. The observation reporter therefore does not interpret
retired cloud minute files as zero requests. Interrupted cleanup reuses the
verified final archive; subsequent snapshots can seed from it to preserve data
already retired from AWS while collecting late additions. Previous manifests and
verification records remain in the local provenance chain.

This local stage requires this computer to be available and an authenticated AWS
CLI session. The existing Codex follow-up will attempt it when eligible and ask
for reauthentication if needed. The AWS-native service shutdown still runs even
when the computer is off. No cloud copy is removed merely because a future local
download was scheduled.

## Collector correction on 1 November 2026

The first eligible final capture started at 18:11 UTC. Its seven S3 bucket copies
finished, but the raw log export was interrupted deliberately before a manifest,
ZIP or successful final verification existed. Its incomplete private directory
is preserved as partial evidence and cannot authorize retirement or AI activation.
This stopped only the desktop exporter; the frozen workload/worker stayed stopped.

The CLI process provider returned credentials inside botocore's default
15-minute advisory/10-minute mandatory refresh windows. Repeated CLI credential
retrieval slowed log collection even though STS still verified the correct user.
The collector now narrows only that local session's process-provider refresh
windows to five minutes/one minute. The real AWS expiry and refresh callback are
unchanged; expired credentials remain unusable. Other providers are unaffected.
This uses the installed botocore refresh interface and refuses an unsupported
interface. No local AWS configuration or credential plaintext is rewritten.

The replacement capture uses four log-reader threads and pins its collector and
helper source hashes. Retirement still reads every owned event and compares its
count and canonical content hash. Each complete log recheck is delivered immediately
before its own deletion, without waiting for slower groups. A final inventory
retains new/recreated owned groups and marks cleanup partial. Exact immutable S3
versions can be deleted in batches of at most
1,000 after the same archive/ownership gate and a fresh bucket Object Lock check
before each batch. Confirmed per-object successes are journaled; partial,
unexpected or missing results stop cleanup. Mutable null versions are retained.
The final version listing detects unarchived arrivals during deletion and marks
retirement partial. All prior protection rules remain in force.

The relevant offline checks pass: 28 collector/retirement tests and 14 independent
AI archive-gate/packaging tests. These checks are not a completed replacement
capture, live deletion or AI deployment result. Require the replacement command's
actual successful verification before proceeding.

## Remaining costs and paper claims

The savings are the CloudWatch copy, unused table/PITR and unlocked duplicates.
The two KMS keys still cost about USD 2/month initially, plus protected S3 objects,
remaining backup retention and small receipt/access costs. Local storage cannot
eliminate the cost of locked originals without making them unreadable. Keep the
existing USD 3â€“5/month initial planning allowance until final retained sizes and
actual bills justify a lower figure. Key rotation remains enabled as described in
[COST_MODEL.md](COST_MODEL.md).

The paper must distinguish checkpoint collection, verified final local capture,
native shutdown and verified duplicate retirement. Local storage costs and the
one-time export/download overhead are outside the narrow AWS retention charge.
Do not mark future cleanup or five-day outcomes completed now.

AWS documents [Object Lock and encryption-key loss](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html)
and [DynamoDB system backups on table deletion](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery_Howitworks.html).


## Final capture and approved retirement update - 1 November 2026

The corrected final capture started at 20:04:55 UTC and passed independent
unpacked/ZIP verification at 20:57:56 UTC. The final directory is
research-evidence/final-20261101T200455Z: 30,459 files, 30,399 S3 versions from seven
pinned buckets, 16 log groups with 20,203,422 returned events, 124 table items and
a 1,789,567,874-byte ZIP. The separate activation gate also verified the frozen
source and pinned native completion/cloud manifest. The earlier interrupted
capture remains incomplete and preserved. Inventory counts do not establish log
delivery completeness or add to the pilot request count.

A fresh preview found a mismatching patient-portal API-access log group. Its
cause is not established. Automatic approval review initially rejected execution
for insufficiently explicit destructive-cleanup consent; nothing was deleted by
that rejected request. The operator subsequently explicitly approved the concrete
unchanged subset: 15 owned log groups, the unused synthetic table/PITR and 18,308
exact archived unlocked versions. Execution is in progress with an explicit
--defer-log for the API-access group. Retain that group for another final capture;
do not claim completed retirement from the preview or approval. All Object Lock
versions, KMS keys/rotation, vaults/recovery points and control receipts remain.

The separately archived and stopped AI trial was also explicitly approved for
removal and completed its scoped cleanup. It never modified the frozen pilot.
See AI_WORKFLOW_DEPLOYMENT.md for its distinct results, evidence and limitations.


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
