> Historical research documentation. Dated entries describe the original study, not the state of a new deployment. Account identifiers and operator email addresses in this public snapshot are examples. Private evidence and account configuration are not distributed. See [public release notes](PUBLIC_RELEASE.md).

# Control Mapping

Evidence column: **CN** = cdk-nag rule evaluated at synth; **CFG** = AWS Config managed rule evaluated continuously;
**SH** = Security Hub standard control; **RS** = RuralShield aspect check; **Doc** = architecture/documentation evidence.

HPH CPG = HHS *Healthcare and Public Health Cybersecurity Performance Goals* (Jan 2024). HICP = *Health Industry
Cybersecurity Practices* 2023 edition. NPRM = HIPAA Security Rule Notice of Proposed Rulemaking (Jan 2025, not final).

## Administrative safeguards — 45 CFR §164.308

| Citation | Requirement | RuralShield implementation | HICP / CPG / NIST CSF 2.0 | Evidence |
|---|---|---|---|---|
| 164.308(a)(1)(ii)(A) Risk analysis | Identify threats/vulnerabilities to ePHI | Security Hub (AFSBP, CIS, NIST 800-53 r5) + Inspector + Macie continuously enumerate exposures; weekly plain-English report | HICP 10; CPG Enhanced "Asset inventory", "Cybersecurity testing"; GV.RM, ID.RA | SH, Doc |
| 164.308(a)(1)(ii)(B) Risk management | Reduce risks to reasonable level | Secure-by-default constructs; synth-time cdk-nag gate; Config drift detection | ID.RA, PR.PS | CN, CFG |
| 164.308(a)(1)(ii)(D) Information system activity review | Review logs, access reports, incidents | CloudTrail (mgmt + S3 + Lambda data events) → WORM archive; CIS alarms; Sentinel triage; incidents table; weekly report | HICP 8; CPG Enhanced "Centralized log collection"; DE.CM, DE.AE | CFG `cloud-trail-enabled`, `multi-region-cloud-trail-enabled`, Doc |
| 164.308(a)(3) Workforce security | Authorize/supervise access | Cognito user pool administered by the organization; no self-sign-up; IAM Access Analyzer for external access | HICP 3; CPG Essential "Revoke credentials for departing workforce"; PR.AA | Doc |
| 164.308(a)(4) Information access management | Access authorization and modification | Least-privilege execution roles via CDK grants; fine-grained authz in app; API requires JWT on every method | HICP 3; PR.AA | CN (IAM4/IAM5 reviewed), Doc |
| 164.308(a)(5)(ii)(B) Protection from malicious software | Guard against malware | GuardDuty Malware Protection for S3 (scan-on-upload) + deny-unscanned bucket policy; Inspector dependency/code scanning; no OS to infect | HICP 2; CPG Essential "Mitigate known vulnerabilities"; PR.PS, DE.CM | Doc, SH |
| 164.308(a)(5)(ii)(C) Log-in monitoring | Monitor log-in attempts | Cognito threat protection (adaptive auth, compromised credentials); CIS alarm for console login without MFA; GuardDuty RDS login anomaly detection | HICP 3; DE.CM | Doc, CFG `iam-user-mfa-enabled` |
| 164.308(a)(5)(ii)(D) Password management | Create/change/safeguard passwords | Cognito 14-char policy; IAM account password policy (14 chars, 24 history, 90-day age); Secrets Manager rotation for DB credentials | CPG Essential "Unique credentials"; PR.AA | CFG `iam-password-policy`, `secretsmanager-rotation-enabled-check` |
| 164.308(a)(6) Security incident procedures | Identify, respond, document incidents | Sentinel: triage → policy → (approval) → containment → audit record; Security Hub notes; plain-English notifications | HICP 8; CPG Essential "Basic incident planning and preparedness"; RS.MA, RS.AN | Doc |
| 164.308(a)(7)(ii)(A) Data backup plan | Retrievable exact copies of ePHI | AWS Backup continuous (35 d) + monthly (1 y); DynamoDB PITR; S3 versioning + Object Lock | HICP 4; CPG Essential "Basic incident planning"; PR.DS | CFG `dynamodb-pitr-enabled`, `dynamodb-in-backup-plan`, `backup-recovery-point-minimum-retention-check` |
| 164.308(a)(7)(ii)(B) Disaster recovery plan | Restore any loss of data | Vault Lock; optional cross-region vault copy + PHI replication; redeploy via `cdk deploy` in DR region | RC.RP | Doc |
| 164.308(a)(7)(ii)(D) Testing and revision | Test contingency plans | Weekly automated AWS Backup restore test with validation window; failures alarm | CPG Enhanced "Cybersecurity testing"; ID.IM | Doc |
| 164.308(a)(8) Evaluation | Periodic technical evaluation | Config rules + Security Hub re-evaluate every 12–24 h; weekly report archived as evidence | GV.OV | CFG, Doc |
| 164.308(b) Business associate contracts | Satisfactory assurances | AWS BAA (operator accepts via AWS Artifact); only HIPAA-eligible services used | GV.SC | Doc |

## Technical safeguards — 45 CFR §164.312

| Citation | Requirement | RuralShield implementation | HICP / CPG / NIST CSF 2.0 | Evidence |
|---|---|---|---|---|
| 164.312(a)(1) Access control | Allow only authorized persons/software | Cognito-authorized API; IAM least privilege; private subnets; S3 Block Public Access (bucket + account) | HICP 3, 6; PR.AA, PR.IR | CN S2/S10/IAM5, CFG `s3-bucket-public-read-prohibited`, `s3-account-level-public-access-blocks-periodic`, `lambda-function-public-access-prohibited`, `rds-instance-public-access-check` |
| 164.312(a)(2)(i) Unique user identification | Unique name/number | Cognito identities; CloudTrail attributes every API call; no shared service users | CPG Essential "Unique credentials" | Doc |
| 164.312(a)(2)(ii) Emergency access | Obtain ePHI during emergency | Break-glass IAM role (operator-defined) and Object Lock GOVERNANCE mode allow authorized override; DR region | RC.RP | Doc |
| 164.312(a)(2)(iii) Automatic logoff | End sessions after inactivity | Cognito access/ID tokens 30 min; refresh 8 h; token revocation enabled | PR.AA | RS-IDN1, Doc |
| 164.312(a)(2)(iv) Encryption/decryption | Encrypt ePHI | SSE-KMS (CMK, rotated) on S3, DynamoDB, Aurora, SQS, SNS, Secrets, Logs, Backup, Lambda env | HICP 4; CPG Essential "Strong encryption"; PR.DS | CN S3/DDB4/RDS2, CFG `s3-bucket-server-side-encryption-enabled`, `dynamodb-table-encrypted-kms`, `rds-storage-encrypted`, `cloudwatch-log-group-encrypted`, `backup-recovery-point-encrypted`, `cmk-backing-key-rotation-enabled` |
| 164.312(b) Audit controls | Record and examine activity | CloudTrail with data events, file validation; VPC flow logs; API access logs; WAF logs; ALB logs; 6-year WORM archive | HICP 8; CPG Enhanced "Centralized log collection"; DE.CM | CFG `cloud-trail-log-file-validation-enabled`, `cloud-trail-encryption-enabled`, `vpc-flow-logs-enabled`, `api-gw-execution-logging-enabled`, `wafv2-logging-enabled`; RS-LOG1 |
| 164.312(c)(1) Integrity | Protect ePHI from improper alteration/destruction | Object Lock; versioning; Vault Lock; deletion protection; PITR; CloudTrail digest files | PR.DS | RS-PHI1/PHI3, RS-BKP1, CFG `s3-bucket-versioning-enabled`, `rds-cluster-deletion-protection-enabled` |
| 164.312(d) Person or entity authentication | Verify identity | Cognito MFA required (TOTP); IAM MFA checks; IAM database authentication for Aurora | CPG Essential "Multifactor authentication"; PR.AA | RS-IDN1, CFG `root-account-mfa-enabled`, `iam-user-mfa-enabled` |
| 164.312(e)(1) Transmission security | Guard against unauthorized access in transit | TLS everywhere: `enforceSSL` bucket policies, `rds.force_ssl=1`, SQS/SNS SSL-only, ALB TLS 1.3 policy, API GW TLS; private VPC endpoints keep AWS traffic off the internet | CPG Essential "Strong encryption"; PR.DS | CN S10/SQS4/SNS3, CFG `s3-bucket-ssl-requests-only` |
| 164.316(b)(2)(i) Documentation retention | Retain 6 years | Log archive Object Lock 6 years; incidents table TTL 6 years; weekly reports archived | GV.PO | Doc |

## NPRM-specific proposals (not yet final)

| Proposal | Status in RuralShield |
|---|---|
| Encryption at rest and in transit mandatory | Default everywhere; cannot be disabled via config |
| MFA mandatory | Cognito MFA required; IAM/root MFA monitored |
| Technology asset inventory + network map | Every resource tagged (`rural-shield:*`, `DataClassification`); Security Hub resource inventory; CDK app is the authoritative network map |
| Vulnerability scanning ≥ every 6 months | Inspector continuous |
| Penetration testing ≥ annually | Operator responsibility; WAF logs + API logs support it |
| Network segmentation | Isolated app/data subnets; no NAT; SG ingress only from app tier |
| Separate backup/recovery controls | Vault Lock, separate DR account/region option |
| 72-hour restoration | Weekly automated restore test proves RTO |
| Anti-malware | GuardDuty malware protection, Inspector |
| Review/test security measures ≥ annually | Config + Security Hub continuous; weekly report |

## HPH CPG coverage summary

| Essential goal | Coverage | Enhanced goal | Coverage |
|---|---|---|---|
| Mitigate known vulnerabilities | Inspector + managed runtimes (AWS patches) | Asset inventory | Tags + Security Hub inventory |
| Email security | Out of scope (endpoint program) | Third-party vulnerability disclosure | Out of scope |
| Multifactor authentication | Cognito MFA required | Third-party incident reporting | Out of scope |
| Basic cybersecurity training | Out of scope (notifications are educational by design) | Cybersecurity testing | Weekly restore tests; GuardDuty sample findings exercise |
| Strong encryption | Default | Cybersecurity mitigation | Sentinel containment playbooks |
| Revoke credentials for departing workforce | Cognito admin; Access Analyzer unused-access (optional) | Detect and respond to relevant threats and TTPs | GuardDuty ETD + MITRE mapping + Sentinel |
| Basic incident planning and preparedness | Sentinel runbooks, backups, DR | Network segmentation | Private subnets, SGs |
| Unique credentials | Cognito, IAM roles | Centralized log collection | CloudTrail/flow/API/WAF logs → archive |
| Separate user and privileged accounts | IAM Identity Center recommended (README) | Centralized incident planning | Step Functions workflow + incidents table |
| Vendor/supplier cybersecurity requirements | AWS BAA; Inspector on third-party images | Configuration management | CDK + Config drift detection |
