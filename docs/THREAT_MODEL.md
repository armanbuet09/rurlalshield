> Historical research documentation. Dated entries describe the original study, not the state of a new deployment. Account identifiers and operator email addresses in this public snapshot are examples. Private evidence and account configuration are not distributed. See [public release notes](PUBLIC_RELEASE.md).

# Threat Model

## Assets
1. ePHI in DynamoDB / Aurora / S3 and in transit through API Gateway or the ALB.
2. Availability of the clinical application (patient care disruption is the primary harm; see mortality evidence in DESIGN.md).
3. Integrity and availability of backups and audit logs.
4. Credentials: Cognito identities, IAM roles, the approval-link HMAC secret, DB secrets.
5. The security pipeline itself (an attacker who disables detection or abuses containment).

## Adversaries
* Financially motivated ransomware affiliates (phishing, credential theft, exposed services) — the dominant healthcare threat.
* Opportunistic scanners exploiting misconfiguration (public buckets, open security groups, known CVEs).
* Malicious or compromised insider with console/CLI access.
* An attacker who has read the RuralShield source and crafts findings/inputs to manipulate the Sentinel.

## Trust boundaries
Internet → WAF → API GW/ALB → app compute (private VPC) → data stores; AWS control plane → EventBridge → Sentinel;
e-mail recipient → approval API.

## STRIDE analysis of the Sentinel pipeline

| Threat | Vector | Mitigation | Residual |
|---|---|---|---|
| **Spoofing** a finding to trigger containment against a victim resource | Attacker needs `securityhub:BatchImportFindings` or `events:PutEvents` in the account | Only AWS services publish to the default bus by default; IAM least privilege; CloudTrail alarms on IAM policy changes; containment only affects resources *in the finding* and never protected ones | An insider with Security Hub write access could cause a reversible action against an unprotected resource; the audit record and e-mail expose it |
| **Spoofing** an approval | Forged link | HMAC-SHA256 over `id:action`, constant-time compare, 32-hex random id, single use (conditional write), expiry, rate limit, WAF | E-mail account compromise lets an attacker approve the *proposed reversible* action — the same outcome a legitimate approver would produce |
| **Tampering** with model output to run arbitrary actions | Prompt injection via attacker-controlled finding fields | Finding wrapped as data; Guardrail PROMPT_ATTACK filter; forced tool with closed enum; policy ignores free text; targets taken from structured finding; tag-fenced IAM; no destructive playbooks | A successful injection can at most *recommend* a different allow-listed reversible playbook, which still must pass rule agreement or human approval |
| **Tampering** with the policy (code) | Supply-chain or deployment compromise | CDK app in version control; CloudTrail on Lambda code updates; function tags protected; reviewers see diffs | Standard software supply-chain risk |
| **Repudiation** | "The system did that, not me" | Every triage, approval (with source IP/UA) and containment is recorded in the incidents table (6-year TTL) and in Security Hub notes; SFN logs ALL | — |
| **Information disclosure** of PHI through the model | Finding text containing PHI (e.g., object keys, user names) sent to Bedrock | Bedrock does not train on customer data and is HIPAA-eligible; Guardrail PII anonymization; findings rarely contain clinical content; no request/response bodies are logged (API data tracing disabled) | Object keys chosen by the application could embed identifiers — guidance: use opaque keys |
| **Denial of service** of the pipeline | Finding floods, model throttling | Reserved concurrency 10, DLQs, SFN retries with backoff, rule-based fallback when the model fails; findings remain in Security Hub regardless | Delayed triage during a burst; no loss |
| **Denial of service** of the hospital by the pipeline | Over-eager automation | Only reversible actions; AUTO only for CRITICAL (or HIGH for S3 BPA) with rule agreement; protected tags on the framework's own roles and the ALB SG; roll-back command in every e-mail | A false-positive CRITICAL credential-exfiltration finding could deactivate a key an integration depends on; roll back is one command |
| **Elevation of privilege** via the containment role | Abuse of `iam:PutRolePolicy` | Only Deny statements are ever written; actions fenced by `aws:ResourceTag/rural-shield:protected`; no `iam:AttachRolePolicy`/`CreatePolicyVersion` | The role can still deny-all an unprotected role (by design, with approval) |

## Workload-layer threats (summary)
* Public exposure: account + bucket BPA, private subnets, no NAT, WAF; Config/Security Hub detect drift.
* Credential theft: MFA everywhere, short tokens, Cognito threat protection, GuardDuty credential findings → REVOKE_ROLE_SESSIONS.
* Ransomware: Object Lock, Vault Lock, PITR, DR copies, weekly restore tests; GuardDuty RDS data-activity and S3 exfiltration/destruction detection.
* Malware via uploads: scan-on-upload; deny-unscanned bucket policy.
* Vulnerable dependencies: Inspector code + dependency scanning; managed runtimes patched by AWS.
* Logging gaps: CloudTrail data events, flow logs, API/WAF/ALB logs to WORM archive; CIS alarms on logging changes.

## Explicitly out of scope
Endpoint devices, e-mail, medical devices, on-premises networks, physical security, workforce training,
legal breach determination.
