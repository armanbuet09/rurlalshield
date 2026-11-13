"""
RuralShield containment policy.

This module is deliberately free of AWS SDK calls and of any model in the loop.
The LLM may *recommend* a playbook; this code decides what is allowed to happen.

Design rules (see docs/THREAT_MODEL.md and the paper's Section 4):
  1. Only playbooks in PLAYBOOKS may ever execute. Unknown strings degrade to ESCALATE_ONLY.
  2. Only *threat* findings are eligible for containment. Posture, vulnerability and
     sensitive-data findings are explained and routed to humans (NOTIFY).
  3. Unattended (AUTO) execution requires: operator opt-in, a reversible low-blast-radius
     playbook, a severity at or above the playbook's auto threshold, model confidence >= 0.7
     (or a rule-based match), and no protected target.
  4. Findings are never suppressed or closed automatically (recall-preserving).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# ----------------------------------------------------------------------------- playbooks
# target_types use normalized resource types (see normalize_finding).
PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "DEACTIVATE_IAM_ACCESS_KEY": {
        "description": "Set a long-lived IAM access key to Inactive (re-activate to roll back).",
        "reversible": True,
        "blast_radius": "single credential",
        "target_types": ["iam-access-key"],
        "auto_allowed": True,
        "auto_min_severity": "CRITICAL",
    },
    "REVOKE_ROLE_SESSIONS": {
        "description": "Attach an inline policy denying all sessions issued before now (AWS 'revoke sessions'); "
                       "new role assumptions keep working. Delete the inline policy to roll back.",
        "reversible": True,
        "blast_radius": "existing sessions of one role",
        "target_types": ["iam-role"],
        "auto_allowed": True,
        "auto_min_severity": "CRITICAL",
    },
    "QUARANTINE_IAM_ROLE": {
        "description": "Attach a deny-all inline policy to a role (breaks anything using the role until removed).",
        "reversible": True,
        "blast_radius": "one role and every workload using it",
        "target_types": ["iam-role"],
        "auto_allowed": False,
        "auto_min_severity": None,
    },
    "BLOCK_S3_PUBLIC_ACCESS": {
        "description": "Enable all four S3 Block Public Access settings on a bucket.",
        "reversible": True,
        "blast_radius": "public readers of one bucket (none are expected in this architecture)",
        "target_types": ["s3-bucket"],
        "auto_allowed": True,
        "auto_min_severity": "HIGH",
    },
    "QUARANTINE_LAMBDA_FUNCTION": {
        "description": "Set reserved concurrency to 0 so the function cannot run; previous value is recorded for roll back.",
        "reversible": True,
        "blast_radius": "availability of one function",
        "target_types": ["lambda-function"],
        "auto_allowed": False,
        "auto_min_severity": None,
    },
    "REVOKE_OPEN_SECURITY_GROUP_INGRESS": {
        "description": "Remove 0.0.0.0/0 and ::/0 ingress rules from a security group; removed rules are recorded.",
        "reversible": True,
        "blast_radius": "network reachability of resources behind one security group",
        "target_types": ["security-group"],
        "auto_allowed": False,
        "auto_min_severity": None,
    },
    "ESCALATE_ONLY": {
        "description": "No automated action; explain and notify humans.",
        "reversible": True,
        "blast_radius": "none",
        "target_types": [],
        "auto_allowed": False,
        "auto_min_severity": None,
    },
}

PLAYBOOK_NAMES = list(PLAYBOOKS.keys())
PROTECTED_TAG_KEY = "rural-shield:protected"


# ----------------------------------------------------------------------------- data model
@dataclass
class Target:
    type: str            # iam-access-key | iam-user | iam-role | s3-bucket | lambda-function | security-group | other
    id: str              # ARN or native id
    name: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    protected: Optional[bool] = None  # filled by enrichment (tag lookup)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    finding_id: str
    source: str                       # securityhub | guardduty
    product: str                      # GuardDuty | Inspector | Macie | Security Hub | ...
    title: str
    description: str
    severity_label: str               # INFORMATIONAL..CRITICAL
    severity_score: float
    types: List[str]
    category: str                     # threat | posture | vulnerability | sensitive-data | unknown
    targets: List[Target]
    created_at: str
    account: str = ""
    region: str = ""
    remediation_text: str = ""
    remediation_url: str = ""
    mitre: List[str] = field(default_factory=list)
    product_arn: str = ""
    raw_excerpt: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["targets"] = [t.to_dict() for t in self.targets]
        return d


@dataclass
class Decision:
    action_mode: str                  # AUTO | APPROVAL | NOTIFY
    playbook: str
    targets: List[Target]
    reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_mode": self.action_mode,
            "playbook": self.playbook,
            "targets": [t.to_dict() for t in self.targets],
            "reasons": self.reasons,
        }


# ------------------------------------------------------------------------- normalization
def _sev_label_from_score(score: float) -> str:
    # GuardDuty: 1.0-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, 9.0-10 Critical
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 1.0:
        return "LOW"
    return "INFORMATIONAL"


def categorize(product: str, types: List[str]) -> str:
    p = (product or "").lower()
    joined = " ".join(types).lower()
    if "guardduty" in p or joined.startswith("ttps") or "ttps/" in joined or "unusual behaviors" in joined or "effects/" in joined:
        return "threat"
    if "inspector" in p or "vulnerabilities" in joined:
        return "vulnerability"
    if "macie" in p or "sensitive data" in joined:
        return "sensitive-data"
    if "industry and regulatory standards" in joined or "security best practices" in joined or "config" in p or "security hub" in p:
        return "posture"
    return "unknown"


def _targets_from_asff(resources: List[Dict[str, Any]]) -> List[Target]:
    out: List[Target] = []
    for r in resources or []:
        rtype = r.get("Type", "")
        rid = r.get("Id", "")
        details = r.get("Details", {}) or {}
        tags = r.get("Tags", {}) or {}
        protected = (str(tags.get(PROTECTED_TAG_KEY, "")).lower() == "true") if tags else None
        if rtype == "AwsIamAccessKey":
            d = details.get("AwsIamAccessKey", {})
            key_id = rid.split(":")[-1] if ":" in rid else rid
            principal_type = d.get("PrincipalType", "")
            if principal_type == "AssumedRole" or key_id.startswith("ASIA"):
                role_name = (d.get("PrincipalName") or "").split("/")[0]
                out.append(Target("iam-role", f"role/{role_name}", role_name, {"principal_id": d.get("PrincipalId", "")}, protected))
            else:
                out.append(Target("iam-access-key", key_id, d.get("PrincipalName", ""), {"user_name": d.get("PrincipalName", "")}, protected))
        elif rtype == "AwsIamUser":
            name = (details.get("AwsIamUser", {}) or {}).get("UserName") or rid.split("/")[-1]
            out.append(Target("iam-user", rid, name, {}, protected))
        elif rtype == "AwsIamRole":
            name = rid.split("/")[-1]
            out.append(Target("iam-role", rid, name, {}, protected))
        elif rtype == "AwsS3Bucket":
            name = rid.replace("arn:aws:s3:::", "").split("/")[0]
            out.append(Target("s3-bucket", rid, name, {}, protected))
        elif rtype == "AwsLambdaFunction":
            name = rid.split(":function:")[-1].split(":")[0]
            out.append(Target("lambda-function", rid, name, {}, protected))
        elif rtype == "AwsEc2SecurityGroup":
            gid = rid.split("/")[-1]
            out.append(Target("security-group", rid, gid, {}, protected))
        else:
            out.append(Target("other", rid, rid.split("/")[-1], {"asff_type": rtype}, protected))
    return out


def _targets_from_guardduty(resource: Dict[str, Any]) -> List[Target]:
    out: List[Target] = []
    ak = resource.get("accessKeyDetails") or {}
    if ak:
        user_type = ak.get("userType", "")
        key_id = ak.get("accessKeyId", "")
        user_name = ak.get("userName", "")
        if user_type == "AssumedRole" or key_id.startswith("ASIA"):
            role_name = user_name.split("/")[0]
            out.append(Target("iam-role", f"role/{role_name}", role_name, {"principal_id": ak.get("principalId", "")}))
        elif key_id:
            out.append(Target("iam-access-key", key_id, user_name, {"user_name": user_name}))
    for b in resource.get("s3BucketDetails") or []:
        out.append(Target("s3-bucket", b.get("arn", ""), b.get("name", ""), {"public": (b.get("publicAccess") or {}).get("effectivePermission", "")}))
    ld = resource.get("lambdaDetails") or {}
    if ld.get("functionArn"):
        out.append(Target("lambda-function", ld["functionArn"], ld.get("functionName", ""), {"tags": ld.get("tags", [])}))
    inst = resource.get("instanceDetails") or {}
    for ni in inst.get("networkInterfaces") or []:
        for sg in ni.get("securityGroups") or []:
            out.append(Target("security-group", sg.get("groupId", ""), sg.get("groupName", "")))
    rds = resource.get("rdsDbInstanceDetails") or {}
    if rds.get("dbClusterIdentifier"):
        out.append(Target("other", rds.get("dbInstanceArn", ""), rds["dbClusterIdentifier"], {"kind": "aurora-cluster"}))
    return out


def normalize_finding(event: Dict[str, Any]) -> Finding:
    """Accepts an EventBridge event from Security Hub (ASFF) or GuardDuty (native)."""
    detail = event.get("detail", event) or {}
    source = event.get("source", "")
    if "findings" in detail and isinstance(detail["findings"], list):  # ASFF
        f = detail["findings"][0]
        sev = f.get("Severity", {}) or {}
        label = (sev.get("Label") or _sev_label_from_score(float(sev.get("Normalized", 0)) / 10.0)).upper()
        types = f.get("Types", []) or []
        product = f.get("ProductName") or f.get("ProductFields", {}).get("aws/securityhub/ProductName", "") or "Security Hub"
        rem = (f.get("Remediation", {}) or {}).get("Recommendation", {}) or {}
        pf = f.get("ProductFields", {}) or {}
        mitre = [v for k, v in pf.items() if "mitre" in k.lower() or "ttp" in k.lower()]
        return Finding(
            finding_id=f.get("Id", ""),
            source="securityhub",
            product=product,
            title=f.get("Title", ""),
            description=f.get("Description", ""),
            severity_label=label,
            severity_score=float(sev.get("Normalized", 0)) / 10.0,
            types=types,
            category=categorize(product, types),
            targets=_targets_from_asff(f.get("Resources", [])),
            created_at=f.get("CreatedAt", ""),
            account=f.get("AwsAccountId", ""),
            region=f.get("Region", ""),
            remediation_text=rem.get("Text", ""),
            remediation_url=rem.get("Url", ""),
            mitre=mitre,
            product_arn=f.get("ProductArn", ""),
            raw_excerpt=_excerpt(f),
        )
    # GuardDuty native
    score = float(detail.get("severity", 0))
    types = [detail.get("type", "")]
    service = detail.get("service", {}) or {}
    seq = (service.get("detection", {}) or {}).get("sequence", {}) or {}
    # Attack-sequence findings carry the correlated weak signals and their ATT&CK mapping.
    mitre: List[str] = []
    for sig in seq.get("signals", []) or []:
        name = sig.get("name") or sig.get("type")
        if name:
            mitre.append(str(name))
    for tactic in seq.get("tactics", []) or []:
        mitre.append(str(tactic))
    additional = service.get("additionalInfo", {}) or {}
    return Finding(
        finding_id=detail.get("id", ""),
        source="guardduty" if "guardduty" in source or detail.get("schemaVersion") else "unknown",
        product="GuardDuty",
        title=detail.get("title", ""),
        description=detail.get("description", ""),
        severity_label=_sev_label_from_score(score),
        severity_score=score,
        types=types,
        category="threat",
        targets=_targets_from_guardduty(detail.get("resource", {}) or {}),
        created_at=detail.get("createdAt", ""),
        account=detail.get("accountId", ""),
        region=detail.get("region", ""),
        remediation_text=str(additional.get("recommendedActions", "") or seq.get("description", "")),
        mitre=mitre[:12],
        product_arn="",
        raw_excerpt=_excerpt(detail),
    )


def _excerpt(obj: Any, limit: int = 6000) -> str:
    """Compact JSON for the model prompt. Attacker-controlled strings stay inside this blob and are
    wrapped in <finding> tags by prompts.py so the model treats them as data, not instructions."""
    s = json.dumps(obj, default=str, separators=(",", ":"))
    return s if len(s) <= limit else s[:limit] + "...<truncated>"


# ------------------------------------------------------------------ rule-based fallback
_RULES = [
    (re.compile(r"AttackSequence:IAM/CompromisedCredentials", re.I), ["REVOKE_ROLE_SESSIONS", "DEACTIVATE_IAM_ACCESS_KEY"]),
    (re.compile(r"InstanceCredentialExfiltration|CredentialAccess:IAMUser|UnauthorizedAccess:IAMUser|Persistence:IAMUser|PrivilegeEscalation:IAMUser|Exfiltration:IAMUser|Impact:IAMUser|Recon:IAMUser|Discovery:IAMUser|DefenseEvasion:IAMUser|InitialAccess:IAMUser", re.I),
     ["DEACTIVATE_IAM_ACCESS_KEY", "REVOKE_ROLE_SESSIONS"]),
    (re.compile(r"Policy:S3/BucketAnonymousAccessGranted|Policy:S3/BucketPublicAccessGranted|Policy:S3/BucketBlockPublicAccessDisabled|AccountBlockPublicAccessDisabled|S3/AnomalousBehavior", re.I),
     ["BLOCK_S3_PUBLIC_ACCESS"]),
    (re.compile(r"CryptoCurrency:Lambda|Backdoor:Lambda|UnauthorizedAccess:Lambda|Trojan:Lambda", re.I), ["QUARANTINE_LAMBDA_FUNCTION"]),
    (re.compile(r"Recon:EC2/Portscan|UnauthorizedAccess:EC2/SSHBruteForce|UnauthorizedAccess:EC2/RDPBruteForce|Impact:EC2", re.I), ["REVOKE_OPEN_SECURITY_GROUP_INGRESS"]),
]


def rule_based_recommendation(finding: Finding) -> str:
    """Deterministic mapping used when the model is unavailable, and as a cross-check."""
    if finding.category != "threat":
        return "ESCALATE_ONLY"
    available = {t.type for t in finding.targets}
    for pattern, candidates in _RULES:
        if any(pattern.search(t) for t in finding.types) or pattern.search(finding.title):
            for pb in candidates:
                if set(PLAYBOOKS[pb]["target_types"]) & available:
                    return pb
    return "ESCALATE_ONLY"


# ---------------------------------------------------------------------------- decision
def select_targets(finding: Finding, playbook: str) -> List[Target]:
    wanted = set(PLAYBOOKS.get(playbook, PLAYBOOKS["ESCALATE_ONLY"])["target_types"])
    return [t for t in finding.targets if t.type in wanted and t.id]


def decide(finding: Finding, recommended_playbook: str, confidence: float,
           auto_containment_enabled: bool, model_used: bool = True) -> Decision:
    reasons: List[str] = []
    playbook = recommended_playbook if recommended_playbook in PLAYBOOKS else "ESCALATE_ONLY"
    if playbook != recommended_playbook:
        reasons.append(f"recommended playbook '{recommended_playbook}' is not allow-listed; downgraded to ESCALATE_ONLY")

    if finding.category != "threat":
        reasons.append(f"finding category '{finding.category}' is not eligible for containment; notify only")
        return Decision("NOTIFY", "ESCALATE_ONLY", [], reasons)

    if playbook == "ESCALATE_ONLY":
        reasons.append("no containment playbook applicable")
        return Decision("NOTIFY", playbook, [], reasons)

    targets = select_targets(finding, playbook)
    if not targets:
        reasons.append(f"no target of type {PLAYBOOKS[playbook]['target_types']} present in finding; notify only")
        return Decision("NOTIFY", "ESCALATE_ONLY", [], reasons)

    protected = [t for t in targets if t.protected]
    if protected:
        reasons.append("target(s) tagged rural-shield:protected=true cannot be acted upon: " + ", ".join(t.name or t.id for t in protected))
        return Decision("NOTIFY", "ESCALATE_ONLY", [], reasons)

    pb = PLAYBOOKS[playbook]
    sev_ok = pb["auto_min_severity"] is not None and SEVERITY_ORDER.get(finding.severity_label, 0) >= SEVERITY_ORDER[pb["auto_min_severity"]]
    conf_ok = (confidence >= 0.7) if model_used else True
    agrees_with_rules = rule_based_recommendation(finding) == playbook

    if auto_containment_enabled and pb["auto_allowed"] and sev_ok and conf_ok and agrees_with_rules:
        reasons.append(
            f"AUTO: reversible playbook ({pb['blast_radius']}), severity {finding.severity_label} >= {pb['auto_min_severity']}, "
            f"confidence {confidence:.2f}, model and rule-based mapping agree, operator opted in"
        )
        return Decision("AUTO", playbook, targets, reasons)

    if not auto_containment_enabled:
        reasons.append("operator disabled unattended containment")
    if not pb["auto_allowed"]:
        reasons.append(f"playbook requires human approval (blast radius: {pb['blast_radius']})")
    if pb["auto_allowed"] and not sev_ok:
        reasons.append(f"severity {finding.severity_label} below auto threshold {pb['auto_min_severity']}")
    if pb["auto_allowed"] and not conf_ok:
        reasons.append(f"model confidence {confidence:.2f} below 0.70")
    if pb["auto_allowed"] and not agrees_with_rules:
        reasons.append("model recommendation differs from rule-based mapping; a human decides")
    return Decision("APPROVAL", playbook, targets, reasons)
