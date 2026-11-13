"""
RuralShield weekly posture report.

Collects posture signals (Security Hub, GuardDuty, Config, Backup, incidents) and asks Bedrock to
write a one-page plain-English brief for hospital leadership. The numbers always come from the
APIs; the model only narrates them. A deterministic template is used if the model is unavailable.
The report is also written to the WORM log archive as compliance evidence.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import boto3

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

TABLE = os.environ["INCIDENTS_TABLE"]
TOPIC_ARN = os.environ["ALERTS_TOPIC_ARN"]
ORG = os.environ.get("ORG_NAME", "the organization")
MODEL_ID = os.environ["MODEL_ID"]
GUARDRAIL_ID = os.environ.get("GUARDRAIL_ID")
GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION", "DRAFT")
ARCHIVE = os.environ.get("LOG_ARCHIVE_BUCKET")

_table = boto3.resource("dynamodb").Table(TABLE)
_sns = boto3.client("sns")
_bedrock = boto3.client("bedrock-runtime")
_sh = boto3.client("securityhub")
_gd = boto3.client("guardduty")
_config = boto3.client("config")
_backup = boto3.client("backup")
_s3 = boto3.client("s3")


def _safe(fn, default):
    try:
        return fn()
    except Exception as e:  # noqa: BLE001
        logger.warning("collector failed: %s", e)
        return default


def security_hub_summary() -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    products: Dict[str, int] = {}
    failed_controls = 0
    token = None
    pages = 0
    while pages < 10:
        kwargs: Dict[str, Any] = {
            "Filters": {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                        "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}, {"Value": "NOTIFIED", "Comparison": "EQUALS"}]},
            "MaxResults": 100,
        }
        if token:
            kwargs["NextToken"] = token
        resp = _sh.get_findings(**kwargs)
        for f in resp.get("Findings", []):
            label = f.get("Severity", {}).get("Label", "INFORMATIONAL")
            counts[label] = counts.get(label, 0) + 1
            p = f.get("ProductName", "unknown")
            products[p] = products.get(p, 0) + 1
            if f.get("Compliance", {}).get("Status") == "FAILED":
                failed_controls += 1
        token = resp.get("NextToken")
        pages += 1
        if not token:
            break
    return {"open_findings_by_severity": counts, "open_findings_by_product": products, "failed_controls": failed_controls, "truncated": bool(token)}


def guardduty_summary(since: datetime) -> Dict[str, Any]:
    detectors = _gd.list_detectors().get("DetectorIds", [])
    if not detectors:
        return {"enabled": False}
    stats = _gd.get_findings_statistics(
        DetectorId=detectors[0],
        FindingStatisticTypes=["COUNT_BY_SEVERITY"],
        FindingCriteria={"Criterion": {"updatedAt": {"Gte": int(since.timestamp() * 1000)}, "service.archived": {"Eq": ["false"]}}},
    )
    return {"enabled": True, "findings_last_7d_by_severity": stats.get("FindingStatistics", {}).get("CountBySeverity", {})}


def config_summary() -> Dict[str, Any]:
    compliant = non = 0
    worst: List[str] = []
    token = None
    while True:
        kwargs: Dict[str, Any] = {}
        if token:
            kwargs["NextToken"] = token
        resp = _config.describe_compliance_by_config_rule(**kwargs)
        for r in resp.get("ComplianceByConfigRules", []):
            if not r.get("ConfigRuleName", "").startswith("rural-shield-"):
                continue
            t = r.get("Compliance", {}).get("ComplianceType")
            if t == "COMPLIANT":
                compliant += 1
            elif t == "NON_COMPLIANT":
                non += 1
                worst.append(r["ConfigRuleName"])
        token = resp.get("NextToken")
        if not token:
            break
    total = compliant + non
    return {"rules_evaluated": total, "compliant": compliant, "non_compliant": non,
            "compliance_pct": round(100 * compliant / total, 1) if total else None, "non_compliant_rules": worst[:10]}


def backup_summary(since: datetime) -> Dict[str, Any]:
    jobs = _backup.list_backup_jobs(ByCreatedAfter=since, MaxResults=200).get("BackupJobs", [])
    restores = _backup.list_restore_jobs(ByCreatedAfter=since, MaxResults=50).get("RestoreJobs", [])
    by_state: Dict[str, int] = {}
    for j in jobs:
        by_state[j.get("State", "?")] = by_state.get(j.get("State", "?"), 0) + 1
    return {"backup_jobs_by_state": by_state,
            "restore_tests": {"total": len(restores), "completed": sum(1 for r in restores if r.get("Status") == "COMPLETED"),
                              "failed": sum(1 for r in restores if r.get("Status") in ("FAILED", "ABORTED"))}}


def incidents_summary(since: datetime) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "FilterExpression": "begins_with(sk, :t) AND created_at >= :s",
        "ExpressionAttributeValues": {":t": "TRIAGE#", ":s": since.isoformat()},
    }
    while True:
        resp = _table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    modes: Dict[str, int] = {}
    for it in items:
        m = (it.get("decision") or {}).get("action_mode", "?")
        modes[m] = modes.get(m, 0) + 1
    return {"incidents_triaged": len(items), "by_action_mode": modes,
            "model_available_pct": round(100 * sum(1 for i in items if i.get("model_used")) / len(items), 1) if items else None,
            "titles": [it.get("title", "")[:80] for it in items[:8]]}


def narrate(stats: Dict[str, Any], week: str) -> str:
    system = ("You write a one-page weekly security brief for the administrator of a small rural hospital with no security "
              "staff. Use only the numbers in the JSON. Plain English, 8th-grade level, no jargon, no speculation. Sections: "
              "'How we did this week' (3 bullets), 'What needs attention' (max 3 prioritized items with who should do it), "
              "'Backups and recovery' (1-2 sentences), 'Numbers' (a short table). Under 350 words. Do not invent anything.")
    kwargs: Dict[str, Any] = {
        "modelId": MODEL_ID,
        "system": [{"text": system}],
        "messages": [{"role": "user", "content": [{"text": f"Week of {week}. Data:\n<data>\n{json.dumps(stats, default=str)}\n</data>"}]}],
        "inferenceConfig": {"maxTokens": 900, "temperature": 0.2},
    }
    if GUARDRAIL_ID:
        kwargs["guardrailConfig"] = {"guardrailIdentifier": GUARDRAIL_ID, "guardrailVersion": GUARDRAIL_VERSION}
    resp = _bedrock.converse(**kwargs)
    return "".join(b.get("text", "") for b in resp["output"]["message"]["content"])


def template(stats: Dict[str, Any], week: str) -> str:
    sh = stats.get("security_hub", {})
    cfg = stats.get("config", {})
    bk = stats.get("backup", {})
    inc = stats.get("incidents", {})
    return f"""Weekly security brief for {ORG} - week of {week}
(AI narration unavailable; automated summary)

Open Security Hub findings by severity: {json.dumps(sh.get('open_findings_by_severity', {}))}
Failed compliance controls: {sh.get('failed_controls', 'n/a')}
HIPAA-aligned Config rules compliant: {cfg.get('compliant', 'n/a')}/{cfg.get('rules_evaluated', 'n/a')} ({cfg.get('compliance_pct', 'n/a')}%)
Non-compliant rules: {', '.join(cfg.get('non_compliant_rules', [])) or 'none'}
GuardDuty findings (7 days): {json.dumps(stats.get('guardduty', {}).get('findings_last_7d_by_severity', {}))}
Backup jobs: {json.dumps(bk.get('backup_jobs_by_state', {}))}; restore tests: {json.dumps(bk.get('restore_tests', {}))}
Incidents triaged: {inc.get('incidents_triaged', 0)} by mode {json.dumps(inc.get('by_action_mode', {}))}
"""


def lambda_handler(_event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=7)
    week = now.strftime("%Y-%m-%d")
    stats = {
        "security_hub": _safe(security_hub_summary, {"error": "unavailable"}),
        "guardduty": _safe(lambda: guardduty_summary(since), {"error": "unavailable"}),
        "config": _safe(config_summary, {"error": "unavailable"}),
        "backup": _safe(lambda: backup_summary(since), {"error": "unavailable"}),
        "incidents": _safe(lambda: incidents_summary(since), {"error": "unavailable"}),
    }
    try:
        body = narrate(stats, week)
        model_used = True
    except Exception as e:  # noqa: BLE001
        logger.error("narration failed: %s", e)
        body = template(stats, week)
        model_used = False
    footer = f"\n\n---\nGenerated by RuralShield{' with Amazon Bedrock' if model_used else ''}. Raw data:\n{json.dumps(stats, default=str, indent=1)}"
    if ARCHIVE:
        _safe(lambda: _s3.put_object(Bucket=ARCHIVE, Key=f"posture-reports/{now.strftime('%Y/%m/%d')}-weekly.md",
                                     Body=(body + footer).encode(), ContentType="text/markdown"), None)
    _sns.publish(TopicArn=TOPIC_ARN, Subject=f"[RuralShield] Weekly security brief - {ORG} - {week}"[:100], Message=body + footer)
    return {"ok": True, "model_used": model_used, "stats": stats}
