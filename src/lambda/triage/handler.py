"""
RuralShield triage Lambda (Step Functions task 1).

Input : EventBridge event (Security Hub ASFF or GuardDuty native finding)
Output: dict stored at $.triage and consumed by the RouteByPolicy choice state.
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

import policy
import prompts

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

TABLE = os.environ["INCIDENTS_TABLE"]
TOPIC_ARN = os.environ["ALERTS_TOPIC_ARN"]
ORG = os.environ.get("ORG_NAME", "the organization")
MODEL_ID = os.environ["MODEL_ID"]
GUARDRAIL_ID = os.environ.get("GUARDRAIL_ID")
GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION", "DRAFT")
AUTO = os.environ.get("AUTO_CONTAINMENT", "false").lower() == "true"
PROTECTED_TAG = os.environ.get("PROTECTED_TAG", "rural-shield:protected")
INCIDENT_TTL_DAYS = 6 * 365  # keep the audit trail for the HIPAA documentation period

_dynamo = boto3.resource("dynamodb")
_table = _dynamo.Table(TABLE)
_sns = boto3.client("sns")
_bedrock = boto3.client("bedrock-runtime")
_securityhub = boto3.client("securityhub")
_iam = boto3.client("iam")
_lambda = boto3.client("lambda")
_s3 = boto3.client("s3")
_cloudtrail = boto3.client("cloudtrail")


# ------------------------------------------------------------------------- enrichment
def _tags_say_protected(tags: List[Dict[str, str]]) -> bool:
    for t in tags or []:
        if t.get("Key") == PROTECTED_TAG and str(t.get("Value", "")).lower() == "true":
            return True
    return False


def enrich(finding: policy.Finding) -> Dict[str, Any]:
    """Best-effort, read-only context. Any failure is logged and ignored."""
    ctx: Dict[str, Any] = {"recent_api_activity": [], "notes": []}
    for t in finding.targets:
        try:
            if t.type == "iam-access-key" and t.extra.get("user_name"):
                tags = _iam.list_user_tags(UserName=t.extra["user_name"]).get("Tags", [])
                t.protected = _tags_say_protected(tags)
                keys = _iam.list_access_keys(UserName=t.extra["user_name"]).get("AccessKeyMetadata", [])
                t.extra["key_status"] = next((k["Status"] for k in keys if k["AccessKeyId"] == t.id), "unknown")
            elif t.type == "iam-role" and t.name:
                tags = _iam.list_role_tags(RoleName=t.name).get("Tags", [])
                t.protected = _tags_say_protected(tags)
            elif t.type == "lambda-function" and t.id.startswith("arn:"):
                tags = _lambda.list_tags(Resource=t.id).get("Tags", {})
                t.protected = str(tags.get(PROTECTED_TAG, "")).lower() == "true"
            elif t.type == "s3-bucket" and t.name:
                try:
                    tagset = _s3.get_bucket_tagging(Bucket=t.name).get("TagSet", [])
                    t.protected = _tags_say_protected(tagset)
                    t.extra["data_classification"] = next((x["Value"] for x in tagset if x["Key"] == "DataClassification"), "")
                except ClientError as e:
                    if e.response["Error"]["Code"] != "NoSuchTagSet":
                        raise
                pab = _s3.get_public_access_block(Bucket=t.name).get("PublicAccessBlockConfiguration", {})
                t.extra["public_access_block"] = pab
        except Exception as e:  # noqa: BLE001 - enrichment must never break triage
            ctx["notes"].append(f"enrichment skipped for {t.type} {t.name or t.id}: {type(e).__name__}")
            if t.protected is None:
                t.protected = False

    # Last few CloudTrail events for the implicated principal give the model (and the human) timeline context.
    principal = next((t.extra.get("user_name") or t.name for t in finding.targets if t.type in ("iam-access-key", "iam-user", "iam-role")), None)
    if principal:
        try:
            resp = _cloudtrail.lookup_events(
                LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": principal}],
                StartTime=datetime.now(timezone.utc) - timedelta(hours=24),
                MaxResults=10,
            )
            for ev in resp.get("Events", []):
                ctx["recent_api_activity"].append({
                    "time": ev.get("EventTime").isoformat() if ev.get("EventTime") else "",
                    "event": ev.get("EventName"),
                    "source": ev.get("EventSource"),
                    "resources": [r.get("ResourceName") for r in ev.get("Resources", [])][:3],
                })
        except Exception as e:  # noqa: BLE001
            ctx["notes"].append(f"cloudtrail lookup skipped: {type(e).__name__}")
    return ctx


# ------------------------------------------------------------------------------ model
def call_model(finding: policy.Finding, context: Dict[str, Any]) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "modelId": MODEL_ID,
        "system": [{"text": prompts.SYSTEM_PROMPT}],
        "messages": [{"role": "user", "content": [{"text": prompts.build_user_message(finding, context)}]}],
        "inferenceConfig": {"maxTokens": 1500, "temperature": 0.1},
        "toolConfig": {"tools": [prompts.RECORD_TRIAGE_TOOL], "toolChoice": {"tool": {"name": "record_triage"}}},
    }
    if GUARDRAIL_ID:
        kwargs["guardrailConfig"] = {"guardrailIdentifier": GUARDRAIL_ID, "guardrailVersion": GUARDRAIL_VERSION, "trace": "enabled"}
    resp = _bedrock.converse(**kwargs)
    usage = resp.get("usage", {})
    if resp.get("stopReason") == "guardrail_intervened":
        raise RuntimeError("guardrail_intervened")
    for block in resp.get("output", {}).get("message", {}).get("content", []):
        if "toolUse" in block and block["toolUse"].get("name") == "record_triage":
            out = dict(block["toolUse"]["input"])
            out["_usage"] = {"input_tokens": usage.get("inputTokens"), "output_tokens": usage.get("outputTokens")}
            return out
    raise RuntimeError("model did not call record_triage")


# --------------------------------------------------------------------------- persistence
def record(incident_id: str, finding: policy.Finding, assessment: Dict[str, Any], decision: policy.Decision,
           model_used: bool, latency_ms: int, context: Dict[str, Any]) -> None:
    now = datetime.now(timezone.utc)
    item = {
        "pk": f"INCIDENT#{incident_id}",
        "sk": f"TRIAGE#{now.isoformat()}",
        "incident_id": incident_id,
        "created_at": now.isoformat(),
        "finding_id": finding.finding_id,
        "source": finding.source,
        "product": finding.product,
        "category": finding.category,
        "severity": finding.severity_label,
        "title": finding.title,
        "types": finding.types,
        "targets": [t.to_dict() for t in finding.targets],
        "assessment": assessment,
        "decision": decision.to_dict(),
        "model_used": model_used,
        "model_id": MODEL_ID if model_used else None,
        "triage_latency_ms": latency_ms,
        "enrichment_notes": context.get("notes", []),
        "status": "TRIAGED",
        "ttl": int((now + timedelta(days=INCIDENT_TTL_DAYS)).timestamp()),
    }
    _table.put_item(Item=json.loads(json.dumps(item, default=str), parse_float=Decimal))


def annotate_security_hub(finding: policy.Finding, incident_id: str, decision: policy.Decision) -> None:
    if finding.source != "securityhub" or not finding.product_arn:
        return
    try:
        _securityhub.batch_update_findings(
            FindingIdentifiers=[{"Id": finding.finding_id, "ProductArn": finding.product_arn}],
            Note={"Text": f"RuralShield incident {incident_id}: {decision.action_mode} / {decision.playbook}"[:512], "UpdatedBy": "rural-shield"},
            Workflow={"Status": "NOTIFIED"},  # never SUPPRESSED or RESOLVED by automation
        )
    except Exception as e:  # noqa: BLE001
        logger.warning("security hub annotation failed: %s", e)


# ------------------------------------------------------------------------------ handler
def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    started = time.time()
    incident_id = f"RS-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
    finding = policy.normalize_finding(event)
    logger.info("triage %s: %s [%s/%s]", incident_id, finding.title, finding.product, finding.severity_label)

    context = enrich(finding)

    model_used = True
    try:
        assessment = call_model(finding, context)
    except Exception as e:  # noqa: BLE001 - degrade gracefully, never drop the finding
        logger.error("model call failed (%s); using rule-based fallback", e)
        model_used = False
        assessment = prompts.fallback_assessment(finding, policy.rule_based_recommendation(finding))

    recommended = str(assessment.get("recommended_playbook", "ESCALATE_ONLY"))
    confidence = float(assessment.get("confidence", 0) or 0)
    decision = policy.decide(finding, recommended, confidence, AUTO, model_used=model_used)

    latency_ms = int((time.time() - started) * 1000)
    record(incident_id, finding, assessment, decision, model_used, latency_ms, context)
    annotate_security_hub(finding, incident_id, decision)

    title = f"{finding.severity_label}: {finding.title}"[:90]
    body = prompts.email_body(ORG, finding, assessment, decision.to_dict(), incident_id, model_used)
    try:
        _sns.publish(TopicArn=TOPIC_ARN, Subject=f"[RuralShield] {title}"[:100], Message=body)
    except Exception as e:  # noqa: BLE001
        logger.error("alert publish failed: %s", e)

    return {
        "incident_id": incident_id,
        "title": title,
        "action_mode": decision.action_mode,
        "playbook": decision.playbook,
        "targets": [t.to_dict() for t in decision.targets],
        "reasons": decision.reasons,
        "summary": assessment.get("plain_english_summary", ""),
        "confidence": confidence,
        "model_used": model_used,
        "finding": {
            "id": finding.finding_id, "product_arn": finding.product_arn, "source": finding.source,
            "severity": finding.severity_label, "category": finding.category, "title": finding.title,
        },
        "email_body": body,
        "triage_latency_ms": latency_ms,
    }
