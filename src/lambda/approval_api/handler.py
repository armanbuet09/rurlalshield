"""
RuralShield approval endpoint: GET /decision?id=...&action=approve|deny&sig=...

Verifies the HMAC, enforces single use with a conditional write, resumes the waiting
Step Functions execution and renders a minimal confirmation page.
"""
from __future__ import annotations

import hashlib
import hmac
from html import escape
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

TABLE = os.environ["INCIDENTS_TABLE"]
SECRET_ARN = os.environ["SIGNING_SECRET_ARN"]
ORG = os.environ.get("ORG_NAME", "the organization")

_table = boto3.resource("dynamodb").Table(TABLE)
_sfn = boto3.client("stepfunctions")
_secrets = boto3.client("secretsmanager")

HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}


def expected_sig(approval_id: str, action: str, version: str) -> str:
    key = _secrets.get_secret_value(SecretId=SECRET_ARN, VersionId=version)["SecretString"].encode()
    return hmac.new(key, f"{approval_id}:{action}".encode(), hashlib.sha256).hexdigest()[:40]


def page(status: int, title: str, message: str) -> Dict[str, Any]:
    title, message = escape(title), escape(message)
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>RuralShield</title>
<style>body{{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#1f2937}}
h1{{font-size:1.4rem}} .ok{{color:#065f46}} .bad{{color:#991b1b}}</style></head>
<body><h1 class="{'ok' if status == 200 else 'bad'}">{title}</h1><p>{message}</p>
<p style="color:#6b7280;font-size:.9rem">RuralShield for {escape(ORG)}. You can close this window.</p></body></html>"""
    return {"statusCode": status, "headers": HEADERS, "body": html}


def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    qs = event.get("queryStringParameters") or {}
    approval_id = str(qs.get("id", ""))
    action = str(qs.get("action", "")).lower()
    sig = str(qs.get("sig", ""))
    if not (approval_id.isalnum() and len(approval_id) == 32 and action in ("approve", "deny") and len(sig) == 40):
        return page(400, "Invalid link", "This approval link is malformed.")
    now = datetime.now(timezone.utc)
    request = _table.get_item(Key={"pk": f"APPROVAL#{approval_id}", "sk": "REQUEST"}, ConsistentRead=True).get("Item", {})
    if request.get("status") != "PENDING" or request.get("expires_at", "") <= now.isoformat():
        return page(410, "Link already used or expired", "The approval window closed or a decision was already recorded.")
    version = request.get("signing_key_version")
    if not version or not hmac.compare_digest(sig, expected_sig(approval_id, action, version)):
        logger.warning("bad signature for approval %s", approval_id)
        return page(403, "Invalid link", "This approval link is not valid.")

    try:
        resp = _table.update_item(
            Key={"pk": f"APPROVAL#{approval_id}", "sk": "REQUEST"},
            UpdateExpression="SET #s = :decided, decided_at = :now, decision = :d, decided_via = :via",
            ConditionExpression="#s = :pending AND expires_at > :now",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":decided": "DECIDED", ":pending": "PENDING", ":now": now.isoformat(),
                                       ":d": action, ":via": "email-link"},
            ReturnValues="ALL_NEW",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return page(410, "Link already used or expired", "A decision was already recorded for this incident, or the approval window closed.")
        raise
    item = resp["Attributes"]
    approved = action == "approve"
    try:
        _sfn.send_task_success(
            taskToken=item["task_token"],
            output=json.dumps({"approved": approved, "decided_by": "email-link", "decided_at": now.isoformat(), "approval_id": approval_id}),
        )
    except ClientError as e:
        if e.response["Error"]["Code"] in ("TaskTimedOut", "TaskDoesNotExist"):
            return page(410, "Approval window closed", "The incident workflow already timed out; RuralShield has escalated it by e-mail.")
        raise
    _table.put_item(Item={
        "pk": f"INCIDENT#{item.get('incident_id', 'unknown')}",
        "sk": f"DECISION#{now.isoformat()}",
        "approval_id": approval_id,
        "approved": approved,
        "decided_via": "email-link",
        "source_ip": (event.get("requestContext", {}).get("identity", {}) or {}).get("sourceIp", ""),
        "user_agent": (event.get("requestContext", {}).get("identity", {}) or {}).get("userAgent", "")[:200],
        "ttl": int(now.timestamp()) + 6 * 365 * 86400,
    })
    if approved:
        return page(200, "Approved", f"RuralShield is now running {item.get('playbook')} for incident {item.get('incident_id')}. "
                                      "A confirmation e-mail with the result and roll-back instructions will follow.")
    return page(200, "Declined", f"No automated action will be taken for incident {item.get('incident_id')}. The finding remains open in Security Hub.")
