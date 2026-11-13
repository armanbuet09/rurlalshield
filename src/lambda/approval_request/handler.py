"""
RuralShield approval request (Step Functions task with .waitForTaskToken).

Stores the task token under a random approval id and e-mails single-use, HMAC-signed
Approve / Decline links. The approver never needs an AWS login; the link is the credential,
it is bound to one incident + one action, and it expires with the Step Functions task timeout.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import boto3

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

TABLE = os.environ["INCIDENTS_TABLE"]
TOPIC_ARN = os.environ["ALERTS_TOPIC_ARN"]
ORG = os.environ.get("ORG_NAME", "the organization")
SECRET_ARN = os.environ["SIGNING_SECRET_ARN"]
BASE_URL = os.environ.get("APPROVAL_BASE_URL", "").rstrip("/") + "/"
TIMEOUT_HOURS = int(os.environ.get("APPROVAL_TIMEOUT_HOURS", "24"))

_table = boto3.resource("dynamodb").Table(TABLE)
_sns = boto3.client("sns")
_secrets = boto3.client("secretsmanager")


def sign(key: bytes, approval_id: str, action: str) -> str:
    return hmac.new(key, f"{approval_id}:{action}".encode(), hashlib.sha256).hexdigest()[:40]


def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    token = event["taskToken"]
    incident = event.get("incident", {})
    triage = incident.get("triage", {})
    incident_id = triage.get("incident_id", "unknown")
    approval_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=TIMEOUT_HOURS)
    # Pin each request to one version. Rotation must not invalidate pending links,
    # and a warm Lambda must start using AWSCURRENT for the next request.
    secret = _secrets.get_secret_value(SecretId=SECRET_ARN, VersionStage="AWSCURRENT")
    key = secret["SecretString"].encode()

    _table.put_item(Item={
        "pk": f"APPROVAL#{approval_id}",
        "sk": "REQUEST",
        "incident_id": incident_id,
        "task_token": token,
        "signing_key_version": secret["VersionId"],
        "playbook": triage.get("playbook"),
        "targets": triage.get("targets", []),
        "status": "PENDING",
        "requested_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "ttl": int((expires + timedelta(days=30)).timestamp()),
    })
    _table.put_item(Item={
        "pk": f"INCIDENT#{incident_id}",
        "sk": f"APPROVAL_REQUESTED#{now.isoformat()}",
        "approval_id": approval_id,
        "status": "AWAITING_APPROVAL",
        "ttl": int((now + timedelta(days=6 * 365)).timestamp()),
    })

    approve_url = f"{BASE_URL}decision?id={approval_id}&action=approve&sig={sign(key, approval_id, 'approve')}"
    deny_url = f"{BASE_URL}decision?id={approval_id}&action=deny&sig={sign(key, approval_id, 'deny')}"
    targets = ", ".join(t.get("name") or t.get("id") for t in triage.get("targets", [])) or "n/a"
    body = f"""RuralShield needs your decision for {ORG}
Incident: {incident_id}
Finding: {triage.get('title', '')}

{triage.get('summary', '')}

PROPOSED ACTION: {triage.get('playbook')}
Target(s): {targets}
This action is reversible. If you decline, nothing changes and the finding stays open for you.

APPROVE (run the action now):
{approve_url}

DECLINE (do nothing automated):
{deny_url}

These links work once and expire at {expires.strftime('%Y-%m-%d %H:%M UTC')}. If no decision is made,
RuralShield takes no action and escalates by e-mail. Forward this message to a colleague if you are unsure.

Why the system did not act on its own:
""" + "\n".join(f"  - {r}" for r in triage.get("reasons", []))

    _sns.publish(TopicArn=TOPIC_ARN, Subject=f"[RuralShield] APPROVAL NEEDED: {triage.get('title', '')}"[:100], Message=body)
    logger.info("approval %s requested for incident %s", approval_id, incident_id)
    return {"approval_id": approval_id, "expires_at": expires.isoformat()}
