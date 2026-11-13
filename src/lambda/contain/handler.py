"""
RuralShield containment Lambda (Step Functions task).

Executes exactly one allow-listed, reversible playbook against the targets chosen by the policy
engine. Every action re-validates the allow-list and the protected tag at execution time, records
what it changed together with a roll-back command, and e-mails the outcome.
IAM permissions for this function are tag-scoped (see ai-sentinel.ts).
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

TABLE = os.environ["INCIDENTS_TABLE"]
TOPIC_ARN = os.environ["ALERTS_TOPIC_ARN"]
ORG = os.environ.get("ORG_NAME", "the organization")
PROTECTED_TAG = os.environ.get("PROTECTED_TAG", "rural-shield:protected")

ALLOWED = {
    "DEACTIVATE_IAM_ACCESS_KEY", "REVOKE_ROLE_SESSIONS", "QUARANTINE_IAM_ROLE",
    "BLOCK_S3_PUBLIC_ACCESS", "QUARANTINE_LAMBDA_FUNCTION", "REVOKE_OPEN_SECURITY_GROUP_INGRESS",
}
REVOKE_POLICY_NAME = "RuralShieldRevokeOlderSessions"
QUARANTINE_POLICY_NAME = "RuralShieldQuarantine"

_table = boto3.resource("dynamodb").Table(TABLE)
_sns = boto3.client("sns")
_iam = boto3.client("iam")
_s3 = boto3.client("s3")
_lambda = boto3.client("lambda")
_ec2 = boto3.client("ec2")
_securityhub = boto3.client("securityhub")


class Protected(Exception):
    pass


def _protected(tags: Any) -> bool:
    if isinstance(tags, dict):
        return str(tags.get(PROTECTED_TAG, "")).lower() == "true"
    for t in tags or []:
        if t.get("Key") == PROTECTED_TAG and str(t.get("Value", "")).lower() == "true":
            return True
    return False


# ------------------------------------------------------------------------- playbooks
def deactivate_access_key(target: Dict[str, Any]) -> Dict[str, Any]:
    user = target.get("extra", {}).get("user_name") or target.get("name")
    key_id = target["id"]
    if _protected(_iam.list_user_tags(UserName=user).get("Tags", [])):
        raise Protected(user)
    _iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
    return {"action": "deactivated access key", "user": user, "access_key_id": key_id,
            "rollback": f"aws iam update-access-key --user-name {user} --access-key-id {key_id} --status Active"}


def revoke_role_sessions(target: Dict[str, Any]) -> Dict[str, Any]:
    role = target.get("name") or target["id"].split("/")[-1]
    if _protected(_iam.list_role_tags(RoleName=role).get("Tags", [])):
        raise Protected(role)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*",
                                                   "Condition": {"DateLessThan": {"aws:TokenIssueTime": now}}}]}
    _iam.put_role_policy(RoleName=role, PolicyName=REVOKE_POLICY_NAME, PolicyDocument=json.dumps(doc))
    return {"action": "revoked all sessions issued before now (new assumptions still work)", "role": role, "cutoff": now,
            "rollback": f"aws iam delete-role-policy --role-name {role} --policy-name {REVOKE_POLICY_NAME}"}


def quarantine_role(target: Dict[str, Any]) -> Dict[str, Any]:
    role = target.get("name") or target["id"].split("/")[-1]
    if _protected(_iam.list_role_tags(RoleName=role).get("Tags", [])):
        raise Protected(role)
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    _iam.put_role_policy(RoleName=role, PolicyName=QUARANTINE_POLICY_NAME, PolicyDocument=json.dumps(doc))
    return {"action": "attached deny-all quarantine policy", "role": role,
            "rollback": f"aws iam delete-role-policy --role-name {role} --policy-name {QUARANTINE_POLICY_NAME}"}


def block_s3_public_access(target: Dict[str, Any]) -> Dict[str, Any]:
    bucket = target.get("name") or target["id"].replace("arn:aws:s3:::", "")
    try:
        if _protected(_s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])):
            raise Protected(bucket)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchTagSet":
            raise
    try:
        before = _s3.get_public_access_block(Bucket=bucket).get("PublicAccessBlockConfiguration", {})
    except ClientError:
        before = {}
    _s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    return {"action": "enabled S3 Block Public Access (all four settings)", "bucket": bucket, "previous": before,
            "rollback": f"aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration '{json.dumps(before)}'" if before
            else f"aws s3api delete-public-access-block --bucket {bucket}"}


def quarantine_lambda(target: Dict[str, Any]) -> Dict[str, Any]:
    arn = target["id"]
    name = target.get("name") or arn.split(":function:")[-1]
    if _protected(_lambda.list_tags(Resource=arn).get("Tags", {})):
        raise Protected(name)
    try:
        prev = _lambda.get_function_concurrency(FunctionName=name).get("ReservedConcurrentExecutions")
    except ClientError:
        prev = None
    _lambda.put_function_concurrency(FunctionName=name, ReservedConcurrentExecutions=0)
    rollback = (f"aws lambda put-function-concurrency --function-name {name} --reserved-concurrent-executions {prev}"
                if prev is not None else f"aws lambda delete-function-concurrency --function-name {name}")
    return {"action": "set reserved concurrency to 0 (function cannot run)", "function": name, "previous_concurrency": prev, "rollback": rollback}


def revoke_open_sg_ingress(target: Dict[str, Any]) -> Dict[str, Any]:
    gid = target.get("name") if str(target.get("name", "")).startswith("sg-") else target["id"].split("/")[-1]
    sg = _ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]
    if _protected(sg.get("Tags", [])):
        raise Protected(gid)
    removed: List[Dict[str, Any]] = []
    for perm in sg.get("IpPermissions", []):
        open_v4 = [r for r in perm.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
        open_v6 = [r for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]
        if not (open_v4 or open_v6):
            continue
        to_revoke = {k: v for k, v in perm.items() if k in ("IpProtocol", "FromPort", "ToPort")}
        if open_v4:
            to_revoke["IpRanges"] = open_v4
        if open_v6:
            to_revoke["Ipv6Ranges"] = open_v6
        _ec2.revoke_security_group_ingress(GroupId=gid, IpPermissions=[to_revoke])
        removed.append(to_revoke)
    return {"action": "removed world-open ingress rules", "security_group": gid, "removed_rules": removed,
            "rollback": f"aws ec2 authorize-security-group-ingress --group-id {gid} --ip-permissions '{json.dumps(removed)}'" if removed else "nothing removed"}


PLAYBOOK_IMPL = {
    "DEACTIVATE_IAM_ACCESS_KEY": deactivate_access_key,
    "REVOKE_ROLE_SESSIONS": revoke_role_sessions,
    "QUARANTINE_IAM_ROLE": quarantine_role,
    "BLOCK_S3_PUBLIC_ACCESS": block_s3_public_access,
    "QUARANTINE_LAMBDA_FUNCTION": quarantine_lambda,
    "REVOKE_OPEN_SECURITY_GROUP_INGRESS": revoke_open_sg_ingress,
}


# --------------------------------------------------------------------------- handler
def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    triage = event.get("triage", {})
    incident_id = triage.get("incident_id", "unknown")
    playbook = triage.get("playbook", "")
    approved_by = (event.get("approval") or {}).get("decided_by") or ("policy (AUTO)" if triage.get("action_mode") == "AUTO" else "unknown")
    if playbook not in ALLOWED:
        raise ValueError(f"playbook {playbook} is not allow-listed")  # defense in depth: SFN should never route here
    results: List[Dict[str, Any]] = []
    errors: List[str] = []
    for target in triage.get("targets", []):
        try:
            results.append(PLAYBOOK_IMPL[playbook](target))
        except Protected as p:
            errors.append(f"refused: {p} is tagged {PROTECTED_TAG}=true")
        except ClientError as e:
            errors.append(f"{target.get('name') or target.get('id')}: {e.response['Error']['Code']} {e.response['Error'].get('Message', '')}"[:300])
        except Exception as e:  # noqa: BLE001
            errors.append(f"{target.get('name') or target.get('id')}: {type(e).__name__}: {e}"[:300])

    now = datetime.now(timezone.utc)
    status = "CONTAINED" if results and not errors else ("PARTIAL" if results else "FAILED")
    _table.put_item(Item=json.loads(json.dumps({
        "pk": f"INCIDENT#{incident_id}", "sk": f"CONTAIN#{now.isoformat()}",
        "playbook": playbook, "approved_by": approved_by, "results": results, "errors": errors, "status": status,
        "ttl": int((now + timedelta(days=6 * 365)).timestamp()),
    }, default=str)))

    finding = triage.get("finding", {})
    if finding.get("source") == "securityhub" and finding.get("product_arn"):
        try:
            _securityhub.batch_update_findings(
                FindingIdentifiers=[{"Id": finding["id"], "ProductArn": finding["product_arn"]}],
                Note={"Text": f"RuralShield {incident_id}: {playbook} -> {status} ({approved_by})"[:512], "UpdatedBy": "rural-shield"},
                Workflow={"Status": "NOTIFIED"},
            )
        except Exception as e:  # noqa: BLE001
            logger.warning("security hub annotation failed: %s", e)

    lines = [f"RuralShield containment result for {ORG}", f"Incident: {incident_id}", f"Playbook: {playbook}", f"Authorized by: {approved_by}", f"Status: {status}", ""]
    for r in results:
        lines.append(f"- {r['action']}")
        lines.append("  details: " + json.dumps({k: v for k, v in r.items() if k not in ('action', 'rollback')}, default=str))
        lines.append(f"  ROLL BACK WITH: {r['rollback']}")
    for e in errors:
        lines.append(f"- ERROR: {e}")
    lines += ["", "Next: confirm with the affected user/vendor, rotate any credentials involved, and keep this e-mail with your incident record.",
              "If the action was a mistake, run the roll-back command above (it restores the previous state)."]
    try:
        _sns.publish(TopicArn=TOPIC_ARN, Subject=f"[RuralShield] {status}: {playbook} ({incident_id})"[:100], Message="\n".join(lines))
    except Exception as e:  # noqa: BLE001
        logger.error("result publish failed: %s", e)
    return {"status": status, "results": results, "errors": errors}
