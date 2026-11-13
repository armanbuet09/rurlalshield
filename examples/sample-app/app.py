"""
Minimal example workload: a FHIR-flavoured patient-record API behind RuralShield.
Replace this directory with your own code; RuralShield provides TABLE_NAME / PHI_BUCKET / DB_* env vars.
Only the Python standard library and boto3 (bundled in the Lambda runtime) are used.
"""
import json
import os
import uuid
from datetime import datetime, timezone

import boto3

TABLE = os.environ.get("TABLE_NAME")
BUCKET = os.environ.get("PHI_BUCKET")
_dynamo = boto3.resource("dynamodb").Table(TABLE) if TABLE else None
_s3 = boto3.client("s3")


def _resp(status, body):
    return {"statusCode": status, "headers": {"Content-Type": "application/fhir+json", "Cache-Control": "no-store",
                                             "X-Content-Type-Options": "nosniff", "Strict-Transport-Security": "max-age=31536000"},
            "body": json.dumps(body)}


def _caller(event):
    # Cognito authorizer puts the verified JWT claims here; use them for fine-grained authorization.
    return (event.get("requestContext", {}).get("authorizer", {}) or {}).get("claims", {}) or {}


def handler(event, _context):
    path = event.get("path", "/")
    method = event.get("httpMethod", "GET")
    claims = _caller(event)

    if path == "/health":
        return _resp(200, {"status": "ok", "time": datetime.now(timezone.utc).isoformat()})

    if path.startswith("/Patient") and method == "GET":
        patient_id = path.split("/")[-1] if path != "/Patient" else None
        if not patient_id or not _dynamo:
            return _resp(400, {"resourceType": "OperationOutcome", "issue": [{"severity": "error", "code": "invalid"}]})
        item = _dynamo.get_item(Key={"pk": f"PATIENT#{patient_id}", "sk": "DEMOGRAPHICS"}).get("Item")
        if not item:
            return _resp(404, {"resourceType": "OperationOutcome", "issue": [{"severity": "error", "code": "not-found"}]})
        # Every PHI read is attributable to a verified user (HIPAA audit controls).
        _dynamo.put_item(Item={"pk": f"PATIENT#{patient_id}", "sk": f"ACCESS#{datetime.now(timezone.utc).isoformat()}",
                               "by": claims.get("email", "unknown"), "action": "read"})
        return _resp(200, item.get("resource", {}))

    if path == "/Patient" and method == "POST" and _dynamo:
        body = json.loads(event.get("body") or "{}")
        patient_id = body.get("id") or str(uuid.uuid4())
        _dynamo.put_item(Item={"pk": f"PATIENT#{patient_id}", "sk": "DEMOGRAPHICS", "resource": body, "created_by": claims.get("email", "unknown")})
        return _resp(201, {"resourceType": "Patient", "id": patient_id})

    if path == "/DocumentReference" and method == "POST" and BUCKET:
        # Pre-signed upload; the object is malware-scanned by GuardDuty before the app may read it back.
        key = f"documents/{uuid.uuid4()}.pdf"
        url = _s3.generate_presigned_url("put_object", Params={"Bucket": BUCKET, "Key": key, "ContentType": "application/pdf"}, ExpiresIn=300)
        return _resp(201, {"resourceType": "DocumentReference", "uploadUrl": url, "key": key})

    return _resp(404, {"resourceType": "OperationOutcome", "issue": [{"severity": "error", "code": "not-found"}]})
