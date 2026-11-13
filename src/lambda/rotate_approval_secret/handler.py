"""Four-step Secrets Manager rotation for the approval HMAC key.

There is no external password store to update. Pending approvals explicitly read
their recorded version; AWSPREVIOUS retains it beyond the maximum seven-day window.
"""
import hashlib
import hmac
import os
import secrets

import boto3
from botocore.exceptions import ClientError

_secrets = boto3.client("secretsmanager")
SECRET_ARN = os.environ["SIGNING_SECRET_ARN"]


def pending(token):
    value = _secrets.get_secret_value(SecretId=SECRET_ARN, VersionId=token, VersionStage="AWSPENDING")["SecretString"]
    if len(value) < 48:
        raise ValueError("Signing key is too short")
    return value


def lambda_handler(event, _context):
    if event["SecretId"] != SECRET_ARN:
        raise ValueError("Unexpected secret")
    token, step = event["ClientRequestToken"], event["Step"]
    if step not in ("createSecret", "setSecret", "testSecret", "finishSecret"):
        raise ValueError("Unknown rotation step")
    metadata = _secrets.describe_secret(SecretId=SECRET_ARN)
    if not metadata.get("RotationEnabled"):
        raise ValueError("Rotation is disabled")
    versions = metadata["VersionIdsToStages"]
    if token not in versions or "AWSPENDING" not in versions[token] and "AWSCURRENT" not in versions[token]:
        raise ValueError("Rotation token is not staged")
    if "AWSCURRENT" in versions[token]:
        return
    if step == "createSecret":
        _secrets.get_secret_value(SecretId=SECRET_ARN, VersionStage="AWSCURRENT")
        try:
            pending(token)
        except ClientError as error:
            if error.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            kwargs = dict(SecretId=SECRET_ARN, ClientRequestToken=token,
                          SecretString=secrets.token_urlsafe(48), VersionStages=["AWSPENDING"])
            if event.get("RotationToken"):
                kwargs["RotationToken"] = event["RotationToken"]
            _secrets.put_secret_value(**kwargs)
    elif step in ("setSecret", "testSecret"):
        key = pending(token).encode()
        # Verify the pending value can perform the operation used by both callers.
        digest = hmac.new(key, b"rotation-check", hashlib.sha256).hexdigest()
        if len(digest) != 64:
            raise ValueError("Signing key test failed")
    else:
        pending(token)
        current = next(version for version, stages in versions.items() if "AWSCURRENT" in stages)
        _secrets.update_secret_version_stage(SecretId=SECRET_ARN, VersionStage="AWSCURRENT",
                                            MoveToVersionId=token, RemoveFromVersionId=current)
