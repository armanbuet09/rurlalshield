"""Copy each delivered log version to a separate immutable archive.

S3 notifications are at-least-once. The destination key identifies the source
version; retries may create identical immutable versions. Never delete sources.
"""
import hashlib
import os
from urllib.parse import quote, unquote_plus

import boto3

_s3 = boto3.client("s3")
SOURCE = os.environ["SOURCE_BUCKET"]
ARCHIVE = os.environ["ARCHIVE_BUCKET"]


def lambda_handler(event, _context):
    if event.get("Event") == "s3:TestEvent":
        return
    for record in event["Records"]:
        source = record["s3"]
        if source["bucket"]["name"] != SOURCE:
            raise ValueError("Unexpected source bucket")
        obj = source["object"]
        key, version = unquote_plus(obj["key"]), obj.get("versionId")
        if not version:
            raise ValueError("A versioned source object is required")
        # Hash keeps the destination within S3's key length limit, even for long source keys.
        identity = hashlib.sha256(f"{SOURCE}\0{key}\0{version}".encode()).hexdigest()
        _s3.copy_object(Bucket=ARCHIVE, Key=f"service-delivery/{SOURCE}/{identity}",
                        CopySource=f"{SOURCE}/{quote(key, safe='/')}?versionId={quote(version, safe='')}",
                        MetadataDirective="REPLACE", Metadata={"source-version": version,
                                                                 "source-key-sha256": hashlib.sha256(key.encode()).hexdigest()})
        # No encryption override: the destination bucket's customer-managed KMS
        # key and default Object Lock retention apply to every new archive copy.
