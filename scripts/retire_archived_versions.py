"""Batch exact immutable versions only after the caller's archive/ownership gate.

This module does not discover targets or open an AWS session. A caller must
independently verify its archive, ownership and current version inventory first.
Every batch rechecks bucket Object Lock and records confirmed per-version results
before raising on a partial/ambiguous service response.
"""


def require_unlocked(client, bucket):
    try:
        config = client.get_object_lock_configuration(Bucket=bucket)
    except Exception as error:
        code = getattr(error, 'response', {}).get('Error', {}).get('Code')
        if code not in ('ObjectLockConfigurationNotFoundError', 'NoSuchObjectLockConfiguration'):
            raise
        config = {}
    if config.get('ObjectLockConfiguration', {}).get('ObjectLockEnabled') == 'Enabled':
        raise ValueError('Object Lock bucket cannot be retired')


def delete_verified_batches(client, bucket, versions, record):
    """Delete a prechecked exact list, ≤1000 per request; no mutable null versions.

    record(key, version_id) is an append-only durable journal callback. Explicit
    VersionId makes retransmission idempotent. Missing result identities and
    per-object errors are failures even when the HTTP request returned success.
    """
    expected = set()
    for item in versions:
        key, version = item.get('Key'), item.get('VersionId')
        if not isinstance(key, str) or not key or not isinstance(version, str) or not version or version == 'null':
            raise ValueError('Only explicit immutable version identities may be retired')
        if (key, version) in expected:
            raise ValueError('Duplicate version in retirement batch')
        expected.add((key, version))
    removed = 0
    for offset in range(0, len(versions), 1000):
        batch = versions[offset:offset + 1000]
        requested = {(x['Key'], x['VersionId']) for x in batch}
        require_unlocked(client, bucket)
        response = client.delete_objects(Bucket=bucket, Delete={'Objects': batch, 'Quiet': False})
        identities = [(x.get('Key'), x.get('VersionId')) for x in response.get('Deleted', [])]
        confirmed = set(identities) & requested
        for key, version in sorted(confirmed):
            record(key, version)
        removed += len(confirmed)
        if (response.get('Errors') or set(identities) != requested
                or len(identities) != len(requested)):
            raise ValueError('Partial or ambiguous S3 retirement response; inspect durable action journal')
    return removed
