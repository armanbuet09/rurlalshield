"""Read closeout receipts and optionally download the paper's private evidence.

This script never stops services. Use --download for a local, hash-indexed copy.
"""
import concurrent.futures
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'cdk.out/python-tools'))
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

state = json.loads((ROOT / 'cdk.out/observation-state.json').read_text())
session = boto3.Session(profile_name='ruralshield-research', region_name='us-east-2')
s3 = session.client('s3', config=Config(max_pool_connections=32, retries={'mode': 'standard', 'max_attempts': 5}))
bucket = state['outputs']['EvidenceBucket']
out = ROOT / 'cdk.out/closeout'
out.mkdir(exist_ok=True)
receipts = {}
for name in ['archive-verified', 'latest', 'completed', 'local-retirement']:
    try:
        body = s3.get_object(Bucket=bucket, Key='closeout/' + name + '.json')['Body'].read()
        receipts[name] = json.loads(body)
        (out / (name + '.json')).write_bytes(body)
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchKey':
            raise

try:
    schedule = session.client('scheduler').get_schedule(Name='ruralshield-nonai-closeout')
    schedule_info = {k: schedule.get(k) for k in ['State', 'StartDate', 'EndDate', 'ScheduleExpression']}
except ClientError as e:
    if e.response['Error']['Code'] != 'ResourceNotFoundException':
        raise
    schedule_info = {'State': 'ABSENT'}

download_count = None
retirement = receipts.get('local-retirement', {})
local_verification = None
if '--download' in sys.argv and retirement.get('executed'):
    from paper_evidence import verify_local
    _, local_verification = verify_local(Path(retirement['archive']))
elif '--download' in sys.argv:
    target = (out / 'preserved-evidence').resolve()
    objects = []
    for prefix in ['freeze/', 'minutes/', 'control/', 'closeout/']:
        for page in s3.get_paginator('list_objects_v2').paginate(Bucket=bucket, Prefix=prefix):
            objects.extend(page.get('Contents', []))

    def download(obj):
        destination = (target / obj['Key']).resolve()
        if not destination.is_relative_to(target):
            raise RuntimeError('Unsafe object path')
        response = s3.get_object(Bucket=bucket, Key=obj['Key'])
        body = response['Body'].read()
        digest = hashlib.sha256(body).hexdigest()
        if response.get('Metadata', {}).get('sha256', digest) != digest:
            raise RuntimeError('Remote evidence checksum mismatch: ' + obj['Key'])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
        if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Local evidence checksum mismatch')
        return {'key': obj['Key'], 'versionId': response.get('VersionId'), 'sha256': digest,
                'bytes': len(body), 'etag': response.get('ETag')}

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        index = list(executor.map(download, objects))
    expected = {x['key']: x['sha256'] for x in receipts.get('archive-verified', {}).get('objects', [])}
    actual = {x['key']: x['sha256'] for x in index}
    if any(actual.get(key) != digest for key, digest in expected.items()):
        raise RuntimeError('Downloaded files do not match the final archive manifest')
    (out / 'download-index.json').write_text(json.dumps({'bucket': bucket, 'objects': index}, indent=2))
    download_count = len(index)

completed = receipts.get('completed')
summary = {'schedule': schedule_info, 'archiveVerified': 'archive-verified' in receipts,
           'shutdownVerified': bool(completed and completed.get('checks') and all(completed['checks'].values())),
           'checks': receipts.get('latest', {}).get('checks'), 'downloadedObjects': download_count,
           'duplicateRetirement': retirement.get('phase'), 'localArchive': retirement.get('archive'),
           'localVerification': local_verification,
           'retainedCosts': 'KMS keys, locked S3/backups, small control receipts and any not-yet-retired storage remain billable; not zero cost.'}
(out / 'checked-status.json').write_text(json.dumps(summary, indent=2, default=str))
print(json.dumps(summary, indent=2, default=str))
