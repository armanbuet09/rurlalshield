"""Local paper archive and conservative retirement of verified redundant copies.

No credentials are exported. No KMS key, protected object or recovery point is
deleted. AWS-native closeout remains independent of this local second stage.
"""
import concurrent.futures
import gzip
import hashlib
import json
import shutil
import sys
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from evidence_log_checks import recheck_logs
from local_aws_session import configure_process_refresh
from retire_archived_versions import delete_verified_batches

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'cdk.out/python-tools'))


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def safe_path(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Unsafe archive path')
    base = root.resolve()
    result = base / relative
    if not result.is_relative_to(base):
        raise ValueError('Archive path leaves its directory')
    # Resolve the trusted root once; do not race concurrent creation of children.
    current = base
    for part in relative.parts:
        current = current / part
        if current.is_symlink() or current.is_junction():
            raise ValueError('Archive child is a link or junction')
    return result


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), default=str).encode()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode(value))


def validate_final(manifest, now):
    if manifest.get('stage') != 'final':
        raise ValueError('A running-test checkpoint cannot authorize cleanup')
    if now < datetime.fromisoformat(manifest['window']['endAt']) + timedelta(hours=24):
        raise ValueError('Wait until at least 24 hours after the frozen test end')
    receipt = manifest.get('nativeCloseout', {})
    if not receipt.get('checks') or not all(receipt['checks'].values()):
        raise ValueError('AWS-native service shutdown must be verified first')
    if not manifest.get('finalGateVerified'):
        raise ValueError('Final AWS evidence manifest was not verified locally')
    if not receipt.get('at'):
        raise ValueError('Missing native closeout timestamp')
    if now < datetime.fromisoformat(receipt['at']) + timedelta(hours=24):
        raise ValueError('Wait until at least 24 hours after native closeout for late data')
    native_object = manifest.get('nativeCloseoutObject') or {}
    if not native_object.get('lastModified') or not native_object.get('sha256'):
        raise ValueError('Missing native closeout receipt object timestamp or checksum')
    if native_object.get('documentSha256') != hashlib.sha256(encode(receipt)).hexdigest():
        raise ValueError('Native closeout receipt object metadata does not match its document')
    if now < datetime.fromisoformat(native_object['lastModified']) + timedelta(hours=24):
        raise ValueError('Wait until at least 24 hours after the native closeout receipt was written')


def verify_local(folder):
    folder = folder.resolve()
    manifest = json.loads((folder / 'manifest.json').read_text())
    for item in manifest['files']:
        path = safe_path(folder / 'payload', item['path'])
        if not path.is_file() or path.stat().st_size != item['bytes'] or sha(path) != item['sha256']:
            raise ValueError('Local evidence is missing or changed: ' + item['path'])
    package = folder / 'evidence.zip'
    expected = {x['path']: x['sha256'] for x in manifest['files']}
    expected['manifest.json'] = sha(folder / 'manifest.json')
    with zipfile.ZipFile(package) as archive:
        if len(archive.namelist()) != len(expected) or set(archive.namelist()) != set(expected):
            raise ValueError('ZIP contents do not match manifest')
        for name, digest in expected.items():
            h = hashlib.sha256()
            with archive.open(name) as source:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    h.update(block)
            if h.hexdigest() != digest:
                raise ValueError('ZIP evidence checksum mismatch: ' + name)
    return manifest, {'manifestSha256': sha(folder / 'manifest.json'), 'zipSha256': sha(package),
                      'filesVerified': len(manifest['files']), 'verifiedAt': datetime.now(timezone.utc).isoformat()}


def archived_minutes(folder, bucket, expected_window=None):
    manifest, verification = verify_local(folder)
    if expected_window is not None and (manifest['stage'] != 'final' or manifest['window'] != expected_window):
        raise ValueError('Local reporting archive does not match the final experiment')
    rows = [json.loads(safe_path(folder/'payload', item['path']).read_text()) for item in manifest['s3Objects']
            if item['bucket'] == bucket and item['isLatest'] and item['key'].startswith('minutes/')]
    return rows, verification


class Evidence:
    def __init__(self):
        # Offline verification must work even after build output/SDKs are removed.
        global boto3, Config, ClientError
        import boto3
        from botocore.config import Config
        from botocore.exceptions import ClientError
        self.state = json.loads((ROOT / 'cdk.out/observation-state.json').read_text())
        self.plan = json.loads((ROOT / 'cdk.out/closeout/plan.json').read_text())
        self.session = boto3.Session(profile_name='ruralshield-research', region_name='us-east-2')
        self.credential_refresh = configure_process_refresh(self.session)
        self.clients = {}
        if self.client('sts', 'us-east-2').get_caller_identity()['Account'] != self.plan['account']:
            raise ValueError('Wrong AWS account')

    def client(self, service, region):
        key = service, region
        if key not in self.clients:
            self.clients[key] = self.session.client(service, region_name=region, config=Config(
                max_pool_connections=24, retries={'mode': 'standard', 'max_attempts': 7}, connect_timeout=8, read_timeout=60))
        return self.clients[key]

    def resources(self, kind):
        return [(rg, r['PhysicalResourceId']) for rg, stacks in self.plan['regions'].items()
                for st in stacks for r in st['resources'] if r['ResourceType'] == kind and r.get('PhysicalResourceId')]

    def read_control(self, key, with_metadata=False):
        try:
            response = self.client('s3', 'us-east-2').get_object(Bucket=self.plan['evidenceBucket'], Key=key)
            body = response['Body'].read()
            document = json.loads(body)
            if with_metadata:
                return document, {'key': key, 'versionId': response.get('VersionId'),
                                  'lastModified': response['LastModified'].isoformat(),
                                  'sha256': hashlib.sha256(body).hexdigest(),
                                  'documentSha256': hashlib.sha256(encode(document)).hexdigest()}
            return document
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                return (None, None) if with_metadata else None
            raise

    def bucket_versions(self, region, bucket):
        versions, markers = [], []
        for page in self.client('s3', region).get_paginator('list_object_versions').paginate(Bucket=bucket):
            versions.extend(page.get('Versions', []))
            markers.extend(page.get('DeleteMarkers', []))
        return versions, markers

    def owned_groups(self):
        result = []
        for region in self.plan['regions']:
            groups = {name for rg, name in self.resources('AWS::Logs::LogGroup') if rg == region}
            functions = {name for rg, name in self.resources('AWS::Lambda::Function') if rg == region}
            if region == 'us-east-2':
                # Include the separate native closeout's own logs and generated Lambda logs.
                for page in self.client('cloudformation', region).get_paginator('list_stack_resources').paginate(StackName=self.plan['closeoutStack']):
                    for r in page['StackResourceSummaries']:
                        if r['ResourceType'] == 'AWS::Logs::LogGroup':
                            groups.add(r['PhysicalResourceId'])
                        if r['ResourceType'] == 'AWS::Lambda::Function':
                            functions.add(r['PhysicalResourceId'])
            groups.update('/aws/lambda/' + name for name in functions)
            for page in self.client('logs', region).get_paginator('describe_log_groups').paginate():
                for group in page['logGroups']:
                    name = group['logGroupName']
                    if name in groups or (region == 'us-east-2' and name.startswith('API-Gateway-Execution-Logs_' + self.plan['apiId'] + '/')):
                        result.append({'region': region, **group})
        return result

    def log_events(self, region, group):
        token = None
        while True:
            kwargs = {'logGroupName': group, 'limit': 10000}
            if token:
                kwargs['nextToken'] = token
            response = self.client('logs', region).filter_log_events(**kwargs)
            yield from response.get('events', [])
            next_token = response.get('nextToken')
            if not next_token or next_token == token:
                return
            token = next_token
            time.sleep(.25)

    def snapshot(self, final=False):
        now = datetime.now(timezone.utc)
        completed, completed_object = self.read_control('closeout/completed.json', with_metadata=True)
        gate = self.read_control('closeout/archive-verified.json')
        if final:
            validate_final({'stage': 'final', 'window': self.state['manifest'], 'nativeCloseout': completed or {},
                            'nativeCloseoutObject': completed_object, 'finalGateVerified': bool(gate)}, now)
        folder = ROOT / 'research-evidence' / (('final-' if final else 'checkpoint-') + now.strftime('%Y%m%dT%H%M%SZ'))
        folder.mkdir(parents=True, exist_ok=False)
        payload = folder / 'payload'
        payload.mkdir()
        seed = self.read_control('closeout/local-retirement.json')
        seed_manifest = None
        if seed and seed.get('executed'):
            seed_folder = Path(seed['archive'])
            seed_manifest, seed_check = verify_local(seed_folder)
            if seed_manifest['window'] != self.state['manifest']:
                raise ValueError('Previous local archive belongs to another experiment')
            shutil.copytree(seed_folder/'payload', payload, dirs_exist_ok=True)
            write_json(payload/('provenance/' + seed_check['manifestSha256'] + '-manifest.json'), seed_manifest)
            write_json(payload/('provenance/' + seed_check['manifestSha256'] + '-verification.json'), seed_check)
        manifest = {'schema': 1, 'stage': 'final' if final else 'checkpoint', 'capturedAt': now.isoformat(),
                    'collectorSources': {name: sha(ROOT/'scripts'/name) for name in
                        ('paper_evidence.py', 'local_aws_session.py', 'evidence_log_checks.py', 'retire_archived_versions.py')},
                    'collectorCredentialRefresh': self.credential_refresh,
                    'account': self.plan['account'], 'window': self.state['manifest'], 'nativeCloseout': completed,
                    'nativeCloseoutObject': completed_object,
                    'finalGateVerified': False, 'buckets': [], 's3Objects': [], 'logs': [], 'tables': [], 'files': [],
                    'scope': 'Paper source/config, all versions in the pinned RuralShield buckets, owned CloudWatch logs, deployed synthetic table, metrics/findings/recovery receipts. No credentials. Checkpoints are partial, not completed results.'}
        if seed_manifest:
            manifest['seedArchive'] = seed['archive']
            manifest['s3Objects'] = [dict(x, cloudRetired=True) for x in seed_manifest['s3Objects']]
            manifest['tables'] = list(seed_manifest['tables'])
        for region, bucket in self.resources('AWS::S3::Bucket'):
            s3 = self.client('s3', region)
            try:
                lock = s3.get_object_lock_configuration(Bucket=bucket)
                has_lock = lock.get('ObjectLockConfiguration', {}).get('ObjectLockEnabled') == 'Enabled'
            except ClientError as e:
                if e.response['Error']['Code'] not in ('ObjectLockConfigurationNotFoundError', 'NoSuchObjectLockConfiguration'):
                    raise
                lock, has_lock = {'ObjectLockEnabled': False}, False
            versions, markers = self.bucket_versions(region, bucket)
            config = {'region': region, 'bucket': bucket, 'objectLockEnabled': has_lock, 'lockConfiguration': lock,
                      'encryption': s3.get_bucket_encryption(Bucket=bucket), 'logging': s3.get_bucket_logging(Bucket=bucket),
                      'versions': versions, 'deleteMarkers': markers}
            manifest['buckets'].append(config)
            def download(version):
                identity = bucket + '\0' + version['Key'] + '\0' + version['VersionId']
                relative = 's3/' + hashlib.sha256(bucket.encode()).hexdigest()[:12] + '/' + hashlib.sha256(identity.encode()).hexdigest() + '.bin'
                dest = safe_path(payload, relative)
                dest.parent.mkdir(parents=True, exist_ok=True)
                response = s3.get_object(Bucket=bucket, Key=version['Key'], VersionId=version['VersionId'])
                digest = hashlib.sha256()
                with dest.open('wb') as stream:
                    for block in response['Body'].iter_chunks(chunk_size=1024*1024):
                        digest.update(block)
                        stream.write(block)
                if response.get('Metadata', {}).get('sha256', digest.hexdigest()) != digest.hexdigest():
                    raise ValueError('Remote evidence checksum mismatch')
                return {'region': region, 'bucket': bucket, 'key': version['Key'], 'versionId': version['VersionId'],
                        'isLatest': version['IsLatest'], 'path': relative, 'sha256': digest.hexdigest(), 'bytes': dest.stat().st_size,
                        'objectLockMode': response.get('ObjectLockMode'), 'retainUntil': response.get('ObjectLockRetainUntilDate'),
                        'legalHold': response.get('ObjectLockLegalHoldStatus')}
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
                manifest['s3Objects'].extend(executor.map(download, versions))
            print(json.dumps({'copiedBucket': bucket, 'versions': len(versions)}), flush=True)
        # Preserve verified prior data after interrupted retirement; fresh versions win.
        manifest['s3Objects'] = list({(x['bucket'], x['key'], x['versionId']): x for x in manifest['s3Objects']}.values())
        latest = {x['key']: x for x in manifest['s3Objects'] if x['bucket'] == self.plan['evidenceBucket'] and x['isLatest']}
        if gate:
            if any(latest.get(x['key'], {}).get('sha256') != x['sha256'] for x in gate['objects']):
                raise ValueError('Final cloud evidence manifest does not match local files')
            manifest['finalGateVerified'] = True
        source = latest.get('freeze/source.zip')
        if not source or source['sha256'] != self.state['manifest']['sourceArchiveSha256']:
            raise ValueError('Frozen experiment source hash mismatch')
        groups = self.owned_groups()
        def download_logs(group):
            region, name = group['region'], group['logGroupName']
            relative = 'logs/' + region + '/' + hashlib.sha256((name + now.isoformat()).encode()).hexdigest()[:20] + '.jsonl.gz'
            dest = safe_path(payload, relative)
            dest.parent.mkdir(parents=True, exist_ok=True)
            digest, count = hashlib.sha256(), 0
            with dest.open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as stream:
                for event in self.log_events(region, name):
                    line = encode(event) + b'\n'
                    digest.update(line); stream.write(line); count += 1
            return {'region': region, 'name': name, 'metadata': group, 'path': relative,
                    'events': count, 'eventSha256': digest.hexdigest()}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            manifest['logs'] = list(executor.map(download_logs, groups))
        if seed_manifest:
            manifest['logs'] = list({(x['region'], x['name']): x for x in seed_manifest['logs'] + manifest['logs']}.values())
        for region, table in self.resources('AWS::DynamoDB::GlobalTable') + self.resources('AWS::DynamoDB::Table'):
            db = self.client('dynamodb', region)
            try:
                pages = list(db.get_paginator('scan').paginate(TableName=table, ConsistentRead=True))
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException' and seed_manifest and any(x['region'] == region and x['name'] == table for x in manifest['tables']):
                    continue
                raise
            items = [x for page in pages for x in page['Items']]
            item_digest = hashlib.sha256(encode(sorted(items, key=lambda x: encode(x)))).hexdigest()
            if final:
                native_key = 'closeout/archive/' + region + '/table-' + table + '.json'
                native = latest.get(native_key)
                if not native:
                    raise ValueError('Missing native final synthetic-table export')
                original = json.loads(safe_path(payload, native['path']).read_text())
                original_items = [x for page in original['items'] for x in page['Items']]
                if hashlib.sha256(encode(sorted(original_items, key=lambda x: encode(x)))).hexdigest() != item_digest:
                    raise ValueError('Synthetic data changed after native closeout; retain table and investigate')
            relative = 'tables/' + region + '/' + table + '.json'
            write_json(safe_path(payload, relative), {'description': db.describe_table(TableName=table),
                       'pitr': db.describe_continuous_backups(TableName=table), 'items': items})
            manifest['tables'].append({'region': region, 'name': table, 'path': relative, 'itemSha256': item_digest})
        manifest['tables'] = list({(x['region'], x['name']): x for x in manifest['tables']}.values())
        # Current paper text is separate from the immutable source frozen at arming.
        local = [ROOT/'README.md', ROOT/'package-lock.json', ROOT/'cdk.out/observation-reports/latest.json', ROOT/'cdk.out/observation-reports/account-day-costs.json', ROOT/'cdk.out/closeout/plan.json']
        local.extend(ROOT/'scripts'/name for name in
                     ('local_aws_session.py', 'evidence_log_checks.py', 'retire_archived_versions.py'))
        for directory, pattern in [('paper', '*'), ('docs', '*.md'), ('scripts', '*paper*evidence*.py'), ('cdk.out/nonai-tests', '*.json'), ('cdk.out/nonai-20261025T175721Z', '*.json'), ('cdk.out/nonai-20261025T175840Z', '*.json')]:
            local.extend((ROOT/directory).glob(pattern))
        for path in set(local):
            if path.is_file():
                dest = safe_path(payload, 'workspace/' + path.relative_to(ROOT).as_posix())
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, dest)
        write_json(payload/'inventory.json', {k: v for k, v in manifest.items() if k != 'files'})
        for path in sorted(payload.rglob('*')):
            if path.is_file():
                manifest['files'].append({'path': path.relative_to(payload).as_posix(), 'sha256': sha(path), 'bytes': path.stat().st_size})
        write_json(folder/'manifest.json', manifest)
        with zipfile.ZipFile(folder/'evidence.zip', 'w', compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
            archive.write(folder/'manifest.json', 'manifest.json')
            for item in manifest['files']:
                archive.write(safe_path(payload, item['path']), item['path'])
        _, receipt = verify_local(folder)
        receipt.update({'stage': manifest['stage'], 'finalGateVerified': manifest['finalGateVerified'],
                        's3Versions': len(manifest['s3Objects']), 'logGroups': len(manifest['logs']),
                        'logEvents': sum(x['events'] for x in manifest['logs']), 'zipBytes': (folder/'evidence.zip').stat().st_size})
        write_json(folder/'verification.json', receipt)
        print(json.dumps({'archive': str(folder), **receipt}), flush=True)
        return folder

    def retire(self, folder, execute=False, deferred_logs=()):
        """Retire only archived, unprotected duplicates; never run during the pilot."""
        manifest, verification = verify_local(folder)
        validate_final(manifest, datetime.now(timezone.utc))
        archived_groups = {(g['region'], g['name']) for g in manifest['logs']}
        deferred = {tuple(x) for x in deferred_logs}
        if not deferred <= archived_groups:
            raise ValueError('Deferred log groups must belong to this verified archive')
        if manifest['account'] != self.plan['account'] or manifest['window'] != self.state['manifest']:
            raise ValueError('Archive is for a different account or experiment')
        completed, completed_object = self.read_control('closeout/completed.json', with_metadata=True)
        if completed != manifest['nativeCloseout'] or completed_object != manifest.get('nativeCloseoutObject'):
            raise ValueError('Native closeout receipt differs from the archived receipt')
        if self.client('events', 'us-east-2').describe_rule(Name=self.plan['loadRule'])['State'] != 'DISABLED':
            raise ValueError('Synthetic traffic schedule is still enabled')
        try:
            self.client('apigateway', 'us-east-2').get_rest_api(restApiId=self.plan['apiId'])
        except ClientError as e:
            if e.response['Error']['Code'] != 'NotFoundException':
                raise
        else:
            raise ValueError('Application API is present; do not retire its evidence stores')
        for region, trail in self.resources('AWS::CloudTrail::Trail'):
            if self.client('cloudtrail', region).get_trail_status(Name=trail)['IsLogging']:
                raise ValueError('Audit collection is still running')
        if execute:
            # Reporting must switch to the verified local source even if cleanup is interrupted.
            pending = {'phase': 'in-progress', 'executed': True, 'archive': str(folder.resolve()), 'verification': verification}
            self.client('s3', 'us-east-2').put_object(Bucket=self.plan['evidenceBucket'], Key='closeout/local-retirement.json',
                Body=encode(pending), ContentType='application/json', Metadata={'sha256': hashlib.sha256(encode(pending)).hexdigest()})
        owned = {(x['region'], x['logGroupName']) for x in self.owned_groups()}
        actions, skipped = [], []
        receipt_path = folder / 'retirement.json'
        tool_sources = {name: sha(ROOT/'scripts'/name) for name in
                        ('paper_evidence.py', 'local_aws_session.py', 'evidence_log_checks.py', 'retire_archived_versions.py')}
        def record(kind, target, **details):
            item = {'kind': kind, 'target': target, **details}
            actions.append(item)
            with (folder / 'retirement-actions.jsonl').open('ab') as journal:
                journal.write(encode({'executed': execute, **item}) + b'\n')
        for group in manifest['logs']:
            region, name = group['region'], group['name']
            if (region, name) not in owned:
                skipped.append({'kind': 'log-group', 'target': name, 'reason': 'not present in current owned-group inventory'})
        unarchived_groups = owned - archived_groups
        for region, name in sorted(unarchived_groups):
            skipped.append({'kind':'log-group','region':region,'target':name,
                            'reason':'unarchived owned log group retained; take another final archive'})
        for region, name in sorted(deferred):
            skipped.append({'kind':'log-group','region':region,'target':name,
                            'reason':'operator deferred log group; take another final archive'})
        # Clients were initialized by owned_groups. Act on each completed full
        # recheck immediately, rather than letting small-group checks grow stale
        # while a large group is still being read.
        selected = [g for g in manifest['logs'] if (g['region'], g['name']) in owned
                    and (g['region'], g['name']) not in deferred]
        for check in recheck_logs(selected, self.log_events, encode):
            group = check['group']
            region, name = group['region'], group['name']
            count = check['count']
            if check['sha256'] != group['eventSha256'] or count != group['events']:
                skipped.append({'kind': 'log-group', 'target': name, 'region':region,
                    'reason': 'new or changed events; take another final archive',
                    'archivedEvents':group['events'],'observedEvents':count,
                    'archivedEventSha256':group['eventSha256'],'observedEventSha256':check['sha256'],
                    'checkStartedAt':check['startedAt'],'checkFinishedAt':check['finishedAt']})
                continue
            if execute:
                self.client('logs', region).delete_log_group(logGroupName=name)
                remaining = self.client('logs', region).describe_log_groups(logGroupNamePrefix=name)['logGroups']
                if any(g['logGroupName'] == name for g in remaining):
                    raise ValueError('Log group deletion not yet verified')
            record('log-group', name, region=region, events=count,
                   checkStartedAt=check['startedAt'], checkFinishedAt=check['finishedAt'])
        allowed_tables = set(self.resources('AWS::DynamoDB::GlobalTable') + self.resources('AWS::DynamoDB::Table'))
        for table in manifest['tables']:
            region, name = table['region'], table['name']
            if (region, name) not in allowed_tables:
                raise ValueError('Unowned table in archive')
            db = self.client('dynamodb', region)
            try:
                description = db.describe_table(TableName=name)['Table']
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    skipped.append({'kind': 'table', 'target': name, 'reason': 'already absent'})
                    continue
                raise
            items = [x for page in db.get_paginator('scan').paginate(TableName=name, ConsistentRead=True) for x in page['Items']]
            digest = hashlib.sha256(encode(sorted(items, key=lambda x: encode(x)))).hexdigest()
            if digest != table['itemSha256']:
                skipped.append({'kind': 'table', 'target': name, 'reason': 'data changed; take another final archive'})
                continue
            if execute:
                if description.get('DeletionProtectionEnabled'):
                    db.update_table(TableName=name, DeletionProtectionEnabled=False)
                    db.get_waiter('table_exists').wait(TableName=name)
                db.delete_table(TableName=name)
                db.get_waiter('table_not_exists').wait(TableName=name)
            record('synthetic-table-and-pitr', name, region=region)
        expected_buckets = set(self.resources('AWS::S3::Bucket'))
        def eligible(bucket, key):
            return bucket != self.plan['evidenceBucket'] or key.startswith(('freeze/', 'minutes/', 'claims/', 'closeout/archive/', 'closeout/preflight/', 'closeout/preparation/'))
        for bucket_info in manifest['buckets']:
            region, bucket = bucket_info['region'], bucket_info['bucket']
            if (region, bucket) not in expected_buckets:
                raise ValueError('Unowned bucket in archive')
            s3 = self.client('s3', region)
            try:
                locked = s3.get_object_lock_configuration(Bucket=bucket).get('ObjectLockConfiguration', {}).get('ObjectLockEnabled') == 'Enabled'
            except ClientError as e:
                if e.response['Error']['Code'] not in ('ObjectLockConfigurationNotFoundError', 'NoSuchObjectLockConfiguration'):
                    raise
                locked = False
            if locked or bucket_info['objectLockEnabled']:
                skipped.append({'kind': 'bucket', 'target': bucket, 'reason': 'Object Lock enabled; every original and version retained'})
                continue
            archived = [x for x in manifest['s3Objects'] if x['bucket'] == bucket]
            current, _ = self.bucket_versions(region, bucket)
            available = {(x['Key'], x['VersionId']) for x in current}
            candidates = []
            for item in archived:
                key, version = item['key'], item['versionId']
                if not eligible(bucket, key):
                    continue  # Keep cloud control, final gate, action and closeout receipts.
                if (key, version) not in available:
                    continue
                if item.get('objectLockMode') or item.get('legalHold') == 'ON':
                    continue
                if not isinstance(version, str) or not version or version == 'null':
                    skipped.append({'kind': 's3-version', 'target': bucket + '/' + key, 'reason': 'mutable null version retained'})
                    continue
                candidates.append({'Key': key, 'VersionId': version})
            def record_version(key, version):
                record('unlocked-s3-version', bucket + '/' + key, versionId=version)
            if execute:
                delete_verified_batches(s3, bucket, candidates, record_version)
            else:
                for item in candidates:
                    record_version(item['Key'], item['VersionId'])
            if execute:
                remaining, _ = self.bucket_versions(region, bucket)
                remaining_ids = {(x['Key'], x['VersionId']) for x in remaining}
                removed = {(x['target'][len(bucket)+1:], x['versionId']) for x in actions
                           if x['kind'] == 'unlocked-s3-version' and x['target'].startswith(bucket + '/')}
                if remaining_ids & removed:
                    raise ValueError('S3 version deletion not yet verified; see action journal')
            archived_ids = {(x['key'], x['versionId']) for x in archived}
            # The post-deletion inventory can include arrivals after the first list.
            new_count = sum((x['Key'], x['VersionId']) not in archived_ids and eligible(bucket, x['Key'])
                            for x in (remaining if execute else current))
            if new_count:
                skipped.append({'kind': 'bucket', 'target': bucket, 'reason': 'unarchived late versions retained', 'versions': new_count})
        if execute:
            deleted_groups = {(x['region'], x['target']) for x in actions if x['kind'] == 'log-group'}
            for group in self.owned_groups():
                identity = (group['region'], group['logGroupName'])
                if identity in unarchived_groups:
                    continue  # Retained and reported from the initial inventory.
                if identity not in owned or identity in deleted_groups:
                    skipped.append({'kind':'log-group', 'region':identity[0], 'target':identity[1],
                                    'reason':'new or recreated owned log group retained; take another final archive'})
        incomplete = any(x['reason'] in ('new or changed events; take another final archive', 'data changed; take another final archive', 'unarchived late versions retained',
                                        'new or recreated owned log group retained; take another final archive',
                                        'unarchived owned log group retained; take another final archive',
                                        'operator deferred log group; take another final archive') for x in skipped)
        result = {'executed': execute, 'phase': 'complete' if execute and not incomplete else 'partial' if execute else 'preview',
                  'at': datetime.now(timezone.utc).isoformat(), 'archive': str(folder.resolve()),
                  'verification': verification, 'actions': actions, 'skipped': skipped,
                  'retirementToolSources': tool_sources,
                  'deferredLogs': [list(x) for x in sorted(deferred)],
                  'preserved': 'All KMS keys/rotation, Object Lock buckets/versions, vaults/recovery points and cloud control receipts. No retention bypass.'}
        write_json(receipt_path, result)
        if execute:
            self.client('s3', 'us-east-2').put_object(Bucket=self.plan['evidenceBucket'], Key='closeout/local-retirement.json',
                Body=encode(result), ContentType='application/json', Metadata={'sha256': hashlib.sha256(encode(result)).hexdigest()})
        print(json.dumps({'executed': execute, 'actions': len(actions), 'skipped': skipped, 'receipt': str(receipt_path)}), flush=True)
        return result


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--final', action='store_true', help='Require verified native closeout and at least 24 hours after test end')
    parser.add_argument('--verify', type=Path, help='Verify an existing local archive without AWS access')
    parser.add_argument('--retire', type=Path, help='Plan retirement of locally verified duplicates after native closeout plus 24 hours')
    parser.add_argument('--execute', action='store_true', help='Execute the guarded --retire plan; otherwise read-only')
    parser.add_argument('--defer-log', nargs=2, action='append', default=[], metavar=('REGION','LOG_GROUP'),
                        help='Keep a named archived log group pending another final capture; never waive verification')
    args = parser.parse_args()
    if args.execute and not args.retire:
        parser.error('--execute requires --retire')
    if args.defer_log and not args.retire:
        parser.error('--defer-log requires --retire')
    if args.verify:
        _, receipt = verify_local(args.verify)
        print(json.dumps(receipt))
    elif args.retire:
        # Refuse an incomplete/tampered/early archive before even opening an AWS session.
        manifest, _ = verify_local(args.retire)
        validate_final(manifest, datetime.now(timezone.utc))
        Evidence().retire(args.retire, execute=args.execute, deferred_logs=args.defer_log)
    else:
        Evidence().snapshot(final=args.final)


if __name__ == '__main__':
    main()
