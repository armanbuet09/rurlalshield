"""Offline safety checks for the local archive and cloud-retirement gate."""
import json
import tempfile
import unittest
import zipfile
import hashlib
import io
from unittest.mock import Mock, patch
from datetime import datetime, timedelta, timezone
from pathlib import Path

from paper_evidence import ROOT, Evidence, archived_minutes, encode, safe_path, sha, validate_final, verify_local, write_json

TEST_TEMP = (ROOT / "cdk.out/paper-evidence-tests").resolve()
assert TEST_TEMP.is_relative_to(ROOT.resolve())
TEST_TEMP.mkdir(parents=True, exist_ok=True)


class PaperEvidenceSafety(unittest.TestCase):
    def test_new_or_recreated_owned_group_is_retained_and_marks_cleanup_partial(self):
        class ServiceError(Exception):
            def __init__(self, code):self.response = {'Error': {'Code': code}}
        for mode in ('new','recreated','unarchived','deferred'):
            with self.subTest(mode=mode):
                recreated = mode == 'recreated'
                group={'region':'us-east-2','logGroupName':'owned-research-log'}
                manifest=self.final_manifest(datetime.now(timezone.utc)-timedelta(minutes=1))
                manifest.update(account='test-account',tables=[],buckets=[],s3Objects=[],logs=[
                    {'region':'us-east-2','name':group['logGroupName'],'events':0,
                    'eventSha256':hashlib.sha256(b'').hexdigest()}] if mode in ('recreated','deferred') else [])
                evidence=Evidence.__new__(Evidence)
                evidence.plan={'account':'test-account','loadRule':'stopped','apiId':'absent','evidenceBucket':'owned'}
                evidence.state={'manifest':manifest['window']}
                evidence.resources=lambda kind:[]
                evidence.owned_groups=Mock(side_effect=[[group] if mode != 'new' else [],[group]])
                evidence.log_events=Mock(return_value=[])
                evidence.read_control=Mock(return_value=(manifest['nativeCloseout'],manifest['nativeCloseoutObject']))
                clients={name:Mock() for name in ('events','apigateway','s3','logs')}
                clients['events'].describe_rule.return_value={'State':'DISABLED'}
                clients['apigateway'].get_rest_api.side_effect=ServiceError('NotFoundException')
                clients['logs'].describe_log_groups.return_value={'logGroups':[]}
                evidence.client=lambda service,region:clients[service]
                with tempfile.TemporaryDirectory(dir=TEST_TEMP) as name, \
                        patch('paper_evidence.verify_local',return_value=(manifest,{'verified':'fixture'})), \
                        patch('paper_evidence.ClientError',ServiceError,create=True):
                    result=evidence.retire(Path(name),execute=True,
                        deferred_logs=[('us-east-2',group['logGroupName'])] if mode=='deferred' else [])
                self.assertEqual(result['phase'],'partial')
                self.assertEqual(result['skipped'][-1]['reason'],
                    'operator deferred log group; take another final archive' if mode=='deferred' else
                    'unarchived owned log group retained; take another final archive' if mode == 'unarchived'
                    else 'new or recreated owned log group retained; take another final archive')
                self.assertEqual(clients['logs'].delete_log_group.call_count,1 if recreated else 0)
                if mode=='deferred':evidence.log_events.assert_not_called()

    def test_unknown_log_deferral_refused_before_cloud_access(self):
        manifest=self.final_manifest(datetime.now(timezone.utc)-timedelta(minutes=1))
        manifest['logs']=[]
        evidence=Evidence.__new__(Evidence);evidence.read_control=Mock()
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as name, \
                patch('paper_evidence.verify_local',return_value=(manifest,{'verified':'fixture'})):
            with self.assertRaisesRegex(ValueError,'belong to this verified archive'):
                evidence.retire(Path(name),execute=True,deferred_logs=[('us-east-2','unowned')])
        evidence.read_control.assert_not_called()

    def test_late_version_after_delete_is_retained_and_marks_cleanup_partial(self):
        class ServiceError(Exception):
            def __init__(self, code):self.response = {'Error': {'Code': code}}
        manifest = self.final_manifest(datetime.now(timezone.utc) - timedelta(minutes=1))
        manifest.update(account='test-account', logs=[], tables=[],
            buckets=[{'region':'us-east-2','bucket':'owned-test-bucket','objectLockEnabled':False}],
            s3Objects=[{'bucket':'owned-test-bucket','key':'minutes/one.json','versionId':'archived-v1'}])
        evidence = Evidence.__new__(Evidence)
        evidence.plan = {'account':'test-account','loadRule':'stopped','apiId':'absent','evidenceBucket':'owned-test-bucket'}
        evidence.state = {'manifest':manifest['window']}
        evidence.resources = lambda kind: [('us-east-2','owned-test-bucket')] if kind == 'AWS::S3::Bucket' else []
        evidence.owned_groups = Mock(return_value=[])
        evidence.read_control = Mock(return_value=(manifest['nativeCloseout'],manifest['nativeCloseoutObject']))
        evidence.bucket_versions = Mock(side_effect=[
            ([{'Key':'minutes/one.json','VersionId':'archived-v1'}],[]),
            ([{'Key':'minutes/late.json','VersionId':'new-v2'}],[])])
        clients = {name:Mock() for name in ('events','apigateway','s3')}
        clients['events'].describe_rule.return_value = {'State':'DISABLED'}
        clients['apigateway'].get_rest_api.side_effect = ServiceError('NotFoundException')
        clients['s3'].get_object_lock_configuration.return_value = {}
        clients['s3'].delete_objects.return_value = {'Deleted':[{'Key':'minutes/one.json','VersionId':'archived-v1'}]}
        evidence.client = lambda service,region:clients[service]
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as name, \
                patch('paper_evidence.verify_local',return_value=(manifest,{'verified':'fixture'})), \
                patch('paper_evidence.ClientError',ServiceError,create=True):
            result = evidence.retire(Path(name),execute=True)
        self.assertEqual(result['phase'],'partial')
        self.assertEqual(result['skipped'][0]['reason'],'unarchived late versions retained')
        self.assertEqual(result['skipped'][0]['versions'],1)
        clients['s3'].delete_objects.assert_called_once_with(Bucket='owned-test-bucket',
            Delete={'Objects':[{'Key':'minutes/one.json','VersionId':'archived-v1'}],'Quiet':False})

    def make_archive(self, folder):
        payload = folder/'payload'
        payload.mkdir()
        (payload/'measurement.json').write_bytes(b'{"attempted":123}')
        manifest = {'stage': 'checkpoint', 's3Objects': [{'bucket':'test','key':'minutes/0000.json','isLatest':True,'path':'measurement.json'}], 'files': [{'path': 'measurement.json', 'bytes': 17,
                    'sha256': sha(payload/'measurement.json')}]}
        write_json(folder/'manifest.json', manifest)
        with zipfile.ZipFile(folder/'evidence.zip', 'w') as archive:
            archive.write(folder/'manifest.json', 'manifest.json')
            archive.write(payload/'measurement.json', 'measurement.json')
        return manifest

    def test_independent_payload_and_zip_verification(self):
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as name:
            folder = Path(name); self.make_archive(folder)
            manifest, receipt = verify_local(folder)
            self.assertEqual(receipt['filesVerified'], 1)
            self.assertEqual(manifest['stage'], 'checkpoint')

    def test_reporting_can_read_verified_local_minutes(self):
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as name:
            folder = Path(name); self.make_archive(folder)
            rows, receipt = archived_minutes(folder, "test")
            self.assertEqual(sum(x["attempted"] for x in rows), 123)
            self.assertEqual(receipt["filesVerified"], 1)

    def test_changed_payload_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as name:
            folder = Path(name); self.make_archive(folder)
            (folder/'payload/measurement.json').write_bytes(b'altered')
            with self.assertRaisesRegex(ValueError, 'missing or changed'):
                verify_local(folder)

    def test_changed_zip_is_rejected_even_when_payload_is_intact(self):
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as name:
            folder = Path(name); self.make_archive(folder)
            with zipfile.ZipFile(folder/'evidence.zip', 'w') as archive:
                archive.write(folder/'manifest.json', 'manifest.json')
                archive.writestr('measurement.json', b'altered')
            with self.assertRaisesRegex(ValueError, 'ZIP evidence checksum'):
                verify_local(folder)

    def test_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as name:
            with self.assertRaisesRegex(ValueError, 'Unsafe archive path'):
                safe_path(Path(name), '../outside.txt')

    def test_checkpoint_never_authorizes_retirement(self):
        with self.assertRaisesRegex(ValueError, 'checkpoint'):
            validate_final({'stage': 'checkpoint'}, datetime.now(timezone.utc))

    def test_final_requires_native_success_and_verified_cloud_manifest(self):
        now = datetime.now(timezone.utc)
        manifest = {'stage': 'final', 'window': {'endAt': (now-timedelta(days=2)).isoformat()},
                    'nativeCloseout': {'at': (now-timedelta(days=2)).isoformat(), 'checks': {'stopped': False}}, 'finalGateVerified': True}
        with self.assertRaisesRegex(ValueError, 'shutdown'):
            validate_final(manifest, now)
        manifest['nativeCloseout']['checks']['stopped'] = True
        manifest['finalGateVerified'] = False
        with self.assertRaisesRegex(ValueError, 'manifest'):
            validate_final(manifest, now)

    def test_additional_day_for_late_data_is_enforced(self):
        now = datetime.now(timezone.utc)
        manifest = {'stage': 'final', 'window': {'endAt': (now-timedelta(hours=23)).isoformat()},
                    'nativeCloseout': {'at': (now-timedelta(hours=23)).isoformat(), 'checks': {'stopped': True}}, 'finalGateVerified': True}
        manifest['nativeCloseoutObject'] = {'lastModified': (now-timedelta(hours=23)).isoformat(),
            'sha256': 'raw-body-checksum', 'documentSha256': hashlib.sha256(encode(manifest['nativeCloseout'])).hexdigest()}
        with self.assertRaisesRegex(ValueError, '24 hours'):
            validate_final(manifest, now)
        validate_final(manifest, now+timedelta(hours=2))

    def final_manifest(self, now):
        receipt = {'at': (now-timedelta(hours=25)).isoformat(), 'checks': {'stopped': True}}
        return {'stage': 'final', 'window': {'endAt': (now-timedelta(hours=26)).isoformat()},
                'nativeCloseout': receipt, 'finalGateVerified': True,
                'nativeCloseoutObject': {'lastModified': (now-timedelta(hours=24)+timedelta(seconds=1)).isoformat(),
                    'sha256': 'raw-body-checksum', 'documentSha256': hashlib.sha256(encode(receipt)).hexdigest()}}

    def test_waits_for_actual_receipt_write_not_handler_start(self):
        now = datetime.now(timezone.utc)
        manifest = self.final_manifest(now)
        with self.assertRaisesRegex(ValueError, 'receipt was written'):
            validate_final(manifest, now)
        validate_final(manifest, now+timedelta(seconds=1))

    def test_legacy_final_without_receipt_metadata_cannot_retire(self):
        now = datetime.now(timezone.utc)
        manifest = self.final_manifest(now)
        del manifest['nativeCloseoutObject']
        with self.assertRaisesRegex(ValueError, 'object timestamp'):
            validate_final(manifest, now)

    def test_receipt_metadata_must_match_document(self):
        now = datetime.now(timezone.utc)
        manifest = self.final_manifest(now)
        manifest['nativeCloseoutObject']['documentSha256'] = 'changed'
        with self.assertRaisesRegex(ValueError, 'does not match'):
            validate_final(manifest, now)

    def test_control_metadata_binds_exact_s3_version_and_write_time(self):
        written = datetime.now(timezone.utc)
        raw = b'{ "at": "2026-10-30T18:39:50+00:00", "checks": {"stopped": true} }'
        evidence = Evidence.__new__(Evidence)
        evidence.plan = {'evidenceBucket': 'owned-test-bucket'}
        client = Mock()
        client.get_object.return_value = {'Body': io.BytesIO(raw), 'VersionId': 'version-1', 'LastModified': written}
        evidence.client = Mock(return_value=client)
        document, metadata = evidence.read_control('closeout/completed.json', with_metadata=True)
        self.assertEqual(metadata['lastModified'], written.isoformat())
        self.assertEqual(metadata['versionId'], 'version-1')
        self.assertEqual(metadata['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(metadata['documentSha256'], hashlib.sha256(encode(document)).hexdigest())
        client.get_object.assert_called_once_with(Bucket='owned-test-bucket', Key='closeout/completed.json')


if __name__ == '__main__':
    unittest.main()
