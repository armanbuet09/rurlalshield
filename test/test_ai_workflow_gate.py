"""Activation checks use a real miniature archive, without AWS or credentials."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
spec=importlib.util.spec_from_file_location('workflow_gate',ROOT/'scripts/verify-ai-workflow-gate.py')
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
from paper_evidence import encode
package_spec=importlib.util.spec_from_file_location('package_workflow',ROOT/'scripts/package-ai-workflow.py')
packager=importlib.util.module_from_spec(package_spec);package_spec.loader.exec_module(packager)


class GateTests(unittest.TestCase):
    def setUp(self):
        (ROOT/'cdk.out').mkdir(exist_ok=True)
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT/'cdk.out')
        self.folder=Path(self.tmp.name).resolve()
        assert self.folder.is_relative_to(ROOT.resolve())
        self.addCleanup(self.tmp.cleanup)
        self.payload=self.folder/'payload';self.payload.mkdir()
        self.state_root=self.folder/'workspace';(self.state_root/'cdk.out').mkdir(parents=True)
        frozen=b'frozen source archive fixture'
        self.window={'endAt':'2026-10-01T00:00:00+00:00','sourceArchiveSha256':hashlib.sha256(frozen).hexdigest()}
        self.bucket='owned-evidence'
        self.state={'manifest':self.window,'outputs':{'EvidenceBucket':self.bucket}}
        (self.state_root/'cdk.out/observation-state.json').write_text(json.dumps(self.state))
        self.receipt={'at':'2026-10-01T00:10:00+00:00','checks':{'stopped':True}}
        raw=encode(self.receipt)
        data={'freeze/source.zip':frozen,'closeout/archive/counts.json':b'{"count":1}',
              'closeout/completed.json':raw}
        data['closeout/archive-verified.json']=json.dumps({'objects':[{'key':'closeout/archive/counts.json',
            'sha256':hashlib.sha256(data['closeout/archive/counts.json']).hexdigest()}]}).encode()
        self.manifest={'stage':'final','account':'123456789012','window':self.window,
            'capturedAt':'2026-10-03T00:00:00+00:00','nativeCloseout':self.receipt,
            'nativeCloseoutObject':{'lastModified':'2026-10-01T00:11:00+00:00',
              'sha256':hashlib.sha256(raw).hexdigest(),'documentSha256':hashlib.sha256(encode(self.receipt)).hexdigest(),'versionId':'receipt-v1'},
            'finalGateVerified':True,'files':[],'s3Objects':[]}
        for i,(key,body) in enumerate(data.items()):
            name=f'{i}.bin';(self.payload/name).write_bytes(body)
            digest=hashlib.sha256(body).hexdigest()
            self.manifest['files'].append({'path':name,'bytes':len(body),'sha256':digest})
            self.manifest['s3Objects'].append({'bucket':self.bucket,'key':key,'isLatest':True,
                'path':name,'sha256':digest,'versionId':'receipt-v1' if key=='closeout/completed.json' else f'v{i}'})
        self.pack()
        p=patch.object(gate,'ROOT',self.state_root);p.start();self.addCleanup(p.stop)

    def pack(self):
        (self.folder/'manifest.json').write_text(json.dumps(self.manifest))
        with zipfile.ZipFile(self.folder/'evidence.zip','w') as z:
            z.write(self.folder/'manifest.json','manifest.json')
            for item in self.manifest['files']:z.write(self.payload/item['path'],item['path'])

    def test_real_zip_source_receipt_and_cloud_manifest_pass(self):
        result=gate.verify(self.folder)
        self.assertEqual(result['files_verified'],4);self.assertEqual(result['aws_calls'],0)
    def test_changed_unpacked_file_cannot_activate(self):
        (self.payload/'0.bin').write_bytes(b'changed')
        with self.assertRaises(ValueError):gate.verify(self.folder)

    def test_checkpoint_cannot_activate(self):
        self.manifest['stage']='checkpoint';self.pack()
        with self.assertRaises(ValueError):gate.verify(self.folder)
    def test_early_capture_stays_invalid_after_hold_expires(self):
        self.manifest['capturedAt']='2026-10-01T01:00:00+00:00';self.pack()
        with self.assertRaises(ValueError):gate.verify(self.folder)
    def test_receipt_version_mismatch_cannot_activate(self):
        self.manifest['nativeCloseoutObject']['versionId']='other-version';self.pack()
        with self.assertRaises(ValueError):gate.verify(self.folder)
    def test_missing_receipt_version_cannot_activate(self):
        self.manifest['nativeCloseoutObject']['versionId']=None
        for item in self.manifest['s3Objects']:
            if item['key']=='closeout/completed.json':item['versionId']=None
        self.pack()
        with self.assertRaises(ValueError):gate.verify(self.folder)
    def test_future_capture_cannot_activate(self):
        self.manifest['capturedAt']='2099-01-01T00:00:00+00:00';self.pack()
        with self.assertRaises(ValueError):gate.verify(self.folder)
    def test_expected_frozen_source_mismatch_cannot_activate(self):
        self.window['sourceArchiveSha256']='f'*64
        (self.state_root/'cdk.out/observation-state.json').write_text(json.dumps(self.state));self.pack()
        with self.assertRaises(ValueError):gate.verify(self.folder)
    def test_claimed_gate_boolean_cannot_replace_actual_cloud_manifest(self):
        self.manifest['s3Objects']=[x for x in self.manifest['s3Objects'] if x['key']!='closeout/archive-verified.json'];self.pack()
        with self.assertRaises(ValueError):gate.verify(self.folder)
    def test_cloud_export_mismatch_cannot_activate(self):
        for item in self.manifest['s3Objects']:
            if item['key']=='closeout/archive/counts.json':item['sha256']='a'*64
        self.pack()
        with self.assertRaises(ValueError):gate.verify(self.folder)
    def test_cloud_export_hash_is_rechecked_against_actual_payload(self):
        item=next(x for x in self.manifest['s3Objects'] if x['key']=='closeout/archive/counts.json')
        p=self.payload/item['path'];p.write_bytes(b'{"count":999}')
        f=next(x for x in self.manifest['files'] if x['path']==item['path'])
        f.update(bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest());self.pack()
        with self.assertRaises(ValueError):gate.verify(self.folder)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT/'cdk.out');self.folder=Path(self.tmp.name).resolve()
        assert self.folder.is_relative_to(ROOT.resolve());self.addCleanup(self.tmp.cleanup)
        p=patch.object(packager,'ROOT',self.folder);p.start();self.addCleanup(p.stop)
        for source in packager.FILES:
            f=self.folder/source;f.parent.mkdir(parents=True,exist_ok=True);f.write_text('# reviewed source\n')
        self.invoke(False)
    def invoke(self,verify):
        with patch.object(sys,'argv',['package-ai-workflow.py']+(['--verify'] if verify else [])),patch('builtins.print'):
            packager.main()
    def test_packaged_file_change_is_refused(self):
        self.invoke(True)
        (self.folder/'cdk.out/external-ai-workflow-asset/handlers.py').write_text('# changed')
        with self.assertRaises(ValueError):self.invoke(True)
    def test_source_change_requires_repackaging(self):
        (self.folder/'src/external_ai_workflow/runtime.py').write_text('# newer')
        with self.assertRaises(ValueError):self.invoke(True)
    def test_extra_asset_file_is_never_packaged_or_accepted(self):
        (self.folder/'cdk.out/external-ai-workflow-asset/foreign.txt').write_text('not a credential')
        with self.assertRaises(ValueError):self.invoke(False)
        with self.assertRaises(ValueError):self.invoke(True)


if __name__=='__main__':unittest.main()
