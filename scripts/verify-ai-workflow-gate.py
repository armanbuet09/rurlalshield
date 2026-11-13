"""Offline activation gate; writes nothing and never opens an AWS session."""
from datetime import datetime, timezone
import argparse
import hashlib
import json
from pathlib import Path

from paper_evidence import ROOT, validate_final, verify_local, safe_path


def verify(folder):
    manifest, receipt = verify_local(folder)
    state = json.loads((ROOT/'cdk.out/observation-state.json').read_text())
    if manifest.get('account') != '123456789012' or manifest.get('window') != state['manifest']:
        raise ValueError('Archive belongs to another account/window')
    now = datetime.now(timezone.utc)
    validate_final(manifest, now)
    # A later verification time cannot turn an early capture into a valid final copy.
    captured = datetime.fromisoformat(manifest['capturedAt'])
    if captured > now:
        raise ValueError('Archive capture timestamp is in the future')
    validate_final(manifest, captured)
    latest = {item['key']:item for item in manifest['s3Objects']
              if item['bucket'] == state['outputs']['EvidenceBucket'] and item['isLatest']}
    completed = latest.get('closeout/completed.json')
    if not completed:
        raise ValueError('Missing pinned native completion receipt')
    raw = safe_path(folder/'payload', completed['path']).read_bytes()
    metadata = manifest['nativeCloseoutObject']
    if (not isinstance(metadata.get('versionId'),str) or not metadata['versionId']
            or hashlib.sha256(raw).hexdigest() != metadata['sha256']
            or completed.get('versionId') != metadata.get('versionId')
            or json.loads(raw) != manifest['nativeCloseout']):
        raise ValueError('Pinned native receipt differs from final archive metadata')
    source = latest.get('freeze/source.zip')
    frozen = state['manifest']['sourceArchiveSha256']
    if not source or hashlib.sha256(safe_path(folder/'payload', source['path']).read_bytes()).hexdigest() != frozen:
        raise ValueError('Frozen source archive is absent or changed')
    gate = latest.get('closeout/archive-verified.json')
    if not gate:
        raise ValueError('Missing archived cloud final manifest')
    document = json.loads(safe_path(folder/'payload', gate['path']).read_text())
    if not document.get('objects'):
        raise ValueError('Archived cloud final manifest is empty')
    for item in document['objects']:
        local = latest.get(item['key'])
        if (not local or local['sha256'] != item['sha256']
                or hashlib.sha256(safe_path(folder/'payload', local['path']).read_bytes()).hexdigest() != item['sha256']):
            raise ValueError('Archived cloud final manifest does not match pinned exports')
    return {'archive':str(folder.resolve()), 'manifest_sha256':receipt['manifestSha256'],
            'zip_sha256':receipt['zipSha256'], 'files_verified':receipt['filesVerified'],
            'activation_gate':'verified_offline_final_archive', 'aws_calls':0}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.archive)))
    except (ValueError, OSError, KeyError):
        raise SystemExit('Final archive activation gate failed; verify the final archive and frozen source first')
