"""Copy only reviewed runtime source into a standalone, undeployed AWS asset."""
from pathlib import Path
import hashlib
import json
import shutil

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    'src/external_ai_workflow/cases.py':'cases.py',
    'src/external_ai_workflow/runtime.py':'runtime.py',
    'src/external_ai_workflow/handlers.py':'handlers.py',
    'src/external_ai/adapter.py':'adapter.py',
    'src/external_ai/experiment.py':'experiment.py',
    'src/lambda/triage/policy.py':'policy.py',
    'src/lambda/triage/prompts.py':'prompts.py',
    'src/lambda/contain/handler.py':'original_contain.py',
}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    dest = ROOT/'cdk.out/external-ai-workflow-asset'
    if args.verify:
        hashes = json.loads((dest/'source-manifest.json').read_text())
        if set(hashes) != set(FILES):
            raise ValueError('Unexpected package manifest')
        if set(p.name for p in dest.iterdir()) != set(FILES.values()) | {'source-manifest.json'}:
            raise ValueError('Unexpected packaged file')
        for source, target in FILES.items():
            if hashes[source] != hashlib.sha256((ROOT/source).read_bytes()).hexdigest() or hashes[source] != hashlib.sha256((dest/target).read_bytes()).hexdigest():
                raise ValueError('Stale or changed packaged source')
        print(json.dumps({'status':'verified_only','files':len(FILES),'aws_calls':0,'model_calls':0}))
        return
    dest.mkdir(parents=True, exist_ok=True)
    # An old or foreign file must not silently enter a Lambda asset.
    unexpected = [p.name for p in dest.iterdir() if p.name not in set(FILES.values()) | {'source-manifest.json'}]
    if unexpected:
        raise ValueError('Unexpected asset contents; use a fresh reviewed output directory')
    hashes = {}
    for source, target in FILES.items():
        shutil.copyfile(ROOT/source, dest/target)
        hashes[source] = hashlib.sha256((dest/target).read_bytes()).hexdigest()
    (dest/'source-manifest.json').write_text(json.dumps(hashes,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':'packaged_only', 'files':len(FILES), 'aws_calls':0, 'model_calls':0}))


if __name__ == '__main__':
    main()
