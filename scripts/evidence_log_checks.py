"""Read every selected owned log event with bounded parallelism; never delete.

The caller supplies already initialized clients through read_events and the same
canonical encoder used by its archive. Each completed full check is yielded
immediately, so a caller can delete that group without waiting for slower groups.
A failed group read never produces an authorizing result for that group.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib


def recheck_logs(groups, read_events, encode):
    def check(group):
        started = datetime.now(timezone.utc).isoformat()
        digest, count = hashlib.sha256(), 0
        for event in read_events(group['region'], group['name']):
            digest.update(encode(event) + b'\n')
            count += 1
        return {'group': group, 'sha256': digest.hexdigest(), 'count': count,
                'startedAt': started, 'finishedAt': datetime.now(timezone.utc).isoformat()}
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(check, group) for group in groups]
        for future in as_completed(futures):
            yield future.result()
