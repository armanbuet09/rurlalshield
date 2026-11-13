"""Full-content recheck semantics must survive parallel reads."""
import hashlib
import json
import unittest
from threading import Event

from evidence_log_checks import recheck_logs


def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


class LogChecks(unittest.TestCase):
    def test_full_stream_order_counts_and_archive_digest_are_preserved(self):
        groups = [{'region':'ohio','name':'one'},{'region':'oregon','name':'two'}]
        content = {'one':[{'eventId':'b','message':'second sort field'}, {'eventId':'a','message':'same timestamp'}], 'two':[]}
        checked = list(recheck_logs(groups, lambda region,name:iter(content[name]), encode))
        self.assertEqual(sorted(x['group']['name'] for x in checked),['one','two'])
        for row in checked:
            events=content[row['group']['name']]
            self.assertEqual(row['count'],len(events))
            self.assertEqual(row['sha256'],hashlib.sha256(b''.join(encode(x)+b'\n' for x in events)).hexdigest())
            self.assertLessEqual(row['startedAt'],row['finishedAt'])

    def test_failure_after_partial_stream_returns_no_authorizing_result(self):
        def stream(region,name):
            yield {'eventId':'already read'}
            raise RuntimeError('unavailable')
        with self.assertRaisesRegex(RuntimeError,'unavailable'):
            list(recheck_logs([{'region':'ohio','name':'one'}],stream,encode))

    def test_changed_message_changes_digest_even_with_equal_event_count(self):
        group=[{'region':'ohio','name':'one'}]
        a=list(recheck_logs(group,lambda *args:iter([{'eventId':'same','message':'old'}]),encode))[0]
        b=list(recheck_logs(group,lambda *args:iter([{'eventId':'same','message':'new'}]),encode))[0]
        self.assertEqual(a['count'],b['count'])
        self.assertNotEqual(a['sha256'],b['sha256'])

    def test_completed_check_is_delivered_before_slow_group_finishes(self):
        release=Event();slow_finished=Event()
        def stream(region,name):
            if name=='slow':
                release.wait(10)
                slow_finished.set()
            return iter([{'eventId':name}])
        checks=recheck_logs([{'region':'ohio','name':'slow'}, {'region':'ohio','name':'fast'}],stream,encode)
        try:
            first=next(checks)
            self.assertEqual(first['group']['name'],'fast')
            self.assertFalse(slow_finished.is_set())
        finally:release.set()
        self.assertEqual(list(checks)[0]['group']['name'],'slow')


if __name__=='__main__':unittest.main()
