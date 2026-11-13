"""Safety properties for the deferred destructive closeout; no AWS calls."""
import importlib.util
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'cdk.out/python-tools'))
spec = importlib.util.spec_from_file_location('closeout', ROOT / 'scripts/nonai-closeout.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CloseoutSafety(unittest.TestCase):
    def setUp(self):
        self.plan = {'account': '123456789012', 'endAt': '2099-01-01T00:00:00+00:00',
                     'regions': {}, 'scheduleName': 'test', 'evidenceBucket': 'test'}
        self.plan_patch = patch.object(module, 'PLAN', self.plan)
        self.plan_patch.start()
        self.addCleanup(self.plan_patch.stop)

    def test_no_aws_before_deadline_even_if_execute_requested(self):
        with patch.object(module, 'client') as aws:
            result = module.handler({'mode': 'execute'}, None)
        self.assertEqual(result['status'], 'before-closeout-deadline')
        aws.assert_not_called()

    def test_five_minute_drain_guard(self):
        end = datetime.fromisoformat(self.plan['endAt'])
        self.assertFalse(module.deadline_ready(self.plan, end + timedelta(minutes=4, seconds=59)))
        self.assertTrue(module.deadline_ready(self.plan, end + timedelta(minutes=5)))

    def test_preflight_never_archives_or_mutates(self):
        aws = MagicMock()
        aws.get_caller_identity.return_value = {'Account': self.plan['account']}
        with patch.object(module, 'client', return_value=aws), patch.object(module, 'shared_service_guard', return_value={'safeForAccountWidePause': True}), patch.object(module, 'archive') as archive, patch.object(module, 'shutdown') as shutdown:
            result = module.handler({'mode': 'preflight'}, None)
        self.assertEqual(result['status'], 'read-only-preflight')
        archive.assert_not_called()
        shutdown.assert_not_called()

    def test_failed_archive_blocks_all_shutdown(self):
        self.plan['endAt'] = '2000-01-01T00:00:00+00:00'
        aws = MagicMock(); aws.get_caller_identity.return_value = {'Account': self.plan['account']}
        with patch.object(module, 'client', return_value=aws), patch.object(module, 'shared_service_guard', return_value={}), patch.object(module, 'get', return_value=None), patch.object(module, 'archive', side_effect=RuntimeError('hash mismatch')), patch.object(module, 'shutdown') as shutdown:
            with self.assertRaisesRegex(RuntimeError, 'hash mismatch'):
                module.handler({}, None)
        shutdown.assert_not_called()

    def test_archive_diagnostic_cannot_call_shutdown_or_open_final_gate(self):
        aws = MagicMock(); aws.get_caller_identity.return_value = {'Account': self.plan['account']}
        with patch.object(module, 'client', return_value=aws), patch.object(module, 'shared_service_guard', return_value={}), patch.object(module, 'archive', return_value={'objects': []}) as archive, patch.object(module, 'shutdown') as shutdown, patch.object(module, 'put') as put:
            result = module.handler({'mode': 'archive-check'}, None)
        self.assertFalse(result['shutdownPerformed'])
        archive.assert_called_once_with(preview=True)
        shutdown.assert_not_called()
        put.assert_not_called()

    def test_changed_archive_blocks_reuse(self):
        aws = MagicMock(); aws.get_object.return_value = {'Body': MagicMock()}
        aws.get_object.return_value['Body'].read.return_value = b'changed bytes'
        with patch.object(module, 'get', return_value={'objects': [{'key': 'a', 'sha256': 'wrong'}]}), patch.object(module, 'client', return_value=aws):
            with self.assertRaisesRegex(RuntimeError, 'evidence changed'):
                module.archive()

    def test_wrong_account_blocks_archive(self):
        self.plan['endAt'] = '2000-01-01T00:00:00+00:00'
        aws = MagicMock(); aws.get_caller_identity.return_value = {'Account': '999999999999'}
        with patch.object(module, 'client', return_value=aws), patch.object(module, 'archive') as archive:
            with self.assertRaisesRegex(RuntimeError, 'Wrong AWS account'):
                module.handler({}, None)
        archive.assert_not_called()

    def test_archive_precedes_mutations_and_partial_checks_keep_retry(self):
        self.plan['endAt'] = '2000-01-01T00:00:00+00:00'
        aws = MagicMock(); aws.get_caller_identity.return_value = {'Account': self.plan['account']}
        calls = []
        with patch.object(module, 'client', return_value=aws), patch.object(module, 'shared_service_guard', return_value={}), patch.object(module, 'get', return_value=None), patch.object(module, 'archive', side_effect=lambda: calls.append('archive')), patch.object(module, 'shutdown', side_effect=lambda g: calls.append('shutdown') or []), patch.object(module, 'verify', return_value={'some-service': False}), patch.object(module, 'put') as put:
            with self.assertRaisesRegex(RuntimeError, 'incomplete'):
                module.handler({}, None)
        self.assertEqual(calls, ['archive', 'shutdown'])
        self.assertEqual([c.args[0] for c in put.call_args_list], ['latest'])
        aws.delete_schedule.assert_not_called()


if __name__ == '__main__':
    unittest.main()
