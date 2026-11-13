"""Offline safeguards for the exact-version batch deletion transport."""
import unittest
from unittest.mock import Mock

from retire_archived_versions import delete_verified_batches


class RetirementTransport(unittest.TestCase):
    def client(self):
        client = Mock()
        client.get_object_lock_configuration.return_value = {}
        client.delete_objects.side_effect = lambda **kw: {'Deleted': kw['Delete']['Objects']}
        return client

    def test_bounded_batches_recheck_lock_and_journal_exact_confirmations(self):
        client = self.client(); journal = []
        versions = [{'Key': 'synthetic/' + str(i), 'VersionId': 'v' + str(i)} for i in range(1001)]
        self.assertEqual(delete_verified_batches(client, 'owned', versions, lambda *x: journal.append(x)), 1001)
        self.assertEqual(client.get_object_lock_configuration.call_count, 2)
        self.assertEqual([len(c.kwargs['Delete']['Objects']) for c in client.delete_objects.call_args_list], [1000, 1])
        self.assertEqual(set(journal), {(x['Key'], x['VersionId']) for x in versions})
        self.assertTrue(all(c.kwargs['Delete']['Quiet'] is False for c in client.delete_objects.call_args_list))
        self.assertTrue(all('BypassGovernanceRetention' not in c.kwargs for c in client.delete_objects.call_args_list))

    def test_null_empty_and_duplicate_identities_refused_before_any_write(self):
        for versions in ([{'Key':'a','VersionId':'null'}], [{'Key':'a','VersionId':''}],
                         [{'Key':'a'}], [{'Key':'','VersionId':'v'}],
                         [{'Key':'a','VersionId':'v'}] * 2):
            with self.subTest(versions=versions):
                client = self.client()
                with self.assertRaises(ValueError): delete_verified_batches(client, 'owned', versions, Mock())
                client.delete_objects.assert_not_called()

    def test_lock_enabled_between_batches_stops_future_writes(self):
        client = self.client(); client.get_object_lock_configuration.side_effect = [
            {}, {'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled'}}]
        versions = [{'Key':str(i),'VersionId':'v'} for i in range(1001)]
        journal = Mock()
        with self.assertRaisesRegex(ValueError, 'Object Lock'):
            delete_verified_batches(client, 'owned', versions, journal)
        self.assertEqual(journal.call_count, 1000)
        self.assertEqual(client.delete_objects.call_count, 1)

    def test_http_success_with_per_object_error_journals_only_confirmed_versions(self):
        client = self.client(); client.delete_objects.side_effect = None
        client.delete_objects.return_value = {'Deleted':[{'Key':'a','VersionId':'v1'}],
            'Errors':[{'Key':'b','VersionId':'v2','Code':'AccessDenied'}]}
        journal = Mock()
        with self.assertRaisesRegex(ValueError, 'Partial'):
            delete_verified_batches(client, 'owned', [{'Key':'a','VersionId':'v1'},{'Key':'b','VersionId':'v2'}], journal)
        journal.assert_called_once_with('a','v1')

    def test_missing_duplicate_or_foreign_results_are_failures(self):
        for deleted in ([],[{'Key':'foreign','VersionId':'v'}],
                        [{'Key':'a','VersionId':'v'}]*2):
            client = self.client();client.delete_objects.side_effect = None
            client.delete_objects.return_value = {'Deleted':deleted}
            with self.assertRaisesRegex(ValueError, 'ambiguous'):
                delete_verified_batches(client,'owned',[{'Key':'a','VersionId':'v'}],Mock())

    def test_lock_check_error_prevents_deletion(self):
        client = self.client();client.get_object_lock_configuration.side_effect = RuntimeError('unavailable')
        with self.assertRaises(RuntimeError):
            delete_verified_batches(client,'owned',[{'Key':'a','VersionId':'v'}],Mock())
        client.delete_objects.assert_not_called()


if __name__ == '__main__':unittest.main()
