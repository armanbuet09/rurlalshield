"""Expiry and non-process identities must not be altered by the local fix."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from local_aws_session import configure_process_refresh


class LocalRefresh(unittest.TestCase):
    def test_short_process_credentials_keep_real_expiry_and_refresh_callback(self):
        expiry=datetime.now(timezone.utc)+timedelta(minutes=14)
        refresh=object()
        credentials=SimpleNamespace(method='custom-process',_expiry_time=expiry,
            _refresh_using=refresh,_advisory_refresh_timeout=900,_mandatory_refresh_timeout=600)
        session=Mock();session.get_credentials.return_value=credentials
        result=configure_process_refresh(session)
        self.assertEqual((credentials._advisory_refresh_timeout,credentials._mandatory_refresh_timeout),(300,60))
        self.assertIs(credentials._expiry_time,expiry)
        self.assertIs(credentials._refresh_using,refresh)
        self.assertTrue(result['awsExpiryUnchanged'])

    def test_other_providers_and_static_process_credentials_are_unchanged(self):
        for method,expiry in [('iam-role',datetime.now(timezone.utc)),('env',None),('custom-process',None)]:
            credentials=SimpleNamespace(method=method,_expiry_time=expiry,
                _advisory_refresh_timeout=900,_mandatory_refresh_timeout=600)
            session=Mock();session.get_credentials.return_value=credentials
            self.assertFalse(configure_process_refresh(session)['changed'])
            self.assertEqual((credentials._advisory_refresh_timeout,credentials._mandatory_refresh_timeout),(900,600))

    def test_unsupported_refresh_interface_refuses_instead_of_changing_expiry(self):
        credentials=SimpleNamespace(method='custom-process',_expiry_time=datetime.now(timezone.utc))
        session=Mock();session.get_credentials.return_value=credentials
        with self.assertRaises(ValueError):configure_process_refresh(session)


if __name__=='__main__':unittest.main()
