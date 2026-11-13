"""Local CLI process-provider refresh policy for short-lived AWS login credentials.

Botocore's default 15/10-minute refresh windows overlap the CLI login credential
lifetime. Narrow these windows on this session's process credentials only. Actual
AWS expiry, refresh callback and expired-credential rejection remain unchanged.
"""
from datetime import datetime


def configure_process_refresh(session):
    credentials = session.get_credentials()
    if (getattr(credentials, 'method', None) != 'custom-process'
            or not isinstance(getattr(credentials, '_expiry_time', None), datetime)):
        return {'changed': False}
    if not all(hasattr(credentials, name) for name in
               ('_advisory_refresh_timeout', '_mandatory_refresh_timeout')):
        raise ValueError('Unsupported process-provider credential refresh interface')
    credentials._advisory_refresh_timeout = 300
    credentials._mandatory_refresh_timeout = 60
    return {'changed': True, 'advisorySeconds': 300, 'mandatorySeconds': 60,
            'awsExpiryUnchanged': True}
