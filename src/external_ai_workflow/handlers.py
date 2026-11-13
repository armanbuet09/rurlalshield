"""Lambda entry points. Do not print events, secrets, task tokens or bearer links."""
import os

from runtime import Store, Workflow, page


def build():
    import boto3
    from botocore.config import Config
    sdk = Config(retries={'max_attempts':0}, connect_timeout=5, read_timeout=50)
    session = boto3.Session()
    clients = {service:session.client(service, config=sdk)
               for service in ('sns','secretsmanager','stepfunctions','lambda')}
    table = session.resource('dynamodb', config=sdk).Table(os.environ['INCIDENTS_TABLE'])
    config = {'suite':os.environ['SUITE_ID'], 'enabled':os.environ.get('WORKFLOW_ENABLED','false'),
              'budget':os.environ['MODEL_ESTIMATE_BUDGET_USD'],
              'target':os.environ['DISPOSABLE_TARGET_ARN'], 'topic':os.environ['ALERTS_TOPIC_ARN'],
              'api_secret':os.environ.get('API_SECRET_ARN',''),
              'signing_secret':os.environ.get('SIGNING_SECRET_ARN',''),
              'approval_url':os.environ.get('APPROVAL_URL','')}
    return Workflow(config, Store(table, config['suite']), clients)


def run(method, event):
    try:
        return getattr(build(), method)(event)
    except Exception:
        # Step Functions records failure; a stuck budget/action is never auto-reset.
        raise RuntimeError('Isolated workflow step failed; inspect scoped private records') from None


def triage(event, context):
    return run('triage', event)


def request_approval(event, context):
    return run('request_approval', event)


def decision(event, context):
    try:
        return build().decision(event)
    except Exception:
        return page(503, 'Decision unavailable; inspect private workflow records')


def contain(event, context):
    return run('contain', event)


def rollback(event, context):
    return run('rollback', event)


def finish(event, context):
    return run('finish', event)
