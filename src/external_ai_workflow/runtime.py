"""Isolated synthetic workflow; no access to the non-AI application or evidence."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import hmac
from html import escape
import json
import math
import re
from urllib.parse import parse_qs, urlencode

import adapter
import cases

RESERVE = Decimal('0.01')


def json_value(value):
    if isinstance(value, dict):
        return {k: json_value(v) for k,v in value.items()}
    if isinstance(value, (list,tuple)):
        return [json_value(v) for v in value]
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError('Nonfinite evidence')
        return Decimal(str(value))
    if isinstance(value, Decimal) and not value.is_finite():
        raise ValueError('Nonfinite evidence')
    return value


def conditional(error):
    return getattr(error, 'response', {}).get('Error', {}).get('Code') == 'ConditionalCheckFailedException'


class Store:
    """All writes and compare-and-set decisions are scoped to one configured suite."""
    def __init__(self, table, suite):
        self.table, self.suite = table, suite

    def key(self, key):
        return {'pk': self.suite + '#' + key}

    def get(self, key):
        return self.table.get_item(Key=self.key(key), ConsistentRead=True).get('Item', {})

    def claim(self, key, item):
        try:
            self.table.put_item(Item={**self.key(key), **json_value(item)},
                                ConditionExpression='attribute_not_exists(pk)')
            return True
        except Exception as error:
            if conditional(error):
                return False
            raise

    def update(self, key, values, expected=None):
        names = {f'#n{i}': k for i,k in enumerate(values)}
        vals = {f':v{i}': v for i,v in enumerate(json_value(values).values())}
        kwargs = {'Key': self.key(key),
                  'UpdateExpression': 'SET ' + ', '.join(f'#n{i} = :v{i}' for i in range(len(values))),
                  'ExpressionAttributeNames': names, 'ExpressionAttributeValues': vals}
        if expected is not None:
            names['#expected'] = 'status'; vals[':expected'] = expected
            kwargs['ConditionExpression'] = '#expected = :expected'
        try:
            self.table.update_item(**kwargs)
            return True
        except Exception as error:
            if conditional(error):
                return False
            raise

    def reserve(self, budget):
        self.claim('BUDGET', {'status': 'OPEN', 'remaining': budget})
        try:
            self.table.update_item(Key=self.key('BUDGET'),
                UpdateExpression='SET #s = :busy, remaining = remaining - :reserve',
                ConditionExpression='#s = :open AND remaining >= :reserve',
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':busy':'INFLIGHT', ':open':'OPEN', ':reserve':RESERVE})
            return True
        except Exception as error:
            if conditional(error):
                return False
            raise

    def settle(self, cost, valid):
        known = cost is not None and Decimal(str(cost)).is_finite() and 0 <= Decimal(str(cost)) <= RESERVE
        if not valid or not known:
            self.update('BUDGET', {'status': 'BLOCKED'}, expected='INFLIGHT')
            return
        self.table.update_item(Key=self.key('BUDGET'),
            UpdateExpression='SET #s = :open, remaining = remaining + :refund',
            ConditionExpression='#s = :busy', ExpressionAttributeNames={'#s':'status'},
            ExpressionAttributeValues={':open':'OPEN', ':busy':'INFLIGHT', ':refund':RESERVE-Decimal(str(cost))})

    def consume_approval(self, key, action, now):
        try:
            self.table.update_item(Key=self.key(key),
                UpdateExpression='SET #s = :decided, decision = :action, decided_at = :now',
                ConditionExpression='#s = :pending AND expires > :now',
                ExpressionAttributeNames={'#s':'status'},
                ExpressionAttributeValues={':decided':'DECIDED', ':pending':'PENDING', ':action':action, ':now':now})
            return True
        except Exception as error:
            if conditional(error):
                return False
            raise


class Workflow:
    def __init__(self, config, store, clients, clock=None):
        self.cfg, self.store, self.clients = config, store, clients
        self.clock = clock or (lambda: datetime.now(timezone.utc).timestamp())

    def now(self):
        return int(self.clock())

    def enabled(self):
        return self.cfg.get('enabled') == 'true'

    def incident(self, identity):
        if not isinstance(identity, str) or not re.fullmatch(r'[a-f0-9]{24}', identity):
            raise ValueError('Invalid incident')
        item = self.store.get('INCIDENT#' + identity)
        if item.get('suite_id') != self.cfg['suite']:
            raise ValueError('Unknown incident')
        return item

    def publish(self, subject, body):
        result = self.clients['sns'].publish(TopicArn=self.cfg['topic'],
                                            Subject=subject[:100], Message=body)
        return result['MessageId']

    def triage(self, event):
        if not self.enabled():
            return {'route':'STOP', 'status':'DISABLED'}
        case = cases.validate_input(event, self.cfg['suite'])
        identity = hashlib.sha256((self.cfg['suite'] + ':' + case).encode()).hexdigest()[:24]
        key = 'INCIDENT#' + identity
        if not self.store.claim(key, {'suite_id':self.cfg['suite'], 'case_id':case,
                                     'incident_id':identity, 'status':'CLAIMED',
                                     'claimed_at':self.now()}):
            return {'route':'STOP', 'status':'DUPLICATE', 'incident_id':identity}
        kind = 'model' if case in cases.MODEL_CASES else 'scripted_control'
        if kind == 'model':
            if not self.store.reserve(Decimal(self.cfg['budget'])):
                self.store.update(key, {'status':'BUDGET_BLOCKED'})
                return {'route':'STOP', 'status':'BUDGET_BLOCKED', 'incident_id':identity}
            try:
                secret = self.clients['secretsmanager'].get_secret_value(SecretId=self.cfg['api_secret'])
                record = cases.evaluate(case, self.cfg['target'], secret.get('SecretString', ''))
            except Exception:
                # INFLIGHT/BLOCKED is deliberately never auto-reset after uncertain work.
                record = {'status':'credential_or_execution_error', 'estimated_usd':None}
            estimate = record.get('estimated_usd')
            valid = (record['status'] == 'valid_response' and estimate is not None
                     and Decimal(str(estimate)).is_finite() and 0 <= Decimal(str(estimate)) <= RESERVE)
        else:
            record = cases.control(case, self.cfg['target'])
            valid = case != 'control_model_failure'
        decision = record.get('policy_simulation') if valid else None
        decision = decision or {'action_mode':'NOTIFY', 'playbook':'ESCALATE_ONLY', 'targets':[],
                                'reasons':['Model unavailable, invalid or unpriced; no action permitted']}
        # Use immutable policy output, never an action or target supplied by an event/model.
        route = 'APPROVAL' if decision['action_mode'] == 'APPROVAL' else 'NOTIFY'
        if case == 'control_timeout':
            route = 'APPROVAL_TIMEOUT_CONTROL'
        if case == 'weekly_narration' and valid:
            route = 'REPORT'
        self.store.update(key, {'status':'TRIAGED', 'evidence_kind':kind,
                               'model_record':record, 'decision':decision, 'route':route,
                               'model_valid':valid if kind == 'model' else False})
        if kind == 'model':
            # Persist the response first. If that fails, budget stays INFLIGHT.
            self.store.settle(record.get('estimated_usd'), valid)
        return {'route':route, 'incident_id':identity, 'case_id':case, 'evidence_kind':kind}

    def request_approval(self, event):
        if not self.enabled():
            raise ValueError('Workflow disabled')
        item = self.incident(event['incident_id'])
        if item.get('route') not in ('APPROVAL', 'APPROVAL_TIMEOUT_CONTROL'):
            raise ValueError('Incident does not permit approval')
        token = event['taskToken']
        if not isinstance(token, str) or not 1 <= len(token) <= 4096:
            raise ValueError('Invalid callback token')
        approval_id = hashlib.sha256(('approval:' + item['incident_id']).encode()).hexdigest()[:32]
        secret = self.clients['secretsmanager'].get_secret_value(SecretId=self.cfg['signing_secret'], VersionStage='AWSCURRENT')
        lifetime = 10 if item['case_id'] == 'control_timeout' else 900
        approval = {'status':'PENDING', 'incident_id':item['incident_id'],
                    'version':secret['VersionId'], 'expires':self.now()+lifetime,
                    'task_token':token, 'suite_id':self.cfg['suite']}
        if not self.store.claim('APPROVAL#'+approval_id, approval):
            raise ValueError('Approval already requested; do not reissue a callback')
        self.store.update('INCIDENT#'+item['incident_id'], {'approval_id':approval_id})
        links = []
        for action in ('approve','deny'):
            signature = sign(secret['SecretString'], approval_id, action)
            links.append(action.upper()+': '+self.cfg['approval_url']+'?'+urlencode({'id':approval_id,'action':action,'sig':signature}))
        message = ('SYNTHETIC RuralShield research workflow\nCase: '+item['case_id']+'\nEvidence: '+item['evidence_kind']
                   +'\nProposed: '+item['decision']['playbook']+'\nTarget: '+self.cfg['target']
                   +'\nAn approved action is limited to the disposable test Lambda and is followed by a verified rollback attempt.'
                   +'\nNo non-AI pilot resource may be changed. Confirm your decision on the opened page.\n'
                   +'\n'.join(links)+'\nExpires at UTC epoch '+str(approval['expires']))
        message_id = self.publish('[RuralShield AI research] Human decision required', message)
        self.store.update('APPROVAL#'+approval_id, {'sns_message_id':message_id})
        # No task token, signing key or bearer link enters the return payload/logs.
        return {'approval_id':approval_id, 'expires':approval['expires']}

    def decision(self, event):
        if not self.enabled():
            return page(503, 'Workflow disabled')
        method = event.get('requestContext', {}).get('http', {}).get('method', '')
        if method == 'GET':
            fields = event.get('queryStringParameters') or {}
        elif method == 'POST':
            try:
                body = event.get('body') or ''
                if len(body) > 8192:
                    return page(400, 'Invalid request')
                if event.get('isBase64Encoded'):
                    body = base64.b64decode(body, validate=True).decode('utf-8')
                parsed = parse_qs(body, strict_parsing=True)
                if any(len(v) != 1 for v in parsed.values()):
                    return page(400, 'Invalid request')
                fields = {k:v[0] for k,v in parsed.items()}
            except (ValueError, UnicodeError):
                return page(400, 'Invalid request')
        else:
            return page(405, 'Use the confirmation page')
        if (set(fields) != {'id','action','sig'} or not all(isinstance(v,str) for v in fields.values())
                or not re.fullmatch(r'[a-f0-9]{32}',fields['id']) or fields['action'] not in ('approve','deny')
                or not re.fullmatch(r'[a-f0-9]{64}',fields['sig'])):
            return page(400, 'Invalid link')
        key = 'APPROVAL#'+fields['id']
        approval = self.store.get(key)
        if approval.get('suite_id') != self.cfg['suite'] or approval.get('status') != 'PENDING' or approval.get('expires',0) <= self.now():
            return page(410, 'Decision already recorded or expired')
        secret = self.clients['secretsmanager'].get_secret_value(SecretId=self.cfg['signing_secret'], VersionId=approval['version'])
        if not hmac.compare_digest(fields['sig'],sign(secret['SecretString'], fields['id'], fields['action'])):
            return page(403, 'Invalid link')
        if method == 'GET':
            # Email scanners and link previews cannot approve an action with GET.
            return page(200, 'Confirm '+fields['action'], fields)
        # Clock and status are checked atomically in the concrete store operation.
        if not self.store.consume_approval(key, fields['action'], self.now()):
            return page(410, 'Decision already recorded or expired')
        try:
            self.clients['stepfunctions'].send_task_success(taskToken=approval['task_token'],
                output=json.dumps({'approved':fields['action']=='approve', 'approval_id':fields['id']}))
            self.store.update(key, {'callback':'ACCEPTED'})
        except Exception:
            self.store.update(key, {'callback':'FAILED_OR_UNCERTAIN'})
            return page(503, 'Decision recorded; callback needs operator review. Do not retry the action.')
        return page(200, 'Decision recorded; inspect the workflow outcome')

    def contain(self, event):
        if not self.enabled():
            return {'status':'DISABLED'}
        item = self.incident(event['incident_id'])
        approval = self.store.get('APPROVAL#'+str(event.get('approval_id','')))
        decision = item.get('decision', {})
        targets = decision.get('targets', [])
        if (approval.get('incident_id') != item['incident_id'] or approval.get('suite_id') != self.cfg['suite']
                or approval.get('status') != 'DECIDED' or approval.get('decision') != 'approve'
                or approval.get('expires',0) <= self.now() or item.get('approval_id') != event.get('approval_id')
                or decision.get('action_mode') != 'APPROVAL' or decision.get('playbook') != 'QUARANTINE_LAMBDA_FUNCTION'
                or len(targets) != 1 or targets[0].get('type') != 'lambda-function'
                or targets[0].get('id') != self.cfg['target']
                or targets[0].get('name') != self.cfg['target'].split(':function:')[-1]):
            return {'status':'REFUSED'}
        action_key = 'ACTION#'+item['incident_id']
        if not self.store.claim(action_key, {'status':'STARTED', 'target':self.cfg['target']}):
            return {'status':'DUPLICATE_OR_UNCERTAIN'}
        client = self.clients['lambda']
        tags = client.list_tags(Resource=self.cfg['target']).get('Tags',{})
        if tags.get('rural-shield:experiment-target') != self.cfg['suite'] or tags.get('rural-shield:protected') != 'false':
            self.store.update(action_key, {'status':'REFUSED_TAGS'})
            return {'status':'REFUSED'}
        before = client.get_function_concurrency(FunctionName=self.cfg['target']).get('ReservedConcurrentExecutions')
        if before != 1:
            self.store.update(action_key, {'status':'REFUSED_PRIOR_STATE'})
            return {'status':'REFUSED'}
        self.store.update(action_key, {'previous_concurrency':before, 'status':'MUTATION_PENDING'})
        # Reuse the existing tested playbook; IAM still only permits this exact target.
        import original_contain
        original_contain._lambda = client
        result = original_contain.quarantine_lambda(targets[0])
        after = client.get_function_concurrency(FunctionName=self.cfg['target']).get('ReservedConcurrentExecutions')
        self.store.update(action_key, {'status':'CONTAINED' if after == 0 else 'VERIFY_FAILED',
                                       'observed_concurrency':after, 'playbook_result':result})
        return {'status':'CONTAINED' if after == 0 else 'VERIFY_FAILED'}

    def rollback(self, event):
        if not self.enabled():
            return {'status':'DISABLED'}
        identity = self.incident(event['incident_id'])['incident_id']
        key = 'ACTION#'+identity
        action = self.store.get(key)
        if action.get('target') != self.cfg['target'] or action.get('previous_concurrency') != 1:
            return {'status':'REFUSED'}
        if not self.store.update(key, {'status':'ROLLBACK_STARTED'}, expected='CONTAINED'):
            return {'status':'REFUSED_OR_UNCERTAIN'}
        client = self.clients['lambda']
        tags = client.list_tags(Resource=self.cfg['target']).get('Tags',{})
        current = client.get_function_concurrency(FunctionName=self.cfg['target']).get('ReservedConcurrentExecutions')
        if (tags.get('rural-shield:experiment-target') != self.cfg['suite']
                or tags.get('rural-shield:protected') != 'false' or current != 0):
            self.store.update(key, {'status':'ROLLBACK_REFUSED_CHANGED_STATE'})
            return {'status':'REFUSED'}
        client.put_function_concurrency(FunctionName=self.cfg['target'], ReservedConcurrentExecutions=1)
        observed = client.get_function_concurrency(FunctionName=self.cfg['target']).get('ReservedConcurrentExecutions')
        status = 'ROLLED_BACK' if observed == 1 else 'ROLLBACK_VERIFY_FAILED'
        self.store.update(key, {'status':status, 'restored_concurrency':observed})
        return {'status':status}

    def finish(self, event):
        if not self.enabled():
            return {'status':'DISABLED'}
        item = self.incident(event['triage']['incident_id'])
        outcome = event['outcome']['status']
        if outcome not in ('NOTIFIED','REPORT_SENT','APPROVAL_DENIED','APPROVAL_TIMEOUT',
                            'ROLLED_BACK','CONTAINMENT_REFUSED','ROLLBACK_FAILED','WORKFLOW_FAILED'):
            raise ValueError('Invalid outcome')
        if not self.store.claim('FINISH#'+item['incident_id'], {'status':'SENDING', 'outcome':outcome}):
            return {'status':'DUPLICATE_OR_UNCERTAIN', 'incident_id':item['incident_id']}
        output = item.get('model_record',{}).get('validated_output',{})
        text = output if isinstance(output,str) else output.get('plain_english_summary','No valid model assessment')
        message = ('SYNTHETIC RuralShield AWS experiment\nCase: '+item['case_id']+'\nEvidence: '+item['evidence_kind']
                   +'\nOutcome: '+outcome+'\n'+text+'\nNo non-AI pilot data was used.'
                   +'\nSNS acceptance is not confirmation of email delivery; review the private incident/action records.')
        message_id = self.publish('[RuralShield AI research] '+outcome, message)
        self.store.update('FINISH#'+item['incident_id'], {'status':'ACCEPTED', 'sns_message_id':message_id})
        self.store.update('INCIDENT#'+item['incident_id'], {'status':outcome, 'finished_at':self.now()})
        return {'status':outcome, 'incident_id':item['incident_id'], 'evidence_kind':item['evidence_kind']}


def sign(key, approval, action):
    return hmac.new(key.encode(), (approval+':'+action).encode(), hashlib.sha256).hexdigest()


def page(status, title, fields=None):
    form = ''
    if fields:
        form = '<form method="post" action="/">'+''.join('<input type="hidden" name="'+escape(k)+'" value="'+escape(v,quote=True)+'">' for k,v in fields.items())+'<button type="submit">Confirm '+escape(fields['action'])+'</button></form>'
    return {'statusCode':status, 'headers':{'Content-Type':'text/html; charset=utf-8',
            'Cache-Control':'no-store', 'Referrer-Policy':'no-referrer',
            'X-Content-Type-Options':'nosniff', 'Strict-Transport-Security':'max-age=31536000',
            'Content-Security-Policy':"default-src 'none'; form-action 'self'; frame-ancestors 'none'"},
            'body':'<!doctype html><meta charset="utf-8"><title>RuralShield research</title><h1>'+escape(title)+'</h1>'+form}
