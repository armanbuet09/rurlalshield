"""Offline boundary tests; no model requests or AWS mutations."""
import copy
from decimal import Decimal
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src/external_ai_workflow'),str(ROOT/'src/external_ai'),str(ROOT/'src/lambda/triage')]
import cases
import runtime

TARGET='arn:aws:lambda:us-east-2:123456789012:function:disposable'
SUITE='test-suite'


class MemoryStore:
    def __init__(self): self.rows={}
    def get(self,key): return copy.deepcopy(self.rows.get(key,{}))
    def claim(self,key,item):
        if key in self.rows: return False
        self.rows[key]=copy.deepcopy(item);return True
    def update(self,key,values,expected=None):
        if expected is not None and self.rows.get(key,{}).get('status')!=expected:return False
        self.rows.setdefault(key,{}).update(copy.deepcopy(values));return True
    def reserve(self,budget):
        self.claim('BUDGET',{'status':'OPEN','remaining':budget})
        b=self.rows['BUDGET']
        if b['status']!='OPEN' or b['remaining']<runtime.RESERVE:return False
        b.update(status='INFLIGHT',remaining=b['remaining']-runtime.RESERVE);return True
    def settle(self,cost,valid):
        b=self.rows['BUDGET']
        if not valid or cost is None or Decimal(str(cost))>runtime.RESERVE:
            b['status']='BLOCKED';return
        b.update(status='OPEN',remaining=b['remaining']+runtime.RESERVE-Decimal(str(cost)))
    def consume_approval(self,key,action,now):
        a=self.rows.get(key,{})
        if a.get('status')!='PENDING' or a.get('expires',0)<=now:return False
        a.update(status='DECIDED',decision=action,decided_at=now);return True


class LambdaTarget:
    def __init__(self): self.concurrency=1;self.mutations=[];self.tags={'rural-shield:experiment-target':SUITE,'rural-shield:protected':'false'}
    def list_tags(self,Resource):
        assert Resource==TARGET
        return {'Tags':copy.deepcopy(self.tags)}
    def get_function_concurrency(self,FunctionName):
        assert FunctionName in (TARGET,'disposable')
        return {'ReservedConcurrentExecutions':self.concurrency}
    def put_function_concurrency(self,FunctionName,ReservedConcurrentExecutions):
        assert FunctionName in (TARGET,'disposable')
        self.concurrency=ReservedConcurrentExecutions;self.mutations.append(ReservedConcurrentExecutions)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.store=MemoryStore();self.target=LambdaTarget();self.time=10000
        self.cfg={'suite':SUITE,'enabled':'true','budget':'0.048631325','target':TARGET,
                  'topic':'own-topic','api_secret':'api-secret','signing_secret':'signing-secret',
                  'approval_url':'https://example.invalid/'}
        self.sns=Mock();self.sns.publish.return_value={'MessageId':'accepted'}
        self.secrets=Mock();self.secrets.get_secret_value.return_value={'SecretString':'mock-key-not-real','VersionId':'version-one'}
        self.sfn=Mock()
        self.flow=runtime.Workflow(self.cfg,self.store,{'sns':self.sns,'lambda':self.target,
            'secretsmanager':self.secrets,'stepfunctions':self.sfn},clock=lambda:self.time)
        boto=types.ModuleType('boto3');boto.client=lambda service:Mock();boto.resource=lambda service:Mock()
        errors=types.ModuleType('botocore.exceptions');errors.ClientError=type('ClientError',(Exception,),{})
        with patch.dict(sys.modules,{'boto3':boto,'botocore':types.ModuleType('botocore'),'botocore.exceptions':errors}),patch.dict(os.environ,INCIDENTS_TABLE='own-table',ALERTS_TOPIC_ARN='own-topic'):
            spec=importlib.util.spec_from_file_location('original_contain',ROOT/'src/lambda/contain/handler.py')
            self.original=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.original)
        patcher=patch.dict(sys.modules,{'original_contain':self.original});patcher.start();self.addCleanup(patcher.stop)

    def event(self,case):return {'suite_id':SUITE,'case_id':case}
    def approval(self,case='control_approve'):
        triage=self.flow.triage(self.event(case))
        approval=self.flow.request_approval({'incident_id':triage['incident_id'],'taskToken':'private-test-callback'})
        return triage,approval
    def decision_event(self,approval,action='approve',method='POST'):
        fields={'id':approval['approval_id'],'action':action,
                'sig':runtime.sign('mock-key-not-real',approval['approval_id'],action)}
        return {'requestContext':{'http':{'method':method}},
                'queryStringParameters':fields,'body':urlencode(fields)}
    def approved_action(self):
        t,a=self.approval();self.assertEqual(self.flow.decision(self.decision_event(a))['statusCode'],200)
        return t,{'incident_id':t['incident_id'],'approval_id':a['approval_id']}

    def test_disabled_rejects_before_clients_or_writes(self):
        self.cfg['enabled']='false'
        self.assertEqual(self.flow.triage(self.event('lambda_threat'))['status'],'DISABLED')
        self.assertFalse(self.store.rows);self.secrets.get_secret_value.assert_not_called()
    def test_extra_inputs_and_foreign_suite_rejected(self):
        for event in [dict(self.event('posture'),finding={'secret':'no'}),{'suite_id':'foreign','case_id':'posture'},self.event('arbitrary')]:
            with self.assertRaises(ValueError):self.flow.triage(event)
        self.assertFalse(self.store.rows)
    def test_model_case_cannot_be_repeated(self):
        result={'status':'valid_response','estimated_usd':.001,'policy_simulation':{'action_mode':'NOTIFY','playbook':'ESCALATE_ONLY','targets':[]}}
        with patch.object(cases,'evaluate',return_value=result) as call:
            self.assertEqual(self.flow.triage(self.event('posture'))['route'],'NOTIFY')
            self.assertEqual(self.flow.triage(self.event('posture'))['status'],'DUPLICATE')
            self.assertEqual(call.call_count,1)
        self.assertEqual(self.store.get('BUDGET')['remaining'],Decimal('.047631325'))
    def test_failure_blocks_next_model_request_and_is_not_success(self):
        with patch.object(cases,'evaluate',return_value={'status':'http_error','estimated_usd':None}) as call:
            t=self.flow.triage(self.event('lambda_threat'))
            self.assertEqual(t['route'],'NOTIFY')
            self.assertFalse(self.flow.incident(t['incident_id'])['model_valid'])
            self.assertEqual(self.flow.triage(self.event('posture'))['status'],'BUDGET_BLOCKED')
            self.assertEqual(call.call_count,1)
    def test_lost_response_keeps_budget_inflight_without_retry(self):
        with patch.object(cases,'evaluate',side_effect=RuntimeError('not exposed')) as call:
            t=self.flow.triage(self.event('lambda_threat'))
            self.assertEqual(self.flow.incident(t['incident_id'])['model_record']['status'],'credential_or_execution_error')
            self.assertEqual(self.store.get('BUDGET')['status'],'BLOCKED')
            self.assertEqual(call.call_count,1)
    def test_scripted_controls_never_call_model(self):
        with patch.object(cases,'evaluate') as call:
            for c in cases.CONTROL_CASES:
                t=self.flow.triage(self.event(c));self.assertEqual(t['evidence_kind'],'scripted_control')
            call.assert_not_called()
        self.assertNotIn('BUDGET',self.store.rows)
    def test_confirmation_get_does_not_consume_or_callback(self):
        t,a=self.approval()
        response=self.flow.decision(self.decision_event(a,method='GET'))
        self.assertEqual(response['statusCode'],200);self.assertIn('method="post"',response['body'])
        self.assertEqual(self.store.get('APPROVAL#'+a['approval_id'])['status'],'PENDING')
        self.sfn.send_task_success.assert_not_called();self.assertEqual(self.target.mutations,[])
    def test_replay_invalid_signature_and_expiry(self):
        t,a=self.approval();bad=self.decision_event(a);bad['body']=bad['body'].replace('sig=','sig=bad')
        self.assertEqual(self.flow.decision(bad)['statusCode'],400)
        good=self.decision_event(a);self.assertEqual(self.flow.decision(good)['statusCode'],200)
        self.assertEqual(self.flow.decision(good)['statusCode'],410);self.sfn.send_task_success.assert_called_once()
        t,b=self.approval('control_deny');self.time+=901
        self.assertEqual(self.flow.decision(self.decision_event(b))['statusCode'],410)
    def test_atomic_expiry_rechecked_at_post(self):
        t,a=self.approval();original=self.store.consume_approval
        self.store.consume_approval=lambda key,action,now:original(key,action,now+901)
        self.assertEqual(self.flow.decision(self.decision_event(a))['statusCode'],410)
        self.sfn.send_task_success.assert_not_called()
    def test_callback_failure_recorded_not_retried(self):
        t,a=self.approval();self.sfn.send_task_success.side_effect=RuntimeError('private')
        self.assertEqual(self.flow.decision(self.decision_event(a))['statusCode'],503)
        self.assertEqual(self.flow.decision(self.decision_event(a))['statusCode'],410)
        self.assertEqual(self.store.get('APPROVAL#'+a['approval_id'])['callback'],'FAILED_OR_UNCERTAIN')
        self.sfn.send_task_success.assert_called_once()
    def test_denial_cannot_act(self):
        t,a=self.approval('control_deny');self.flow.decision(self.decision_event(a,action='deny'))
        self.assertEqual(self.flow.contain({'incident_id':t['incident_id'],'approval_id':a['approval_id']})['status'],'REFUSED')
        self.assertEqual(self.target.mutations,[])
    def test_existing_playbook_then_separate_rollback_reads_and_restores(self):
        t,event=self.approved_action()
        self.assertEqual(self.flow.contain(event)['status'],'CONTAINED');self.assertEqual(self.target.concurrency,0)
        self.assertEqual(self.flow.contain(event)['status'],'DUPLICATE_OR_UNCERTAIN')
        self.assertEqual(self.flow.rollback({'incident_id':t['incident_id']})['status'],'ROLLED_BACK')
        self.assertEqual(self.target.mutations,[0,1]);self.assertEqual(self.target.concurrency,1)
        self.assertEqual(self.flow.rollback({'incident_id':t['incident_id']})['status'],'REFUSED_OR_UNCERTAIN')
    def test_foreign_target_and_protected_tag_refused(self):
        t,event=self.approved_action();row=self.store.rows['INCIDENT#'+t['incident_id']]
        original=copy.deepcopy(row['decision']['targets'])
        row['decision']['targets'][0]['id']='arn:aws:lambda:us-east-2:123456789012:function:old-pilot'
        self.assertEqual(self.flow.contain(event)['status'],'REFUSED')
        row['decision']['targets']=original;self.target.tags['rural-shield:protected']='true'
        self.assertEqual(self.flow.contain(event)['status'],'REFUSED');self.assertEqual(self.target.mutations,[])
    def test_rollback_refuses_changed_state(self):
        t,event=self.approved_action();self.flow.contain(event);self.target.concurrency=2
        self.assertEqual(self.flow.rollback({'incident_id':t['incident_id']})['status'],'REFUSED')
        self.assertEqual(self.target.mutations,[0])
    def test_finish_acceptance_is_not_email_delivery_and_is_not_republished(self):
        t=self.flow.triage(self.event('control_notify'))
        result=self.flow.finish({'triage':t,'outcome':{'status':'NOTIFIED'}})
        self.assertEqual(result['status'],'NOTIFIED');self.assertIn('not confirmation of email delivery',self.sns.publish.call_args.kwargs['Message'])
        self.assertEqual(self.flow.finish({'triage':t,'outcome':{'status':'NOTIFIED'}})['status'],'DUPLICATE_OR_UNCERTAIN')
        self.sns.publish.assert_called_once()
    def test_scripted_timeout_is_short_and_callback_token_not_returned(self):
        t,a=self.approval('control_timeout');self.assertEqual(a['expires'],self.time+10)
        self.assertNotIn('task_token',a);self.assertNotIn('private-test-callback',json.dumps(a))


class BoundaryTests(unittest.TestCase):
    def test_cloud_fixtures_and_original_local_cases_are_distinct(self):
        normalized=cases.policy.normalize_finding(cases.finding('lambda_threat',TARGET))
        self.assertEqual(cases.policy.rule_based_recommendation(normalized),'QUARANTINE_LAMBDA_FUNCTION')
        self.assertEqual(normalized.targets[0].id,TARGET)
        self.assertEqual(cases.experiment.CASE_IDS,('credential_threat','posture','injection','weekly_narration'))
    def test_store_uses_conditional_case_claim_and_numeric_budget(self):
        table=Mock();s=runtime.Store(table,SUITE);s.reserve(Decimal('.04'))
        put=table.put_item.call_args.kwargs
        self.assertEqual(put['ConditionExpression'],'attribute_not_exists(pk)')
        self.assertIsInstance(put['Item']['remaining'],Decimal)
        self.assertIn('remaining >= :reserve',table.update_item.call_args.kwargs['ConditionExpression'])
    def test_store_consumes_approval_with_atomic_expiry(self):
        table=Mock();s=runtime.Store(table,SUITE);s.consume_approval('APPROVAL#test','approve',100)
        self.assertEqual(table.update_item.call_args.kwargs['ConditionExpression'],'#s = :pending AND expires > :now')
    def test_unsafe_output_refused_by_existing_adapter(self):
        with self.assertRaises(cases.adapter.ExperimentError):
            cases.adapter.parse_output({'status':'completed','output':[{'type':'message','content':[{'type':'output_text','text':'SHELL_EXEC'}]}]},cases.adapter.tool_schema(cases.prompts.RECORD_TRIAGE_TOOL['toolSpec']))


if __name__=='__main__':unittest.main()
