"""Offline contract and isolation checks. Mock responses are not inference results."""
import copy
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
import urllib.error
import importlib.util
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src' / 'external_ai'), str(ROOT / 'src' / 'lambda' / 'triage'), str(ROOT / 'scripts')]
import adapter
import experiment
import handler
import prompts
import policy

runner_spec = importlib.util.spec_from_file_location('external_runner', ROOT / 'scripts' / 'external-ai-experiment.py')
runner = importlib.util.module_from_spec(runner_spec)
runner_spec.loader.exec_module(runner)


def response(case='credential_threat'):
    _, tool, finding, _ = experiment.prepare(case)
    assessment = prompts.fallback_assessment(finding, 'ESCALATE_ONLY')
    assessment['confidence'] = 0.9
    return {'status': 'completed', 'model': adapter.MODEL, 'id': 'resp_mock',
            'usage': {'input_tokens': 1000, 'output_tokens': 100, 'input_tokens_details': {'cached_tokens': 200, 'cache_write_tokens': 0}},
            'output': [{'type': 'function_call', 'name': 'record_triage', 'status': 'completed',
                        'arguments': json.dumps(assessment)}]}


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.tool = experiment.prepare('credential_threat')[1]

    def test_strict_request_and_no_storage(self):
        body = experiment.prepare('credential_threat')[0]
        self.assertFalse(body['store'])
        self.assertFalse(body['parallel_tool_calls'])
        self.assertTrue(body['tools'][0]['strict'])
        self.assertFalse(self.tool['parameters']['additionalProperties'])
        self.assertEqual(set(self.tool['parameters']['required']), set(self.tool['parameters']['properties']))

    def test_no_mutation_of_existing_prompt_schema(self):
        self.assertNotIn('additionalProperties', prompts.RECORD_TRIAGE_TOOL['toolSpec']['inputSchema']['json'])

    def test_valid_function_call(self):
        self.assertEqual(adapter.parse_output(response(), self.tool)['confidence'], .9)

    def test_duplicate_and_nonfinite_json_rejected(self):
        for text in ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', 'not JSON']:
            with self.subTest(text=text), self.assertRaises(adapter.ExperimentError):
                adapter.strict_json(text)

    def test_confidence_and_enum_validation(self):
        value = adapter.parse_output(response(), self.tool)
        for key, invalid in [('confidence', True), ('confidence', 1.01), ('confidence', -.1),
                             ('confidence', float('nan')), ('recommended_playbook', 'SHELL_EXEC'),
                             ('patient_safety_impact', ['high'])]:
            with self.subTest(key=key, value=invalid), self.assertRaises(adapter.ExperimentError):
                adapter.validate_assessment(dict(value, **{key: invalid}), self.tool['parameters'])

    def test_missing_extra_and_array_constraints(self):
        value = adapter.parse_output(response(), self.tool)
        invalids = [dict(value, command='execute'), {k: v for k, v in value.items() if k != 'confidence'},
                    dict(value, next_steps_for_it_staff=[]), dict(value, false_positive_indicators=['a'] * 5),
                    dict(value, next_steps_for_it_staff=[5]), dict(value, what_happened='x' * 6001)]
        for invalid in invalids:
            with self.subTest(invalid=list(invalid)), self.assertRaises(adapter.ExperimentError):
                adapter.validate_assessment(invalid, self.tool['parameters'])

    def test_unexpected_multiple_tools_and_plain_text(self):
        for output in [[], response()['output'] * 2, [{'type': 'computer_call'}],
                       [{'type': 'message', 'content': [{'type': 'output_text', 'text': 'no tool'}]}]]:
            with self.subTest(output=output), self.assertRaises(adapter.ExperimentError):
                adapter.parse_output(dict(response(), output=output), self.tool)

    def test_refusal_and_incomplete(self):
        for value in [dict(response(), status='incomplete'), dict(response(), output=[{
                'type': 'message', 'content': [{'type': 'refusal', 'refusal': 'no'}]}])]:
            with self.assertRaises(adapter.ExperimentError):
                adapter.parse_output(value, self.tool)

    def test_wrong_or_incomplete_function(self):
        for key, value in [('name', 'other'), ('status', 'in_progress')]:
            data = response()
            data['output'][0][key] = value
            with self.assertRaises(adapter.ExperimentError):
                adapter.parse_output(data, self.tool)

    def test_narration_requires_text(self):
        data = dict(response(), output=[{'type': 'message', 'content': [{'type': 'output_text', 'text': 'Synthetic summary'}]}])
        self.assertEqual(adapter.parse_output(data, None), 'Synthetic summary')
        data['output'][0]['content'][0]['text'] = ''
        with self.assertRaises(adapter.ExperimentError):
            adapter.parse_output(data, None)

    def test_malformed_output_shape_rejected(self):
        for output in [[None], [{'type': 'message', 'content': None}],
                       [{'type': 'message', 'content': [{'type': 'output_text', 'text': 7}]}]]:
            with self.subTest(output=output), self.assertRaises(adapter.ExperimentError):
                adapter.parse_output(dict(response(), output=output), None)

    def test_cached_usage_cost(self):
        self.assertAlmostEqual(adapter.usage_cost(response())['estimated_usd'], .000132)

    def test_missing_or_invalid_usage_is_unknown_not_free(self):
        for usage in [None, {}, {'input_tokens': True, 'output_tokens': 3},
                      {'input_tokens': 1, 'output_tokens': 2, 'input_tokens_details': {'cached_tokens': 3}}]:
            self.assertIsNone(adapter.usage_cost({'usage': usage})['estimated_usd'])

    def test_unknown_cached_count_is_labeled(self):
        self.assertEqual(adapter.usage_cost({'usage': {'input_tokens': 1, 'output_tokens': 1}})['cost_status'],
                         'unknown_cache_usage')

    def test_observed_cache_writes_use_default_30m_rate(self):
        usage = {'input_tokens': 1504, 'output_tokens': 483,
                 'input_tokens_details': {'cached_tokens': 0, 'cache_write_tokens': 1371}}
        result = adapter.usage_cost({'usage': usage})
        self.assertAlmostEqual(result['estimated_usd'], .000426175, places=12)
        self.assertEqual(result['cost_status'], 'token_estimate_default_30m')

    def test_mixed_write_lifetimes_are_disjoint_not_double_counted(self):
        usage = {'input_tokens': 12000, 'output_tokens': 0,
                 'input_tokens_details': {'cached_tokens': 4000, 'cache_write_tokens': 7000,
                    'cache_write_tokens_details': {'ttl_30m_tokens': 3000, 'ttl_12h_tokens': 4000}}}
        self.assertAlmostEqual(adapter.usage_cost({'usage': usage})['estimated_usd'], .001515, places=12)

    def test_missing_or_invalid_write_counts_do_not_underestimate(self):
        for detail in [{'cached_tokens': 0}, {'cached_tokens': 0, 'cache_write_tokens': True},
                       {'cached_tokens': 2, 'cache_write_tokens': 2},
                       {'cached_tokens': 0, 'cache_write_tokens': 1, 'cache_write_tokens_details': {'ttl_30m_tokens': 0, 'ttl_12h_tokens': 0}}]:
            self.assertIsNone(adapter.usage_cost({'usage': {'input_tokens': 3, 'output_tokens': 1,
                                                          'input_tokens_details': detail}})['estimated_usd'])

    def test_unpriced_long_context_is_unknown(self):
        data = response()
        data['usage']['input_tokens'] = 272001
        self.assertEqual(adapter.usage_cost(data)['cost_status'], 'unpriced_long_context')


class TransportAndIsolationTests(unittest.TestCase):
    def test_network_failure_no_retry_no_secret_in_error(self):
        transport = Mock(side_effect=urllib.error.URLError('secret-placeholder'))
        with self.assertRaises(adapter.ExperimentError) as caught:
            adapter.call_api({}, 'sk-mock-secret', opener=transport)
        self.assertEqual(transport.call_count, 1)
        self.assertNotIn('secret', str(caught.exception))

    def test_http_failure_records_only_status(self):
        transport = Mock(side_effect=urllib.error.HTTPError(adapter.ENDPOINT, 429, 'private-body', {}, None))
        with self.assertRaises(adapter.ExperimentError) as caught:
            adapter.call_api({}, 'sk-mock-secret', opener=transport)
        self.assertEqual(caught.exception.metadata['http_status'], 429)
        self.assertNotIn('private', str(caught.exception.metadata))
        self.assertEqual(transport.call_count, 1)

    def test_http_error_keeps_only_allowlisted_code_and_request_id(self):
        for code, expected in [('insufficient_quota', 'insufficient_quota'),
                               ('credit_balance_exhausted', 'credit_balance_exhausted'),
                               ('sk-private-value', 'unclassified')]:
            body = io.BytesIO(json.dumps({'error': {'code': code, 'message': 'sk-private-body'}}).encode())
            error = urllib.error.HTTPError(adapter.ENDPOINT, 429, 'private-message', {'x-request-id': 'req_mock'}, body)
            transport = Mock(side_effect=error)
            with self.assertRaises(adapter.ExperimentError) as caught:
                adapter.call_api({}, 'sk-mock-secret', opener=transport)
            self.assertEqual(caught.exception.metadata['provider_error_code'], expected)
            self.assertEqual(caught.exception.metadata['request_id'], 'req_mock')
            self.assertNotIn('private', str(caught.exception.metadata))
            self.assertEqual(transport.call_count, 1)

    def test_transport_bounds_and_verified_tls(self):
        payload = io.BytesIO(json.dumps(response()).encode())
        payload.headers = {'x-request-id': 'req_mock'}
        transport = Mock(return_value=payload)
        result = adapter.call_api({}, 'sk-mock-secret', opener=transport)
        self.assertEqual(result['request_id'], 'req_mock')
        self.assertEqual(transport.call_args.kwargs['timeout'], 45)
        self.assertEqual(transport.call_args.args[0].full_url, adapter.ENDPOINT)

    def test_oversized_response_rejected(self):
        payload = io.BytesIO(b'x' * (adapter.MAX_RESPONSE_BYTES + 1))
        payload.headers = {}
        with self.assertRaises(adapter.ExperimentError):
            adapter.call_api({}, 'sk-mock-secret', opener=Mock(return_value=payload))

    def test_case_ids_only(self):
        with self.assertRaises(adapter.ExperimentError):
            experiment.prepare('real_finding')
        self.assertEqual(handler.lambda_handler({'case_id': 'injection', 'raw': 'anything'}, None)['status'], 'rejected_input')

    def test_lambda_disabled_before_credentials(self):
        with patch.dict('os.environ', {'EXPERIMENT_ENABLED': 'false'}):
            self.assertEqual(handler.lambda_handler({'case_id': 'posture'}, None)['status'], 'disabled')

    def test_local_policy_never_auto(self):
        for case in experiment.CASE_IDS[:3]:
            caller = Mock(return_value={'response': response(case), 'elapsed_ms': 1, 'request_id': 'req_mock'})
            result = experiment.evaluate(case, 'sk-mock-secret', caller=caller)
            self.assertEqual(result['status'], 'valid_response')
            self.assertNotEqual(result['policy_simulation']['action_mode'], 'AUTO')
            self.assertEqual(result['actions_executed'], 0)
            self.assertNotIn('sk-mock-secret', json.dumps(result))

    def test_failed_schema_preserves_usage_and_raw_output(self):
        data = response()
        data['output'][0]['arguments'] = '{}'
        result = experiment.evaluate('injection', 'sk-mock', caller=lambda *a: {'response': data})
        self.assertEqual(result['status'], 'invalid_assessment_fields')
        self.assertIsNotNone(result['estimated_usd'])
        self.assertEqual(result['response'], data)

    def test_model_mismatch_unpriced(self):
        data = dict(response(), model='another-model')
        result = experiment.evaluate('posture', 'sk-mock', caller=lambda *a: {'response': data})
        self.assertEqual(result['status'], 'model_mismatch')
        self.assertIsNone(result['estimated_usd'])


class RunnerSafetyTests(unittest.TestCase):
    def test_default_plan_never_calls_api(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(runner, 'ROOT', Path(folder)), \
                patch.object(runner, 'source_hashes', return_value={}), \
                patch.object(sys, 'argv', ['experiment']), patch.object(experiment, 'evaluate') as call, \
                patch('sys.stdout', new_callable=io.StringIO):
            runner.main()
            call.assert_not_called()
            index = json.loads(next(Path(folder).rglob('index.json')).read_text())
            self.assertEqual(index['attempted_requests'], 0)
            self.assertFalse(index['all_costs_known'])

    def test_live_mode_requires_explicit_processing_acknowledgment(self):
        with patch.object(sys, 'argv', ['experiment', '--live']), \
                patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit):
            runner.main()

    def test_live_failure_stops_and_preserves_remaining_plan(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(runner, 'ROOT', Path(folder)), \
                patch.object(runner, 'source_hashes', return_value={}), patch.object(runner, 'load_key', return_value='sk-mock'), \
                patch.object(sys, 'argv', ['experiment', '--live', '--acknowledge-external-processing']), \
                patch.object(experiment, 'evaluate', return_value={
                    'case_id': 'credential_threat', 'status': 'http_error', 'estimated_usd': None}) as call, \
                patch('sys.stdout', new_callable=io.StringIO):
            runner.main()
            self.assertEqual(call.call_count, 1)
            plan = json.loads(next(Path(folder).rglob('plan.json')).read_text())
            self.assertEqual(len(plan['case_ids']), 4)
            self.assertEqual(plan['stopped_reason'], 'failed_or_unknown_cost_request')
            index = json.loads(next(Path(folder).rglob('index.json')).read_text())
            self.assertEqual(index['unknown_cost_requests'], 1)
            self.assertFalse(index['all_costs_known'])


if __name__ == '__main__':
    unittest.main()
