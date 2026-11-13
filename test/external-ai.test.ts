import * as cdk from 'aws-cdk-lib';
import {Template} from 'aws-cdk-lib/assertions';
import {ExternalAiStack} from '../scripts/external-ai-stack';
import * as path from 'path';

test('manual experiment is disabled, isolated and lacks containment or collection permissions', () => {
  const app = new cdk.App();
  const stack = new ExternalAiStack(app, 'IsolatedAi', {
    env: {account: '123456789012', region: 'us-east-2'}, assetPath: path.join(__dirname, '../src/external_ai'),
    secretArn: 'arn:aws:secretsmanager:us-east-2:123456789012:secret:research/openai-ABCDEF',
  });
  const template = Template.fromStack(stack);
  template.resourceCountIs('AWS::Lambda::Function', 1);
  template.hasResourceProperties('AWS::Lambda::Function', {
    Environment: {Variables: {EXPERIMENT_ENABLED: 'false', API_SECRET_ARN: 'arn:aws:secretsmanager:us-east-2:123456789012:secret:research/openai-ABCDEF'}},
    ReservedConcurrentExecutions: 1,
  });
  for (const type of ['AWS::Events::Rule', 'AWS::Scheduler::Schedule', 'AWS::Lambda::Permission',
                     'AWS::Lambda::Url', 'AWS::ApiGateway::RestApi', 'AWS::SNS::Subscription', 'AWS::KMS::Key']) {
    template.resourceCountIs(type, 0);
  }
  const resources = template.toJSON().Resources;
  const policies = Object.values(resources).filter((r: any) => r.Type === 'AWS::IAM::Policy') as any[];
  const actions = policies.flatMap(p => p.Properties.PolicyDocument.Statement.flatMap((s: any) => s.Action));
  expect(actions.sort()).toEqual(['logs:CreateLogStream', 'logs:PutLogEvents', 'secretsmanager:GetSecretValue'].sort());
  expect(Object.keys(resources).some(k => /Sentinel|Workload|Foundation/.test(k))).toBe(false);
});

test('secret ARN wildcards are rejected', () => {
  expect(() => new ExternalAiStack(new cdk.App(), 'Bad', {
    assetPath: path.join(__dirname, '../src/external_ai'), secretArn: 'arn:aws:secretsmanager:us-east-2:123456789012:secret:*',
  })).toThrow('exact Secrets Manager');
});
