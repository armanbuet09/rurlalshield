import * as cdk from 'aws-cdk-lib';
import {Template} from 'aws-cdk-lib/assertions';
import * as path from 'path';
import {AiWorkflowStack, SUITE} from '../scripts/ai-workflow-stack';

function make() {
  return new AiWorkflowStack(new cdk.App(),'SeparateWorkflow',{
    env:{account:'123456789012',region:'us-east-2'},
    assetPath:path.join(__dirname,'../src/external_ai_workflow'),
    apiSecretArn:'arn:aws:secretsmanager:us-east-2:123456789012:secret:research/openai-ABCDEF',
    alertEmail:'operator@example.invalid',
  });
}

test('synthetic workflow is separate, disabled and cannot collect or contain unrelated resources',()=>{
  const t=Template.fromStack(make());const resources=t.toJSON().Resources;
  t.resourceCountIs('AWS::Lambda::Function',7);
  t.resourceCountIs('AWS::DynamoDB::Table',1);t.resourceCountIs('AWS::Events::EventBus',1);
  t.resourceCountIs('AWS::Events::Rule',1);t.resourceCountIs('AWS::StepFunctions::StateMachine',1);
  for(const type of ['AWS::KMS::Key','AWS::EC2::VPC','AWS::Backup::BackupPlan',
    'AWS::SecurityHub::Hub','AWS::CloudTrail::Trail','AWS::ApiGateway::Account','AWS::Scheduler::Schedule'])t.resourceCountIs(type,0);
  const rule=Object.values(resources).find((r:any)=>r.Type==='AWS::Events::Rule') as any;
  expect(rule.Properties.State).toBe('DISABLED');
  expect(rule.Properties.EventPattern.source).toEqual(['ruralshield.synthetic']);
  expect(rule.Properties.EventPattern.detail.suite_id).toEqual([SUITE]);
  const functions=Object.values(resources).filter((r:any)=>r.Type==='AWS::Lambda::Function') as any[];
  for(const fn of functions.filter(f=>f.Properties.Handler.startsWith('handlers.'))) {
    expect(fn.Properties.Environment.Variables.WORKFLOW_ENABLED).toBe('false');
    expect(fn.Properties.ReservedConcurrentExecutions).toBe(1);
  }
  const statements=(Object.values(resources) as any[]).filter(r=>r.Type==='AWS::IAM::Policy')
    .flatMap(r=>r.Properties.PolicyDocument.Statement);
  const actions=statements.flatMap(s=>Array.isArray(s.Action)?s.Action:[s.Action]);
  expect(actions.some(a=>/^(bedrock|securityhub|guardduty|cloudtrail|backup|iam|s3):/.test(a))).toBe(false);
  const mutations=statements.filter(s=>(Array.isArray(s.Action)?s.Action:[s.Action]).includes('lambda:PutFunctionConcurrency'));
  expect(mutations.length).toBe(2);
  for(const statement of mutations) {
    expect(JSON.stringify(statement.Resource)).toContain('DisposableTarget');
    expect(JSON.stringify(statement.Resource)).not.toContain('*');
  }
  const keyReaders=functions.filter(f=>f.Properties.Environment?.Variables?.API_SECRET_ARN);
  expect(keyReaders.length).toBe(1);expect(keyReaders[0].Properties.Handler).toBe('handlers.triage');
  const machine=Object.values(resources).find((r:any)=>r.Type==='AWS::StepFunctions::StateMachine') as any;
  const definition=JSON.stringify(machine.Properties.DefinitionString);
  expect(definition).toContain('waitForTaskToken');expect(definition).toContain('RestoreDisposableTarget');
  expect(definition).not.toContain('Retry');
  expect(machine.Properties.LoggingConfiguration.IncludeExecutionData).toBe(false);
});

test('activation without a final archive is refused',()=>{
  expect(()=>new AiWorkflowStack(new cdk.App(),'Blocked',{
    env:{account:'123456789012',region:'us-east-2'},assetPath:path.join(__dirname,'../src/external_ai_workflow'),
    apiSecretArn:'arn:aws:secretsmanager:us-east-2:123456789012:secret:research/openai-ABCDEF',
    alertEmail:'operator@example.invalid',enabled:true,
  })).toThrow('verified final archive');
});

test('cross-account or wildcard API secrets are rejected',()=>{
  for(const arn of ['arn:aws:secretsmanager:us-east-2:999999999999:secret:research/openai-ABCDEF',
    'arn:aws:secretsmanager:us-east-2:123456789012:secret:*']) {
    expect(()=>new AiWorkflowStack(new cdk.App(),'Bad',{
      env:{account:'123456789012',region:'us-east-2'},assetPath:path.join(__dirname,'../src/external_ai_workflow'),
      apiSecretArn:arn,alertEmail:'operator@example.invalid',
    })).toThrow('exact same-account');
  }
});
