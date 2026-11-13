#!/usr/bin/env python3
"""Bounded live non-AI smoke checks; creates one synthetic record, no clinical data.
Uses the existing AWS CLI profile. Direct Lambda tests do not validate Cognito login.
"""
import argparse, json, os, ssl, subprocess, urllib.request, urllib.error, shutil, hashlib
from pathlib import Path
from datetime import datetime, timezone
p=argparse.ArgumentParser(); p.add_argument('--profile',default='ruralshield-research'); p.add_argument('--outputs',default='cdk.out/nonai-outputs.json'); a=p.parse_args()
out=Path('cdk.out/nonai-tests'); out.mkdir(parents=True,exist_ok=True)
bundled=Path(os.environ.get('LOCALAPPDATA',''))/'Programs/Amazon/AWSCLIV2/aws.exe'
cli=os.environ.get('AWS_CLI_PATH') or (str(bundled) if bundled.exists() else shutil.which('aws'))
if not cli: raise RuntimeError('AWS CLI not found; set AWS_CLI_PATH.')
def aws(service,operation,*args):
 r=subprocess.run([cli,service,operation,'--profile',a.profile,'--region','us-east-2','--output','json','--no-cli-pager',*args],capture_output=True,text=True,timeout=60)
 if r.returncode: raise RuntimeError(r.stderr.strip())
 return json.loads(r.stdout) if r.stdout.strip() else {}
outputs=json.loads(Path(a.outputs).read_text()); workload=next(k for k in outputs if k.endswith('-Workload'))
resources=aws('cloudformation','list-stack-resources','--stack-name',workload)['StackResourceSummaries']
fn=next(x['PhysicalResourceId'] for x in resources if x['ResourceType']=='AWS::Lambda::Function' and x['LogicalResourceId'].startswith('AppFn'))
endpoint=next(v for k,v in outputs[workload].items() if 'EndpointUrl' in k)
checks=[]
def check(name,passed,detail): checks.append({'name':name,'passed':passed,'detail':detail})
for stack in outputs:
 status=aws('cloudformation','describe-stacks','--stack-name',stack,'--region','us-west-2' if stack.endswith('-DR') else 'us-east-2')['Stacks'][0]['StackStatus']
 check(stack,status in ['CREATE_COMPLETE','UPDATE_COMPLETE'],status)
ca=Path.home()/'.aws/ruralshield-ca-bundle.pem'
context=ssl.create_default_context(cafile=str(ca)) if ca.exists() else ssl.create_default_context()
try:
 with urllib.request.urlopen(endpoint+'health',context=context,timeout=30) as response: status=response.status
except urllib.error.HTTPError as e: status=e.code
check('unauthenticated API rejected',status==401,{'httpStatus':status,'path':'health'})
def invoke(name,path,method,body=None):
 payload={'path':path,'httpMethod':method,'requestContext':{'authorizer':{'claims':{'email':'synthetic-research@example.invalid'}}},'body':json.dumps(body) if body else None}
 f=out/(name+'-request.json'); f.write_text(json.dumps(payload)); response_file=out/(name+'-response.json')
 meta=aws('lambda','invoke','--function-name',fn,'--payload','fileb://'+str(f.resolve()),'--cli-binary-format','raw-in-base64-out',str(response_file.resolve()))
 response=json.loads(response_file.read_text()); check(name,'FunctionError' not in meta and response.get('statusCode')==({'create':201,'read':200,'health':200}[name]),{'statusCode':response.get('statusCode'),'functionError':meta.get('FunctionError'),'scope':'direct Lambda invocation'})
 return response
invoke('health','/health','GET')
patient={'resourceType':'Patient','id':'ruralshield-synthetic-smoke','active':False,'name':[{'family':'SYNTHETIC RESEARCH TEST'}]}
invoke('create','/Patient','POST',patient)
r=invoke('read','/Patient/ruralshield-synthetic-smoke','GET'); check('synthetic round trip',json.loads(r.get('body','{}'))==patient,{'scope':'direct Lambda plus DynamoDB, synthetic claims; excludes actual Cognito authentication'})
fnconfig=aws('lambda','get-function-configuration','--function-name',fn)
check('Lambda ready',fnconfig.get('State')=='Active' and fnconfig.get('LastUpdateStatus')=='Successful',{'state':fnconfig.get('State'),'lastUpdateStatus':fnconfig.get('LastUpdateStatus')})
pool=next(x['PhysicalResourceId'] for x in resources if x['ResourceType']=='AWS::Cognito::UserPool')
poolconfig=aws('cognito-idp','describe-user-pool','--user-pool-id',pool)['UserPool']
check('Cognito requires MFA',poolconfig.get('MfaConfiguration')=='ON',{'mfa':poolconfig.get('MfaConfiguration'),'scope':'deployed configuration; login not tested'})
table=next(x['PhysicalResourceId'] for x in resources if x['ResourceType']=='AWS::DynamoDB::GlobalTable')
tableconfig=aws('dynamodb','describe-table','--table-name',table)['Table']
check('DynamoDB KMS encryption',tableconfig.get('SSEDescription',{}).get('Status')=='ENABLED',{'sseStatus':tableconfig.get('SSEDescription',{}).get('Status')})
pitr=aws('dynamodb','describe-continuous-backups','--table-name',table)['ContinuousBackupsDescription']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus']
check('DynamoDB point in time recovery',pitr=='ENABLED',pitr)
bucket=next(x['PhysicalResourceId'] for x in resources if x['ResourceType']=='AWS::S3::Bucket' and x['LogicalResourceId'].startswith('DataPhiBucket'))
bpa=aws('s3api','get-public-access-block','--bucket',bucket)['PublicAccessBlockConfiguration']
check('PHI bucket blocks public access',all(bpa.get(k) is True for k in ['BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets']),bpa)
lock=aws('s3api','get-object-lock-configuration','--bucket',bucket)['ObjectLockConfiguration']
check('PHI bucket governance retention',lock.get('ObjectLockEnabled')=='Enabled' and lock.get('Rule',{}).get('DefaultRetention',{})=={'Mode':'GOVERNANCE','Days':35},lock)
foundation=next(k for k in outputs if k.endswith('-Foundation'))
foundation_resources=aws('cloudformation','list-stack-resources','--stack-name',foundation)['StackResourceSummaries']
recorder=next(x['PhysicalResourceId'] for x in foundation_resources if x['ResourceType']=='AWS::Config::ConfigurationRecorder')
recording=aws('configservice','describe-configuration-recorder-status','--configuration-recorder-names',recorder)['ConfigurationRecordersStatus'][0]
check('AWS Config recording started',recording.get('recording') is True,{'recording':recording.get('recording'),'lastStatus':recording.get('lastStatus')})
trail=next(x['PhysicalResourceId'] for x in foundation_resources if x['ResourceType']=='AWS::CloudTrail::Trail')
trail_status=aws('cloudtrail','get-trail-status','--name',trail)
check('CloudTrail logging enabled',trail_status.get('IsLogging') is True,{'isLogging':trail_status.get('IsLogging'),'latestDeliveryError':trail_status.get('LatestDeliveryError')})
archive=next(x['PhysicalResourceId'] for x in foundation_resources if x['ResourceType']=='AWS::S3::Bucket' and x['LogicalResourceId'].startswith('BaselineLogArchive'))
archived=aws('s3api','list-objects-v2','--bucket',archive,'--prefix','service-delivery/','--max-keys','1').get('Contents',[])
if archived:
 head=aws('s3api','head-object','--bucket',archive,'--key',archived[0]['Key'])
 check('delivered log archived with KMS and compliance lock',head.get('ServerSideEncryption')=='aws:kms' and head.get('ObjectLockMode')=='COMPLIANCE',{'encryption':head.get('ServerSideEncryption'),'objectLockMode':head.get('ObjectLockMode'),'retainUntil':head.get('ObjectLockRetainUntilDate'),'scope':'one delivered log object; not comprehensive archival reliability'})
else:
 check('delivered log archived with KMS and compliance lock',False,{'reason':'No archived delivery object observed yet; delivery may still be converging.'})
result={'checkedAt':datetime.now(timezone.utc).isoformat(),'configSha256':hashlib.sha256(Path('cdk.out/aws-setup/nonai-research.yaml').read_bytes()).hexdigest(),'lambdaCodeSha256':fnconfig.get('CodeSha256'),'condition':'non-AI; Sentinel absent','checks':checks,'passed':all(x['passed'] for x in checks),'limitations':'No successful Bedrock, Guardrail, Sentinel, actual Cognito login, load, backup restore or five-day observation tested.'}
(out/'results.json').write_text(json.dumps(result,indent=2)); print(json.dumps(result,indent=2)); raise SystemExit(0 if result['passed'] else 1)
