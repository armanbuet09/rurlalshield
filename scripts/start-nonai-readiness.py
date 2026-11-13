"""Run real SRP/TOTP/API checks, then start bounded synthetic replication/backup probes.
Credentials and TOTP stay in memory. Evidence and resumable AWS job IDs contain no tokens.
"""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'cdk.out/python-tools'))
import boto3, json, secrets, string, subprocess, os, hashlib
from datetime import datetime, timezone

region='us-east-2'; session=boto3.Session(profile_name='ruralshield-research',region_name=region)
run_id='nonai-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
out=ROOT/'cdk.out'/run_id; out.mkdir(parents=True)
state={'runId':run_id,'phase':'readiness','createdAt':datetime.now(timezone.utc).isoformat(),'observationStarted':False,'checks':[]}
def save(): (out/'state.json').write_text(json.dumps(state,indent=2,default=str))
save(); print('Evidence:',str(out),flush=True)
outputs=json.loads((ROOT/'cdk.out/nonai-outputs.json').read_text()); workload=next(v for k,v in outputs.items() if k.endswith('-Workload'))
def value(fragment): return next(v for k,v in workload.items() if fragment in k)
pool=value('UserPoolId'); client=value('UserPoolClientId'); endpoint=value('EndpointUrl')
resources=session.client('cloudformation').list_stack_resources(StackName=next(k for k in outputs if k.endswith('-Workload')))['StackResourceSummaries']
def physical(prefix): return next(r['PhysicalResourceId'] for r in resources if r['LogicalResourceId'].startswith(prefix))
table=physical('DataTable'); source_bucket=physical('DataPhiBucket953'); vault=physical('ResilienceVault')
backup_role='arn:aws:iam::123456789012:role/'+physical('ResilienceBackupSelectionRoleF')
restore_role='arn:aws:iam::123456789012:role/'+physical('ResilienceRestoreTestRole7')
patient={'resourceType':'Patient','id':run_id,'active':False,'name':[{'family':'SYNTHETIC READINESS TEST'}]}
username=run_id+'@example.invalid'; password='RS!a9'+''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(30))
cognito=session.client('cognito-idp'); created=False
try:
    cognito.admin_create_user(UserPoolId=pool,Username=username,MessageAction='SUPPRESS',UserAttributes=[{'Name':'email','Value':username},{'Name':'email_verified','Value':'true'}]); created=True
    cognito.admin_set_user_password(UserPoolId=pool,Username=username,Password=password,Permanent=True)
    env={**os.environ,'NODE_EXTRA_CA_CERTS':str(Path.home()/'.aws/ruralshield-ca-bundle.pem')}
    call=subprocess.run(['node',str(ROOT/'scripts/test-cognito-srp.cjs')],input=json.dumps({'poolId':pool,'clientId':client,'endpoint':endpoint,'username':username,'password':password,'patient':patient}),text=True,capture_output=True,env=env,timeout=180)
    result=json.loads(call.stdout); (out/'authenticated-api.json').write_text(json.dumps(result,indent=2));state['checks'].append({'name':'real SRP/TOTP/authenticated API','passed':result['passed']});save()
    if not result['passed']: raise RuntimeError('Authentication/API checks failed; see sanitized result file.')
finally:
    if created: cognito.admin_delete_user(UserPoolId=pool,Username=username); state['syntheticUserDeleted']=True;save()
state.update({'patient':patient,'sourceTable':table,'sourceBucket':source_bucket,'vault':vault,'backupRoleArn':backup_role,'restoreRoleArn':restore_role})
s3=session.client('s3'); key='research-readiness/'+run_id+'.txt'; body=('Synthetic RuralShield replication readiness '+run_id+'\n').encode()
put=s3.put_object(Bucket=source_bucket,Key=key,Body=body,ContentType='text/plain')
state['replication']={'key':key,'sourceVersionId':put['VersionId'],'sha256':hashlib.sha256(body).hexdigest(),'destinationBucket':'ruralshield-research-rshield-phi-dr-123456789012-us-west-2','status':'pending'};save()
job=session.client('backup').start_backup_job(BackupVaultName=vault,ResourceArn='arn:aws:dynamodb:us-east-2:123456789012:table/'+table,IamRoleArn=backup_role,IdempotencyToken=run_id,StartWindowMinutes=60,CompleteWindowMinutes=120,Lifecycle={'DeleteAfterDays':35})
state['backup']={'jobId':job['BackupJobId'],'recoveryPointArn':job['RecoveryPointArn'],'status':'pending'};save()
print(json.dumps({'runId':run_id,'authenticatedApiPassed':True,'replication':'started','backupJobId':job['BackupJobId'],'evidence':str(out)},indent=2))
