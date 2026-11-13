"""Prepare encrypted synthetic credentials; arm a frozen 120-hour pilot only after readiness.
The AWS worker enforces the deadline even when this desktop is closed.
"""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'cdk.out/python-tools'))
import boto3,json,secrets,string,subprocess,os,hashlib,zipfile,math
from datetime import datetime,timezone,timedelta
readiness=Path(sys.argv[1]);prepare_only='--prepare-only' in sys.argv
s=boto3.Session(profile_name='ruralshield-research',region_name='us-east-2');p=ROOT/'cdk.out/observation-state.json'
stack=s.client('cloudformation').describe_stacks(StackName='RuralShield-NonAiObservation')['Stacks'][0]
assert stack['StackStatus'] in ['CREATE_COMPLETE','UPDATE_COMPLETE']
outputs={x['OutputKey']:x['OutputValue'] for x in stack['Outputs']};events=s.client('events')
if p.exists(): state=json.loads(p.read_text())
else: state={'outputs':outputs,'phase':'preparing','readinessFile':str(readiness.resolve())}
def save():p.write_text(json.dumps(state,indent=2,default=str))
if state.get('phase')=='active': print(json.dumps({'phase':'already active','startAt':state['manifest']['startAt'],'endAt':state['manifest']['endAt']}));raise SystemExit()
assert events.describe_rule(Name=outputs['RuleName'])['State']=='DISABLED','Do not alter an active observation'
if not state.get('username'):
    workload=next(v for k,v in json.loads((ROOT/'cdk.out/nonai-outputs.json').read_text()).items() if k.endswith('-Workload'))
    val=lambda fragment:next(v for k,v in workload.items() if fragment in k)
    username='rs-observer-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'@example.invalid'
    cfg={'poolId':val('UserPoolId'),'clientId':val('UserPoolClientId'),'username':username,'password':'RS!a9'+''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(30))}
    cognito=s.client('cognito-idp');created=False
    try:
        cognito.admin_create_user(UserPoolId=cfg['poolId'],Username=username,MessageAction='SUPPRESS',UserAttributes=[{'Name':'email','Value':username},{'Name':'email_verified','Value':'true'}]);created=True
        cognito.admin_set_user_password(UserPoolId=cfg['poolId'],Username=username,Password=cfg['password'],Permanent=True)
        env={**os.environ,'NODE_EXTRA_CA_CERTS':str(Path.home()/'.aws/ruralshield-ca-bundle.pem')}
        r=subprocess.run(['node',str(ROOT/'scripts/enroll-observation.cjs')],input=json.dumps(cfg),capture_output=True,text=True,env=env,timeout=120)
        if r.returncode:raise RuntimeError('Synthetic MFA enrollment failed: '+r.stderr)
        cfg['totpSecret']=json.loads(r.stdout)['totpSecret']
        s.client('secretsmanager').put_secret_value(SecretId=outputs['AuthSecretArn'],SecretString=json.dumps(cfg))
        state.update({'phase':'prepared','username':username,'poolId':cfg['poolId'],'endpoint':val('EndpointUrl')});save()
    except Exception:
        if created:cognito.admin_delete_user(UserPoolId=cfg['poolId'],Username=username)
        raise
    finally:cfg.clear()
if prepare_only:print(json.dumps({'phase':state['phase'],'credentials':'stored only in encrypted Secrets Manager','schedule':'disabled'}));raise SystemExit()
ready=json.loads(readiness.read_text());assert ready.get('readyForObservation') is True,'Readiness gates have not passed'
topic='arn:aws:sns:us-east-2:123456789012:ruralshield-research-rural-shield-alerts'
assert any(x['SubscriptionArn']!='PendingConfirmation' and x['Endpoint']=='research-alerts@example.com' for x in s.client('sns').list_subscriptions_by_topic(TopicArn=topic)['Subscriptions'])
freeze=ROOT/'cdk.out/observation-freeze';freeze.mkdir(exist_ok=True)
files=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard'],cwd=ROOT,text=True).splitlines()
hashes={}
with zipfile.ZipFile(freeze/'source.zip','w',zipfile.ZIP_DEFLATED) as z:
    for name in sorted(set(files)):
        f=ROOT/name
        if f.is_file():z.write(f,name);hashes[name]=hashlib.sha256(f.read_bytes()).hexdigest()
    for name in ['cdk.out/aws-setup/nonai-research.yaml','cdk.context.json','cdk.out/auth-tools/package-lock.json']:
        f=ROOT/name;z.write(f,'frozen-inputs/'+f.name);hashes[name]=hashlib.sha256(f.read_bytes()).hexdigest()
    for f in (ROOT/'cdk.out/nonai-replication').glob('*.template.json'):z.write(f,'templates/'+f.name)
import shutil
shutil.copyfile(readiness,freeze/'readiness-state.json')
shutil.copyfile(readiness.parent/'authenticated-api.json',freeze/'authenticated-api.json')
(freeze/'hashes.json').write_text(json.dumps(hashes,indent=2))
start=datetime.fromtimestamp(math.ceil(datetime.now(timezone.utc).timestamp()/60)*60+120,timezone.utc);end=start+timedelta(hours=120)
manifest={'condition':'non-AI operational pilot; no comparative baseline','instrumentationCodeSha256':s.client('lambda').get_function_configuration(FunctionName=outputs['RunnerName'])['CodeSha256'],'clientRegion':'us-east-2','clientRuntime':'Lambda Node.js 22 ARM64, 512 MiB','startAt':start.isoformat(),'endAt':end.isoformat(),'targetRequests':1000000,'endpoint':state['endpoint'],'patient':{'resourceType':'Patient','id':'rs-five-day-synthetic','active':False,'name':[{'family':'SYNTHETIC OBSERVATION TEST'}]},'configSha256':hashes['cdk.out/aws-setup/nonai-research.yaml'],'sourceArchiveSha256':hashlib.sha256((freeze/'source.zip').read_bytes()).hexdigest(),'readinessEvidence':str(readiness),'requestSchedule':'138 or 139 authenticated HTTPS requests per minute, four concurrent clients; hourly create/read included in total','missingSlots':'not silently replayed or made up','stopPolicy':'120-hour absolute guard; disable schedule on authentication failure, missing minute work, or more than 10 percent HTTP failures','limitations':'Single non-AI condition; does not measure Sentinel, clinical outcomes or comparative advantage'}
(freeze/'manifest.json').write_text(json.dumps(manifest,indent=2));s3=s.client('s3')
for f in freeze.iterdir():s3.upload_file(str(f),outputs['EvidenceBucket'],'freeze/'+f.name)
s3.put_object(Bucket=outputs['EvidenceBucket'],Key='control/manifest.json',Body=json.dumps(manifest).encode(),ContentType='application/json')
state.update({'phase':'active','manifest':manifest,'sourceFilesHashed':len(hashes)});save()
events.enable_rule(Name=outputs['RuleName'])
print(json.dumps({'phase':'active','startAt':manifest['startAt'],'endAt':manifest['endAt'],'targetRequests':1000000,'evidenceBucket':outputs['EvidenceBucket']},indent=2))
