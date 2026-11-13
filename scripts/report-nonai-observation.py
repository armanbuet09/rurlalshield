"""Read immutable-by-protocol minute records; report actual counts without filling gaps."""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'cdk.out/python-tools'))
import boto3,json,math
from datetime import datetime,timezone,timedelta
p=ROOT/'cdk.out/observation-state.json';state=json.loads(p.read_text());m=state['manifest'];out=ROOT/'cdk.out/observation-reports';out.mkdir(exist_ok=True);cache=out/'minutes';cache.mkdir(exist_ok=True)
s=boto3.Session(profile_name='ruralshield-research',region_name='us-east-2');s3=s.client('s3');bucket=state['outputs']['EvidenceBucket']
objects=[]
try:retirement=json.loads(s3.get_object(Bucket=bucket,Key='closeout/local-retirement.json')['Body'].read())
except s3.exceptions.NoSuchKey:retirement=None
if retirement and retirement.get('executed'):
    from paper_evidence import archived_minutes
    rows,local_verification=archived_minutes(Path(retirement['archive']),bucket,expected_window=m)
    data_source={'type':'verified local final archive','path':retirement['archive'],'zipSha256':local_verification['zipSha256']}
else:
    for page in s3.get_paginator('list_objects_v2').paginate(Bucket=bucket,Prefix='minutes/'):
        objects.extend(page.get('Contents',[]))
    rows=[]
    for obj in objects:
        f=cache/Path(obj['Key']).name
        if not f.exists():f.write_bytes(s3.get_object(Bucket=bucket,Key=obj['Key'])['Body'].read())
        rows.append(json.loads(f.read_text()))
    data_source={'type':'AWS minute records'}
start=datetime.fromisoformat(m['startAt']);end=datetime.fromisoformat(m['endAt']);now=datetime.now(timezone.utc)
elapsed=max(0,min(7200,math.floor((min(now,end)-start).total_seconds()/60)));seen={r['slot'] for r in rows};latencies=sorted(x for r in rows for x in r['latenciesMs'])
def percentile(p):return latencies[max(0,math.ceil(p*len(latencies))-1)] if latencies else None
control={}
for name in ['closed','stopped-early']:
    try:control[name]=json.loads(s3.get_object(Bucket=bucket,Key='control/'+name+'.json')['Body'].read())
    except s3.exceptions.NoSuchKey:pass
summary={'checkedAt':now.isoformat(),'startAt':m['startAt'],'endAt':m['endAt'],'condition':m['condition'],'targetRequests':1000000,'minuteRecords':len(rows),'fullyElapsedMinutes':elapsed,'missingFullyElapsedMinutes':[x for x in range(elapsed) if x not in seen],'attempted':sum(r['attempted'] for r in rows),'succeeded':sum(r['succeeded'] for r in rows),'failed':sum(r['failed'] for r in rows),'unsentRequestsInRecordedMinutes':sum(r['missing'] for r in rows),'clientLatencyMs':{'count':len(latencies),'p50':percentile(.5),'p95':percentile(.95),'p99':percentile(.99),'method':'nearest rank, authenticated HTTPS client elapsed time, AWS Ohio Lambda client'},'ruleState':s.client('events').describe_rule(Name=state['outputs']['RuleName'])['State'],'control':control,'completeWindowElapsed':now>=end,'dataSource':data_source,'limitations':'Single non-AI pilot; no clinical/AI/comparative conclusions. Missing minutes are not imputed.'}
try:
    costs=s.client('ce',region_name='us-east-1').get_cost_and_usage(TimePeriod={'Start':start.date().isoformat(),'End':(min(now,end).date()+timedelta(days=1)).isoformat()},Granularity='DAILY',Metrics=['UnblendedCost'],Filter={'Not':{'Dimensions':{'Key':'RECORD_TYPE','Values':['Credit','Refund']}}},GroupBy=[{'Type':'DIMENSION','Key':'SERVICE'}]);(out/'account-day-costs.json').write_text(json.dumps(costs,indent=2,default=str));summary['costBoundary']='Estimated whole-account UTC-day costs, excludes credits/refunds; not attributable exact 120-hour experiment charges.'
except Exception as e:summary['costDataError']=str(e)
if '--closeout' in sys.argv:
    assert now>=end or 'stopped-early' in control,'Do not close an ongoing pilot'
    s.client('events').disable_rule(Name=state['outputs']['RuleName'])
    assert state['username'].startswith('rs-observer-')
    s.client('cognito-idp').admin_disable_user(UserPoolId=state['poolId'],Username=state['username'])
    summary['closeout']={'loadScheduleDisabled':True,'syntheticUserDisabled':True,'workloadAndRetainedStorage':'retained; ongoing service/storage charges are outside the active measurement window'}
    state['phase']='closed' if now>=end else 'stopped-early';p.write_text(json.dumps(state,indent=2))
(out/'latest.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2))
