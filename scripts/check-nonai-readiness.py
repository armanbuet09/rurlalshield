"""Resume/read bounded readiness jobs. Restore only into a named disposable table."""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'cdk.out/python-tools'))
import boto3,json,hashlib
from datetime import datetime,timezone
p=Path(sys.argv[1]);state=json.loads(p.read_text());s=boto3.Session(profile_name='ruralshield-research',region_name='us-east-2');backup=s.client('backup')
def save(): state['lastCheckedAt']=datetime.now(timezone.utc).isoformat();p.write_text(json.dumps(state,indent=2,default=str))
if 'backup' not in state:
    job=backup.start_backup_job(BackupVaultName=state['vault'],ResourceArn='arn:aws:dynamodb:us-east-2:123456789012:table/'+state['sourceTable'],IamRoleArn=state['backupRoleArn'],IdempotencyToken=state['runId'],StartWindowMinutes=60,CompleteWindowMinutes=120,Lifecycle={'DeleteAfterDays':35})
    state['backup']={'jobId':job['BackupJobId'],'recoveryPointArn':job['RecoveryPointArn'],'status':'pending'};save()
job=backup.describe_backup_job(BackupJobId=state['backup']['jobId']);(p.parent/'backup-job.json').write_text(json.dumps(job,indent=2,default=str));state['backup'].update({'status':job['State'],'message':job.get('StatusMessage')});save()
rep=state['replication']
try:
    obj=s.client('s3',region_name='us-west-2').get_object(Bucket=rep['destinationBucket'],Key=rep['key']);body=obj['Body'].read()
    rep.update({'status':'passed' if hashlib.sha256(body).hexdigest()==rep['sha256'] and obj.get('ReplicationStatus')=='REPLICA' else 'failed','replicationStatus':obj.get('ReplicationStatus'),'destinationVersionId':obj.get('VersionId'),'verifiedAt':datetime.now(timezone.utc).isoformat()});save()
except s.client('s3').exceptions.NoSuchKey: rep['status']='pending';save()
if job['State']=='COMPLETED' and 'restore' not in state:
    target='rs-restore-'+state['runId'];assert target.startswith('rs-restore-nonai-')
    meta=backup.get_recovery_point_restore_metadata(BackupVaultName=state['vault'],RecoveryPointArn=state['backup']['recoveryPointArn'])['RestoreMetadata']
    meta.update({'targetTableName':target,'encryptionType':'KMS','kmsMasterKeyArn':'arn:aws:kms:us-east-2:123456789012:key/00000000-0000-4000-8000-000000000000'})
    r=backup.start_restore_job(RecoveryPointArn=state['backup']['recoveryPointArn'],Metadata=meta,IamRoleArn=state['restoreRoleArn'],IdempotencyToken=state['runId']+'-restore',ResourceType='DynamoDB',CopySourceTagsToRestoredResource=False)
    state['restore']={'jobId':r['RestoreJobId'],'targetTable':target,'status':'pending'};save()
if 'restore' in state:
    r=backup.describe_restore_job(RestoreJobId=state['restore']['jobId']);(p.parent/'restore-job.json').write_text(json.dumps(r,indent=2,default=str));state['restore'].update({'status':r['Status'],'message':r.get('StatusMessage')});save()
    if r['Status']=='COMPLETED' and not state['restore'].get('dataVerified'):
        table=s.resource('dynamodb').Table(state['restore']['targetTable']);item=table.get_item(Key={'pk':'PATIENT#'+state['patient']['id'],'sk':'DEMOGRAPHICS'},ConsistentRead=True).get('Item',{})
        state['restore']['dataVerified']=item.get('resource')==state['patient'];save()
        if state['restore']['dataVerified']:
            import os,importlib.util
            os.environ['TABLE_NAME']=state['restore']['targetTable'];os.environ.pop('PHI_BUCKET',None)
            boto3.DEFAULT_SESSION=s
            spec=importlib.util.spec_from_file_location('restore_acceptance',ROOT/'examples/sample-app/app.py');app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
            response=app.handler({'path':'/Patient/'+state['patient']['id'],'httpMethod':'GET','requestContext':{'authorizer':{'claims':{'email':'synthetic-restore@example.invalid'}}}},None)
            state['restore']['applicationHandlerAccepted']=response['statusCode']==200 and json.loads(response['body'])==state['patient'];save()
            if not state['restore']['applicationHandlerAccepted']: raise RuntimeError('Restored data failed application-handler acceptance')
            # Dedicated restored table only; never delete the source or its recovery point.
            target=state['restore']['targetTable'];assert target=='rs-restore-'+state['runId']
            s.client('dynamodb').delete_table(TableName=target);state['restore']['disposableTableDeletionRequested']=True;save()
sns=s.client('sns');topic='arn:aws:sns:us-east-2:123456789012:ruralshield-research-rural-shield-alerts'
subs=sns.list_subscriptions_by_topic(TopicArn=topic)['Subscriptions'];confirmed=any(x['Protocol']=='email' and x['Endpoint']=='research-alerts@example.com' and x['SubscriptionArn']!='PendingConfirmation' for x in subs)
state['alerts']={'subscriptionConfirmed':confirmed,**state.get('alerts',{})};state['alerts']['subscriptionConfirmed']=confirmed
if confirmed and not state['alerts'].get('testMessageId'):
    assert all(x['Protocol']=='email' and x['Endpoint']=='research-alerts@example.com' for x in subs)
    msg=sns.publish(TopicArn=topic,Subject='RuralShield non-AI readiness test',Message='Synthetic RuralShield alert test for '+state['runId']+'. This checks notification delivery for the planned five-day non-AI study. No clinical data or incident is involved.')
    state['alerts']['testMessageId']=msg['MessageId'];state['alerts']['publishedAt']=datetime.now(timezone.utc).isoformat()
state['readyForObservation']=bool(confirmed and state['alerts'].get('testMessageId') and state['alerts'].get('userConfirmedReceipt') and rep['status']=='passed' and state.get('restore',{}).get('dataVerified') and state.get('restore',{}).get('applicationHandlerAccepted') and all(x['passed'] for x in state['checks']));save()
print(json.dumps({k:state.get(k) for k in ['runId','backup','restore','replication','alerts','readyForObservation']},indent=2))
