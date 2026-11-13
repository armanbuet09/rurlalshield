"""Deadline-guarded AWS closeout. Evidence first; no object, key, vault or stack deletion.

Packaged plan.json pins the account, deadline and physical resource IDs. This
instrumentation is separate from the frozen observation worker and workload.
"""
import concurrent.futures
import hashlib
import json
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

PLAN = json.loads(Path(__file__).with_name('plan.json').read_text()) if Path(__file__).with_name('plan.json').exists() else None
CLIENTS = {}


def client(service, region='us-east-2'):
    key = service, region
    if key not in CLIENTS:
        CLIENTS[key] = boto3.client(service, region_name=region, config=Config(
            retries={'mode': 'standard', 'max_attempts': 5}, max_pool_connections=32,
            connect_timeout=5, read_timeout=35))
    return CLIENTS[key]


def deadline_ready(plan, now):
    return now >= datetime.fromisoformat(plan['endAt']) + timedelta(minutes=5)


def resources(kind, region=None):
    return [(rg, r['PhysicalResourceId']) for rg, stacks in PLAN['regions'].items()
            if region is None or rg == region for st in stacks for r in st['resources']
            if r['ResourceType'] == kind and r.get('PhysicalResourceId')]


def get(key):
    try:
        return json.loads(client('s3').get_object(Bucket=PLAN['evidenceBucket'], Key=key)['Body'].read())
    except ClientError as e:
        if e.response['Error']['Code'] in ('NoSuchKey', '404'):
            return None
        raise


def put(name, value):
    key = 'closeout/' + name + '.json'
    body = json.dumps(value, default=str, sort_keys=True).encode()
    digest = hashlib.sha256(body).hexdigest()
    client('s3').put_object(Bucket=PLAN['evidenceBucket'], Key=key, Body=body,
                          ContentType='application/json', Metadata={'sha256': digest})
    actual = client('s3').get_object(Bucket=PLAN['evidenceBucket'], Key=key)['Body'].read()
    if hashlib.sha256(actual).hexdigest() != digest:
        raise RuntimeError('Evidence verification failed: ' + key)
    return {'key': key, 'sha256': digest, 'bytes': len(body)}


def pages(service, operation, region='us-east-2', **kwargs):
    c = client(service, region)
    if c.can_paginate(operation):
        return list(c.get_paginator(operation).paginate(**kwargs))
    result = []
    while True:
        page = getattr(c, operation)(**kwargs)
        result.append(page)
        token = page.get('NextToken') or page.get('nextToken')
        if not token:
            return result
        kwargs['NextToken' if 'NextToken' in page else 'nextToken'] = token


def shared_service_guard():
    """Account-wide scanners must not be turned off for a newly added workload."""
    unexpected = []
    allowed_buckets = {x for _, x in resources('AWS::S3::Bucket')}
    for region in PLAN['regions']:
        allowed_functions = {x for _, x in resources('AWS::Lambda::Function', region)}
        for page in pages('lambda', 'list_functions', region):
            for f in page['Functions']:
                if f['FunctionName'] not in allowed_functions and f['FunctionName'] != PLAN['closeoutFunction']:
                    unexpected.append(region + ':lambda:' + f['FunctionName'])
        for page in pages('ec2', 'describe_instances', region):
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] != 'terminated':
                        unexpected.append(region + ':ec2:' + instance['InstanceId'])
        for page in pages('rds', 'describe_db_instances', region):
            unexpected.extend(region + ':rds:' + x['DBInstanceIdentifier'] for x in page['DBInstances'])
        for page in pages('ecs', 'list_clusters', region):
            unexpected.extend(region + ':ecs:' + x for x in page['clusterArns'])
        allowed_stacks = {s['name'] for s in PLAN['regions'][region]} | {'CDKToolkit', PLAN['closeoutStack']}
        for page in pages('cloudformation', 'describe_stacks', region):
            unexpected.extend(region + ':stack:' + x['StackName'] for x in page['Stacks']
                              if x['StackName'] not in allowed_stacks)
        allowed_tables = {x for _, x in resources('AWS::DynamoDB::GlobalTable')} | {x for _, x in resources('AWS::DynamoDB::Table')}
        for page in pages('dynamodb', 'list_tables', region):
            unexpected.extend(region + ':table:' + x for x in page['TableNames'] if x not in allowed_tables)
    for b in client('s3').list_buckets()['Buckets']:
        if b['Name'] not in allowed_buckets and not b['Name'].startswith('cdk-hnb659fds-assets-'):
            unexpected.append('s3:' + b['Name'])
    return {'safeForAccountWidePause': not unexpected, 'unexpectedResources': unexpected,
            'boundary': 'Ohio/Oregon dedicated research account check; other regions are untouched'}


def final_measurements():
    objects = [o for p in pages('s3', 'list_objects_v2', Bucket=PLAN['evidenceBucket'], Prefix='minutes/') for o in p.get('Contents', [])]
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        rows = list(executor.map(lambda obj: get(obj['Key']), objects))
    latencies = sorted(x for r in rows for x in r['latenciesMs'])
    seen = {r['slot'] for r in rows}
    return {'startAt': PLAN['startAt'], 'endAt': PLAN['endAt'], 'collectedAt': datetime.now(timezone.utc),
            'minuteRecords': len(rows), 'missingSlots': [x for x in range(7200) if x not in seen],
            'attempted': sum(r['attempted'] for r in rows), 'succeeded': sum(r['succeeded'] for r in rows),
            'failed': sum(r['failed'] for r in rows), 'unsentInRecordedSlots': sum(r['missing'] for r in rows),
            'clientLatencyMs': {name: latencies[max(0, math.ceil(p * len(latencies)) - 1)] if latencies else None
                                for name, p in [('p50', .5), ('p95', .95), ('p99', .99)]},
            'limitations': 'Single non-AI condition. Ohio Lambda HTTPS client times, not clinic WAN or clinical outcomes. Missing slots not imputed.'}


def archive(preview=False):
    existing = None if preview else get('closeout/archive-verified.json')
    if existing:
        # Recheck the gate and every exported JSON on retry before any mutations.
        for item in existing['objects']:
            body = client('s3').get_object(Bucket=PLAN['evidenceBucket'], Key=item['key'])['Body'].read()
            if hashlib.sha256(body).hexdigest() != item['sha256']:
                raise RuntimeError('Previously archived evidence changed')
        return existing
    saved = []
    prefix = 'preflight/' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '/' if preview else ''
    def save(name, value):
        saved.append(put(prefix + 'archive/' + name, value))
    save('final-measurements', final_measurements())
    save('shutdown-plan', PLAN)
    for region, stacks in PLAN['regions'].items():
        for st in stacks:
            c = client('cloudformation', region)
            save(region + '/' + st['name'], {'stack': c.describe_stacks(StackName=st['name']),
                 'resources': pages('cloudformation', 'list_stack_resources', region, StackName=st['name']),
                 'template': c.get_template(StackName=st['name'], TemplateStage='Original')})
        for _, group in resources('AWS::Logs::LogGroup', region):
            save(region + '/log-group-' + hashlib.sha256(group.encode()).hexdigest()[:12],
                 client('logs', region).describe_log_groups(logGroupNamePrefix=group))
        for _, vault in resources('AWS::Backup::BackupVault', region):
            save(region + '/backup-' + vault, {'vault': client('backup', region).describe_backup_vault(BackupVaultName=vault),
                 'points': pages('backup', 'list_recovery_points_by_backup_vault', region, BackupVaultName=vault)})
        for _, bucket in resources('AWS::S3::Bucket', region):
            # Original versioned/locked objects stay in their existing encrypted buckets.
            save(region + '/bucket-' + bucket, {'versions': pages('s3', 'list_object_versions', region, Bucket=bucket),
                 'encryption': client('s3', region).get_bucket_encryption(Bucket=bucket),
                 'logging': client('s3', region).get_bucket_logging(Bucket=bucket)})
        tables = sorted({x for _, x in resources('AWS::DynamoDB::GlobalTable')} | {x for _, x in resources('AWS::DynamoDB::Table', region)})
        for table in tables:
            try:
                description = client('dynamodb', region).describe_table(TableName=table)
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException' and region != 'us-east-2':
                    save(region + '/table-' + table, {'present': False, 'reason': 'No deployed DynamoDB replica in this region'})
                    continue
                raise
            save(region + '/table-' + table, {'description': description,
                 'pitr': client('dynamodb', region).describe_continuous_backups(TableName=table),
                 'contributorInsights': client('dynamodb', region).describe_contributor_insights(TableName=table),
                 'items': pages('dynamodb', 'scan', region, TableName=table, ConsistentRead=True)})
    region = 'us-east-2'
    save('securityhub-findings', pages('securityhub', 'get_findings', region))
    save('securityhub-standards', pages('securityhub', 'get_enabled_standards', region))
    save('inspector-findings', pages('inspector2', 'list_findings', region))
    save('inspector-status', client('inspector2').batch_get_account_status(accountIds=[PLAN['account']]))
    for _, detector in resources('AWS::GuardDuty::Detector'):
        ids = [i for p in pages('guardduty', 'list_findings', DetectorId=detector) for i in p['FindingIds']]
        save('guardduty', {'detector': client('guardduty').get_detector(DetectorId=detector),
             'findings': [client('guardduty').get_findings(DetectorId=detector, FindingIds=ids[i:i+50]) for i in range(0, len(ids), 50)]})
    mids = [i for p in pages('macie2', 'list_findings') for i in p['findingIds']]
    save('macie', {'session': client('macie2').get_macie_session(), 'findings': [
         client('macie2').get_findings(findingIds=mids[i:i+50]) for i in range(0, len(mids), 50)]})
    save('config-rules', pages('config', 'describe_config_rules'))
    save('config-status', pages('config', 'describe_config_rule_evaluation_status'))
    for _, rule in resources('AWS::Config::ConfigRule'):
        save('config/' + rule, pages('config', 'get_compliance_details_by_config_rule', ConfigRuleName=rule))
    for region in PLAN['regions']:
        names = [x for _, x in resources('AWS::CloudWatch::Alarm', region)]
        if names:
            save(region + '/alarms', client('cloudwatch', region).describe_alarms(AlarmNames=names))
    # Metric samples are preserved separately from log groups and immutable log archives.
    queries = []
    for metric, stat in [('Count', 'Sum'), ('4XXError', 'Sum'), ('5XXError', 'Sum'), ('Latency', 'Average'), ('IntegrationLatency', 'Average')]:
        queries.append({'Id': 'm' + str(len(queries)), 'MetricStat': {'Metric': {'Namespace': 'AWS/ApiGateway', 'MetricName': metric,
                        'Dimensions': [{'Name': 'ApiName', 'Value': PLAN['apiName']}, {'Name': 'Stage', 'Value': 'dev'}]}, 'Period': 3600, 'Stat': stat}})
    save('metrics', pages('cloudwatch', 'get_metric_data', MetricDataQueries=queries,
         StartTime=datetime.fromisoformat(PLAN['startAt']), EndTime=datetime.fromisoformat(PLAN['endAt'])))
    manifest = {'verifiedAt': datetime.now(timezone.utc), 'objects': saved,
                'retained': 'Raw minutes, frozen source/config, original locked S3 objects, CloudWatch log groups, DynamoDB tables, vaults and all KMS keys. No secret values exported.'}
    if preview:
        manifest['purpose'] = 'Archive permission diagnostic during active run; not final evidence or a shutdown gate'
    put(prefix + 'archive-verified', manifest)
    return manifest


def absent_ok(call, **kwargs):
    try:
        return call(**kwargs)
    except ClientError as e:
        if e.response['Error']['Code'] in ('ResourceNotFoundException', 'ResourceNotFound', 'NotFoundException', 'NoSuchEntityException', 'WAFNonexistentItemException', 'NoSuchConfigRuleException'):
            return {'alreadyAbsent': True}
        raise


def shutdown(guard):
    results = []
    def action(name, fn):
        prior = get('closeout/actions/' + name + '.json')
        if prior:
            results.append(prior)
            return
        value = fn()
        if isinstance(value, dict) and value.get('failedAccounts'):
            raise RuntimeError('Service reported unsuccessful account operations: ' + name)
        receipt = {'name': name, 'at': datetime.now(timezone.utc), 'result': value}
        put('actions/' + name, receipt)
        results.append(receipt)
    for region, rule in resources('AWS::Events::Rule'):
        action(region + '-rule-' + rule, lambda region=region, rule=rule: client('events', region).disable_rule(Name=rule))
    action('disable-observer', lambda: client('cognito-idp').admin_disable_user(UserPoolId=PLAN['poolId'], Username=PLAN['username']))
    for region, bucket in resources('AWS::S3::Bucket'):
        if '-rshield-phi-' in bucket:
            action('stop-access-logging-' + region, lambda region=region, bucket=bucket:
                   client('s3', region).put_bucket_logging(Bucket=bucket, BucketLoggingStatus={}))
    for region, table in resources('AWS::DynamoDB::GlobalTable') + resources('AWS::DynamoDB::Table'):
        action('disable-contributor-insights-' + table, lambda region=region, table=table:
               client('dynamodb', region).update_contributor_insights(TableName=table, ContributorInsightsAction='DISABLE'))
    # No more ingress before removing WAF and private endpoint connectivity.
    for region, api in resources('AWS::ApiGateway::RestApi'):
        action('disassociate-waf-' + api, lambda region=region, api=api: absent_ok(
               client('wafv2', region).disassociate_web_acl, ResourceArn=f'arn:aws:apigateway:{region}::/restapis/{api}/stages/dev'))
    for region, api in resources('AWS::ApiGateway::RestApi'):
        action('delete-api-' + api, lambda region=region, api=api: absent_ok(client('apigateway', region).delete_rest_api, restApiId=api))
    for region, physical in resources('AWS::WAFv2::WebACL'):
        name, identity, scope = physical.split('|')
        def remove_waf(region=region, name=name, identity=identity, scope=scope):
            w = client('wafv2', region)
            try:
                current = w.get_web_acl(Name=name, Id=identity, Scope=scope)
            except ClientError as e:
                if e.response['Error']['Code'] == 'WAFNonexistentItemException':
                    return {'alreadyAbsent': True}
                raise
            arn = current['WebACL']['ARN']
            absent_ok(w.delete_logging_configuration, ResourceArn=arn)
            for attached in w.list_resources_for_web_acl(WebACLArn=arn, ResourceType='API_GATEWAY').get('ResourceArns', []):
                w.disassociate_web_acl(ResourceArn=attached)
            return w.delete_web_acl(Name=name, Id=identity, Scope=scope, LockToken=current['LockToken'])
        action('delete-waf-' + identity, remove_waf)
    for region, endpoint in resources('AWS::EC2::VPCEndpoint'):
        def remove_endpoint(region=region, endpoint=endpoint):
            try:
                response = client('ec2', region).delete_vpc_endpoints(VpcEndpointIds=[endpoint])
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidVpcEndpointId.NotFound':
                    return {'alreadyAbsent': True}
                raise
            bad = [x for x in response.get('Unsuccessful', []) if x.get('Error', {}).get('Code') != 'InvalidVpcEndpointId.NotFound']
            if bad:
                raise RuntimeError(str(bad))
            return response
        action('delete-endpoint-' + endpoint, remove_endpoint)
    for region, plan_name in resources('AWS::Backup::RestoreTestingPlan'):
        for _, selection in resources('AWS::Backup::RestoreTestingSelection', region):
            parent, child = selection.split('|')
            action('restore-selection-' + child, lambda region=region, parent=parent, child=child:
                   absent_ok(client('backup', region).delete_restore_testing_selection, RestoreTestingPlanName=parent, RestoreTestingSelectionName=child))
        action('restore-plan-' + plan_name, lambda region=region, plan_name=plan_name:
               absent_ok(client('backup', region).delete_restore_testing_plan, RestoreTestingPlanName=plan_name))
    for region, plan_id in resources('AWS::Backup::BackupPlan'):
        def remove_backup_plan(region=region, plan_id=plan_id):
            b = client('backup', region)
            try:
                selections = pages('backup', 'list_backup_selections', region, BackupPlanId=plan_id)
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    return {'alreadyAbsent': True}
                raise
            for page in selections:
                for selection in page['BackupSelectionsList']:
                    absent_ok(b.delete_backup_selection, BackupPlanId=plan_id, SelectionId=selection['SelectionId'])
            return absent_ok(b.delete_backup_plan, BackupPlanId=plan_id)
        action('backup-plan-' + plan_id, remove_backup_plan)
    # Per-rule deletion prevents periodic Config evaluations after recording stops.
    for region, rule in resources('AWS::Config::ConfigRule'):
        action('config-rule-' + rule, lambda region=region, rule=rule:
               absent_ok(client('config', region).delete_config_rule, ConfigRuleName=rule))
    if guard['safeForAccountWidePause']:
        for region, recorder in resources('AWS::Config::ConfigurationRecorder'):
            action('stop-recorder-' + region, lambda region=region, recorder=recorder:
                   client('config', region).stop_configuration_recorder(ConfigurationRecorderName=recorder))
        for region, detector in resources('AWS::GuardDuty::Detector'):
            action('suspend-guardduty-' + region, lambda region=region, detector=detector:
                   client('guardduty', region).update_detector(DetectorId=detector, Enable=False))
        if resources('AWS::SecurityHub::Hub'):
            action('disable-securityhub', lambda: client('securityhub').disable_security_hub())
        if resources('AWS::Macie::Session'):
            action('pause-macie', lambda: client('macie2').update_macie_session(status='PAUSED'))
        action('disable-inspector', lambda: client('inspector2').disable(accountIds=[PLAN['account']], resourceTypes=['LAMBDA', 'LAMBDA_CODE', 'ECR']))
        for region, trail in resources('AWS::CloudTrail::Trail'):
            action('stop-trail-' + region, lambda region=region, trail=trail: client('cloudtrail', region).stop_logging(Name=trail))
    for region, flow in resources('AWS::EC2::FlowLog'):
        def remove_flow(region=region, flow=flow):
            response = client('ec2', region).delete_flow_logs(FlowLogIds=[flow])
            if response.get('Unsuccessful'):
                raise RuntimeError('Flow-log deletion failed')
            return response
        action('stop-flow-' + flow, remove_flow)
    for region in PLAN['regions']:
        alarms = [x for _, x in resources('AWS::CloudWatch::Alarm', region)]
        if alarms:
            action('delete-alarms-' + region, lambda region=region, alarms=alarms: client('cloudwatch', region).delete_alarms(AlarmNames=alarms))
        # Keep all original logs readable for at least one year after closeout.
        groups = [x for _, x in resources('AWS::Logs::LogGroup', region)]
        if region == 'us-east-2':
            groups += [x['logGroupName'] for x in client('logs').describe_log_groups(logGroupNamePrefix='API-Gateway-Execution-Logs_' + PLAN['apiId'])['logGroups']]
        for group in groups:
            action('log-retention-' + hashlib.sha256(group.encode()).hexdigest()[:12], lambda region=region, group=group:
                   client('logs', region).put_retention_policy(logGroupName=group, retentionInDays=365))
    action('retire-observer-secret', lambda: client('secretsmanager').delete_secret(SecretId=PLAN['authSecretArn'], RecoveryWindowInDays=7))
    return results


def verify(guard):
    checks = {}
    for region in PLAN['regions']:
        expected = {x for _, x in resources('AWS::EC2::VPCEndpoint', region)}
        present = [x['VpcEndpointId'] for p in pages('ec2', 'describe_vpc_endpoints', region) for x in p['VpcEndpoints']
                   if x['VpcEndpointId'] in expected and x['State'] != 'deleted']
        checks[region + '-endpoints-removed'] = not present
        current_flows = {x['FlowLogId'] for p in pages('ec2', 'describe_flow_logs', region) for x in p['FlowLogs']}
        checks[region + '-flow-logs-removed'] = not any(x in current_flows for _, x in resources('AWS::EC2::FlowLog', region))
        current_plans = {x['BackupPlanId'] for p in pages('backup', 'list_backup_plans', region) for x in p['BackupPlansList']}
        checks[region + '-backup-schedules-removed'] = not any(x in current_plans for _, x in resources('AWS::Backup::BackupPlan', region))
        restore_plans = {x['RestoreTestingPlanName'] for p in pages('backup', 'list_restore_testing_plans', region) for x in p['RestoreTestingPlans']}
        checks[region + '-restore-tests-removed'] = not any(x in restore_plans for _, x in resources('AWS::Backup::RestoreTestingPlan', region))
        alarms = [x for _, x in resources('AWS::CloudWatch::Alarm', region)]
        if alarms:
            current_alarms = client('cloudwatch', region).describe_alarms(AlarmNames=alarms)
            checks[region + '-alarms-removed'] = not current_alarms['MetricAlarms'] and not current_alarms['CompositeAlarms']
    checks['load-disabled'] = client('events').describe_rule(Name=PLAN['loadRule'])['State'] == 'DISABLED'
    checks['observer-disabled'] = client('cognito-idp').admin_get_user(UserPoolId=PLAN['poolId'], Username=PLAN['username'])['Enabled'] is False
    remaining_apis = {x['id'] for p in pages('apigateway', 'get_rest_apis') for x in p['items']}
    checks['api-removed'] = PLAN['apiId'] not in remaining_apis
    checks['bucket-access-logging-stopped'] = all(not client('s3', region).get_bucket_logging(Bucket=bucket).get('LoggingEnabled')
            for region, bucket in resources('AWS::S3::Bucket') if '-rshield-phi-' in bucket)
    checks['contributor-insights-disabled'] = all(client('dynamodb', region).describe_contributor_insights(TableName=table)['ContributorInsightsStatus'] == 'DISABLED'
            for region, table in resources('AWS::DynamoDB::GlobalTable') + resources('AWS::DynamoDB::Table'))
    for region, physical in resources('AWS::WAFv2::WebACL'):
        name, identity, scope = physical.split('|')
        try:
            client('wafv2', region).get_web_acl(Name=name, Id=identity, Scope=scope)
            checks['waf-removed'] = False
        except ClientError as e:
            if e.response['Error']['Code'] == 'WAFNonexistentItemException':
                checks['waf-removed'] = True
            else:
                raise
    rule_names = {r['ConfigRuleName'] for p in pages('config', 'describe_config_rules') for r in p['ConfigRules']}
    checks['owned-config-rules-removed'] = not any(x in rule_names for _, x in resources('AWS::Config::ConfigRule'))
    checks['account-wide-pause-unblocked'] = guard['safeForAccountWidePause']
    if guard['safeForAccountWidePause']:
        checks['config-stopped'] = all(not x['recording'] for x in client('config').describe_configuration_recorder_status()['ConfigurationRecordersStatus'])
        checks['guardduty-suspended'] = all(client('guardduty', rg).get_detector(DetectorId=detector)['Status'] == 'DISABLED' for rg, detector in resources('AWS::GuardDuty::Detector'))
        checks['macie-paused'] = client('macie2').get_macie_session()['status'] == 'PAUSED'
        try:
            client('securityhub').describe_hub()
            checks['securityhub-disabled'] = False
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidAccessException':
                checks['securityhub-disabled'] = True
            else:
                raise
        status = client('inspector2').batch_get_account_status(accountIds=[PLAN['account']])
        rs = status['accounts'][0]['resourceState']
        checks['inspector-disabled'] = all(rs[k]['status'] == 'DISABLED' for k in ['lambda', 'lambdaCode', 'ecr'])
        checks['trail-stopped'] = all(not client('cloudtrail', rg).get_trail_status(Name=trail)['IsLogging'] for rg, trail in resources('AWS::CloudTrail::Trail'))
    return checks


def handler(event, context):
    now = datetime.now(timezone.utc)
    if event.get('mode') not in ('preflight', 'archive-check') and not deadline_ready(PLAN, now):
        return {'status': 'before-closeout-deadline', 'notBefore': PLAN['endAt'] + ' plus five minutes'}
    if client('sts').get_caller_identity()['Account'] != PLAN['account']:
        raise RuntimeError('Wrong AWS account')
    guard = shared_service_guard()
    if event.get('mode') == 'preflight':
        return {'status': 'read-only-preflight', 'guard': guard, 'notBefore': PLAN['endAt'],
                'pinnedResources': sum(len(x['resources']) for ss in PLAN['regions'].values() for x in ss)}
    if event.get('mode') == 'archive-check':
        diagnostic = archive(preview=True)
        return {'status': 'archive-permissions-verified', 'objects': len(diagnostic['objects']),
                'shutdownPerformed': False, 'guard': guard}
    existing = get('closeout/completed.json')
    if existing:
        absent_ok(client('scheduler').delete_schedule, Name=PLAN['scheduleName'])
        return {'status': 'already-completed', 'at': existing['at']}
    archive()
    actions = shutdown(guard)
    checks = verify(guard)
    result = {'at': now, 'checks': checks, 'actions': len(actions), 'guard': guard,
              'retainedCosts': 'Encrypted S3/CloudWatch/DynamoDB evidence, locked backup storage and two KMS keys remain billable. No zero-bill claim.',
              'cloudFormation': 'Physical service removals deliberately create drift; stacks and evidence remain. Do not redeploy frozen application automatically.'}
    put('latest', result)
    if not all(checks.values()):
        raise RuntimeError('Closeout incomplete; see private closeout/latest.json. Automatic retry retained.')
    put('completed', result)
    # Completion also stops the native retry schedule; no reliance on CLI sessions.
    client('scheduler').delete_schedule(Name=PLAN['scheduleName'])
    return {'status': 'completed', 'checks': checks, 'evidenceBucket': PLAN['evidenceBucket']}
