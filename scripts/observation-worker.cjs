/** Scoped external instrumentation; sends only synthetic requests. */
const {S3Client,GetObjectCommand,PutObjectCommand}=require('@aws-sdk/client-s3');
const {SecretsManagerClient,GetSecretValueCommand}=require('@aws-sdk/client-secrets-manager');
const {EventBridgeClient,DisableRuleCommand}=require('@aws-sdk/client-eventbridge');
const {signIn}=require('./observation-auth.cjs');
const s3=new S3Client({}),sm=new SecretsManagerClient({}),events=new EventBridgeClient({});
let session;
async function put(key,value,extra={}){return s3.send(new PutObjectCommand({Bucket:process.env.EVIDENCE_BUCKET,Key:key,Body:JSON.stringify(value),ContentType:'application/json',...extra}));}
exports.handler=async(_event,context)=>{
  let manifest;
  try{manifest=JSON.parse(await (await s3.send(new GetObjectCommand({Bucket:process.env.EVIDENCE_BUCKET,Key:'control/manifest.json'}))).Body.transformToString());}
  catch(e){if(e.name==='NoSuchKey')return {status:'not-armed'};throw e;}
  const now=Date.now(),start=Date.parse(manifest.startAt),end=Date.parse(manifest.endAt);
  if(!Number.isFinite(start)||end-start!==120*3600000||manifest.targetRequests!==1000000)throw new Error('Invalid frozen five-day protocol');
  if(now<start)return {status:'before-start'};
  if(now>=end){
    await put('control/closed.json',{stoppedAt:new Date().toISOString(),reason:'absolute 120-hour cutoff',loadStopped:true,workloadResourcesRetained:true});
    await events.send(new DisableRuleCommand({Name:process.env.RULE_NAME}));return {status:'closed'};
  }
  const slot=Math.floor((now-start)/60000),key=`minutes/${String(slot).padStart(4,'0')}.json`;
  try{await put(`claims/${slot}.json`,{claimedAt:new Date().toISOString()},{IfNoneMatch:'*'});}
  catch(e){if(e.$metadata?.httpStatusCode===412)return {status:'duplicate'};throw e;}
  const planned=Math.floor((slot+1)*1000000/7200)-Math.floor(slot*1000000/7200);
  const result={slot,startedAt:new Date().toISOString(),planned,attempted:0,succeeded:0,failed:0,statusCounts:{},latenciesMs:[],errors:[],condition:'non-AI authenticated HTTPS synthetic pilot'};
  try{
    if(!session?.isValid() || session.getIdToken().getExpiration()*1000-Date.now()<120000){
      const credentials=JSON.parse((await sm.send(new GetSecretValueCommand({SecretId:process.env.AUTH_SECRET}))).SecretString);
      session=(await signIn(credentials)).session;
    }
    const token=session.getIdToken().getJwtToken();let next=0;
    const run=async()=>{while(next<planned && Date.now()<end && context.getRemainingTimeInMillis()>12000){
      const n=next++;const create=slot%60===0&&n===0,read=slot%60===0&&n===1;
      const path=create?'Patient':read?'Patient/'+manifest.patient.id:'health';
      const tick=performance.now();result.attempted++;
      try{
        const r=await fetch(manifest.endpoint+path,{method:create?'POST':'GET',headers:{Authorization:token,'Content-Type':'application/json'},body:create?JSON.stringify(manifest.patient):undefined,signal:AbortSignal.timeout(10000)});
        const body=await r.text();result.statusCounts[r.status]=(result.statusCounts[r.status]||0)+1;
        const matched=!read||require('util').isDeepStrictEqual(JSON.parse(body),manifest.patient);
        if(r.status===(create?201:200)&&matched)result.succeeded++;else result.failed++;
      }catch(e){result.failed++;if(result.errors.length<4)result.errors.push(e.name);}
      result.latenciesMs.push(performance.now()-tick);
    }};
    await Promise.all(Array.from({length:4},run));
  }catch(e){result.errors.push(e.name);result.authenticationFailed=true;}
  result.finishedAt=new Date().toISOString();result.missing=result.planned-result.attempted;
  await put(key,result);console.log(JSON.stringify({...result,latenciesMs:undefined}));
  // Stop instead of continuing a failing load run. No compensating or hidden retries.
  if(result.authenticationFailed || result.missing>0 || result.failed>Math.max(5,result.attempted*.1)){
    await put('control/stopped-early.json',{at:result.finishedAt,slot,reason:'authentication failure or >10% HTTP failure'});
    await events.send(new DisableRuleCommand({Name:process.env.RULE_NAME}));
  }
  return {slot,attempted:result.attempted,succeeded:result.succeeded,failed:result.failed};
};
