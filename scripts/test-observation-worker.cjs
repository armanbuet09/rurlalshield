const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const start=Date.parse('2026-11-01T00:00:00Z'),end=start+120*3600000;
async function run(now,{duplicate=false,authFails=false}={}){
 const calls=[];const manifest={startAt:new Date(start).toISOString(),endAt:new Date(end).toISOString(),targetRequests:1000000,endpoint:'https://example.invalid/',patient:{id:'synthetic'}};
 class Command{constructor(input){this.input=input;this.kind=this.constructor.name;}}
 const commands={};for(const n of ['GetObjectCommand','PutObjectCommand','GetSecretValueCommand','DisableRuleCommand'])commands[n]=class extends Command{constructor(x){super(x);this.kind=n;}};
 class Client{async send(cmd){calls.push(cmd);if(cmd.kind==='GetObjectCommand')return {Body:{transformToString:async()=>JSON.stringify(manifest)}};if(cmd.input.IfNoneMatch&&duplicate)throw Object.assign(new Error('duplicate'),{$metadata:{httpStatusCode:412}});if(cmd.kind==='GetSecretValueCommand')return {SecretString:'{}'};return {};}}
 class Clock extends Date{constructor(...args){super(...(args.length?args:[now]));}static now(){return now;}}
 const box={exports:{},Date:Clock,process:{env:{EVIDENCE_BUCKET:'test',AUTH_SECRET:'test',RULE_NAME:'test'}},console:{log(){}},performance,AbortSignal,
  fetch:async()=>({status:200,text:async()=>'{}'}),require:name=>name==='./observation-auth.cjs'?{signIn:async()=>{if(authFails)throw new Error('test authentication failed');return {session:{isValid:()=>true,getIdToken:()=>({getJwtToken:()=> 'synthetic',getExpiration:()=>Math.floor((end+3600000)/1000)})}};}}:name==='util'?require('util'):{...commands,S3Client:Client,SecretsManagerClient:Client,EventBridgeClient:Client}};
 vm.runInNewContext(fs.readFileSync(__dirname+'/observation-worker.cjs','utf8'),box);const response=await box.exports.handler({}, {getRemainingTimeInMillis:()=>50000});return {calls,response};
}
test('before start never reads credentials or sends load',async()=>{const r=await run(start-1);assert.equal(r.response.status,'before-start');assert.equal(r.calls.length,1);});
test('absolute cutoff disables schedule without reading credentials',async()=>{const r=await run(end);assert.equal(r.response.status,'closed');assert.equal(r.calls.some(x=>x.kind==='GetSecretValueCommand'),false);assert.equal(r.calls.filter(x=>x.kind==='DisableRuleCommand').length,1);});
test('duplicate minute never authenticates or sends load',async()=>{const r=await run(start+60000,{duplicate:true});assert.equal(r.response.status,'duplicate');assert.equal(r.calls.some(x=>x.kind==='GetSecretValueCommand'),false);});
test('authentication failure is persisted and stops schedule',async()=>{const r=await run(start+60000,{authFails:true});const minute=r.calls.find(x=>x.kind==='PutObjectCommand'&&x.input.Key.startsWith('minutes/'));assert.equal(JSON.parse(minute.input.Body).attempted,0);assert.equal(r.calls.some(x=>x.kind==='DisableRuleCommand'),true);});
test('last slot is bounded to 139 requests and records all outcomes',async()=>{const r=await run(end-60000);assert.equal(r.response.attempted,139);assert.equal(r.response.succeeded,139);const minute=r.calls.find(x=>x.kind==='PutObjectCommand'&&x.input.Key.startsWith('minutes/'));assert.equal(JSON.parse(minute.input.Body).missing,0);});
