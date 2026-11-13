/** Read credentials from stdin; keep Cognito tokens and the test TOTP secret in memory. */
const { CognitoUserPool, CognitoUser, AuthenticationDetails } = require('../cdk.out/auth-tools/node_modules/amazon-cognito-identity-js');
const crypto = require('crypto');
let input = '';
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', async () => {
  const cfg = JSON.parse(input); input = '';
  const checks = [];
  const check = (name, passed, detail) => checks.push({ name, passed, detail });
  const cache = {};
  const storage = { setItem: (k,v) => { cache[k]=v; }, getItem: k => cache[k] ?? null,
    removeItem: k => { delete cache[k]; }, clear: () => { for (const k of Object.keys(cache)) delete cache[k]; } };
  const pool = new CognitoUserPool({ UserPoolId: cfg.poolId, ClientId: cfg.clientId, Storage: storage });
  let secret;
  function otp() {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const bits = [...secret.toUpperCase()].map(c => alphabet.indexOf(c).toString(2).padStart(5,'0')).join('');
    const key = Buffer.from((bits.match(/.{8}/g) ?? []).map(b => parseInt(b,2)));
    const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));
    const digest = crypto.createHmac('sha1',key).update(counter).digest(); const offset=digest[19]&15;
    return String((digest.readUInt32BE(offset)&0x7fffffff)%1000000).padStart(6,'0');
  }
  function login(setup) {
    const user = new CognitoUser({ Username: cfg.username, Pool: pool, Storage: storage });
    return new Promise((resolve,reject) => {
      const callbacks = {
        onSuccess: session => resolve({session,user}), onFailure: reject,
        mfaSetup: () => {
          check('SRP login requires MFA setup',setup,{});
          user.associateSoftwareToken({ onFailure: reject, associateSecretCode: code => {
            secret=code; user.verifySoftwareToken(otp(),'RuralShield synthetic readiness',callbacks);
          }});
        },
        totpRequired: () => {
          check('subsequent SRP login requires TOTP',!setup,{});
          user.sendMFACode(otp(),callbacks,'SOFTWARE_TOKEN_MFA');
        },
      };
      user.authenticateUser(new AuthenticationDetails({Username:cfg.username,Password:cfg.password}),callbacks);
    });
  }
  try {
    const first=await login(true); check('MFA enrollment completed',first.session.isValid(),{}); first.user.signOut();
    // Cognito rejects reuse of the enrollment code; use the next TOTP interval.
    await new Promise(resolve=>setTimeout(resolve,30000-(Date.now()%30000)+1200));
    const {session,user}=await login(false); check('SRP plus TOTP authentication',session.isValid(),{});
    const token=session.getIdToken().getJwtToken();
    async function call(name,path,method='GET',body) {
      const started=performance.now();
      const response=await fetch(cfg.endpoint+path,{method,headers:{Authorization:token,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(30000)});
      const text=await response.text(); check(name,response.status===(method==='POST'?201:200),{httpStatus:response.status,clientElapsedMs:performance.now()-started});
      return {status:response.status,body:JSON.parse(text)};
    }
    await call('authenticated HTTPS health','health');
    await call('authenticated HTTPS create','Patient','POST',cfg.patient);
    const read=await call('authenticated HTTPS read','Patient/'+cfg.patient.id);
    check('authenticated synthetic record round trip',require('util').isDeepStrictEqual(read.body,cfg.patient),{});
    user.signOut(); secret=undefined; storage.clear();
  } catch (e) { check('authentication or API error',false,{name:e.name,message:e.message}); }
  console.log(JSON.stringify({checkedAt:new Date().toISOString(),checks,passed:checks.every(x=>x.passed)}));
  process.exitCode=checks.every(x=>x.passed)?0:1;
});
