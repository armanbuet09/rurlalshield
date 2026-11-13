const {CognitoUserPool,CognitoUser,AuthenticationDetails}=require('amazon-cognito-identity-js');
const crypto=require('crypto');
function totp(secret) {
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bits=[...secret.toUpperCase()].map(c=>alphabet.indexOf(c).toString(2).padStart(5,'0')).join('');
  const key=Buffer.from((bits.match(/.{8}/g)||[]).map(b=>parseInt(b,2)));
  const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));
  const h=crypto.createHmac('sha1',key).update(counter).digest();
  return String((h.readUInt32BE(h[19]&15)&0x7fffffff)%1000000).padStart(6,'0');
}
function signIn(cfg,enroll=false) {
  const cache={}; const storage={setItem:(k,v)=>{cache[k]=v;},getItem:k=>cache[k]??null,removeItem:k=>{delete cache[k];},clear:()=>{for(const k in cache)delete cache[k];}};
  const pool=new CognitoUserPool({UserPoolId:cfg.poolId,ClientId:cfg.clientId,Storage:storage});
  const user=new CognitoUser({Username:cfg.username,Pool:pool,Storage:storage});
  return new Promise((resolve,reject)=>{
    let secretCode=cfg.totpSecret;
    const cb={onSuccess:session=>resolve({session,secretCode}),onFailure:reject,
      totpRequired:()=>user.sendMFACode(totp(secretCode),cb,'SOFTWARE_TOKEN_MFA'),
      mfaSetup:()=>{
        if(!enroll)return reject(new Error('Observation user is not enrolled for TOTP'));
        user.associateSoftwareToken({onFailure:reject,associateSecretCode:secret=>{secretCode=secret;user.verifySoftwareToken(totp(secret),'RuralShield synthetic observation',cb);}});
      }};
    user.authenticateUser(new AuthenticationDetails({Username:cfg.username,Password:cfg.password}),cb);
  });
}
module.exports={signIn};
