// Private subprocess protocol: stdout is consumed in memory by the provisioning script.
// Never run with shell output logging or persist this output.
const {signIn}=require('../cdk.out/auth-tools/observation-auth.cjs');
let input='';process.stdin.on('data',x=>{input+=x;});process.stdin.on('end',async()=>{
  try{const cfg=JSON.parse(input);input='';const r=await signIn(cfg,true);process.stdout.write(JSON.stringify({totpSecret:r.secretCode}));}
  catch(e){process.stderr.write(e.name+': '+e.message);process.exitCode=1;}
});
