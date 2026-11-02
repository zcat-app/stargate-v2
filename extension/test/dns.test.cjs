const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const D=require('../src/dns.js'),C=require('../src/core.js');
function fixture(){
 const calls=[],states={dns:{value:true,levelOfControl:'controllable_by_this_extension'},rtc:{value:'default',levelOfControl:'controllable_by_this_extension'}};
 const setting=key=>({get:async()=>({...states[key]}),set:async v=>{calls.push([key+'-set']);Object.assign(states[key],{value:v.value,levelOfControl:'controlled_by_this_extension'});},clear:async()=>{calls.push([key+'-clear']);Object.assign(states[key],{value:key==='dns'?true:'default',levelOfControl:'controllable_by_this_extension'});}});
 return {calls,states,api:{privacy:{network:{networkPredictionEnabled:setting('dns'),webRTCIPHandlingPolicy:setting('rtc')}}}};
}
test('Firefox requires owned false readback; unavailable, conflicts and ignored writes fail',async()=>{
 await assert.rejects(D.apply({},'firefox'),/DNS_UNAVAILABLE/);
 const f=fixture();f.states.dns.levelOfControl='controlled_by_other_extensions';await assert.rejects(D.apply(f.api,'firefox'),/DNS_CONFLICT/);assert.deepEqual(f.calls,[]);
 f.states.dns.levelOfControl='controllable_by_this_extension';f.api.privacy.network.networkPredictionEnabled.set=async()=>{};
 await assert.rejects(D.apply(f.api,'firefox'),/DNS_NOT_CONFIRMED/);
});
test('Brave prediction stays browser-managed and Release never clears another owner',async()=>{
 const f=fixture();await D.apply(f.api,'brave');await D.release(f.api,'brave');assert.deepEqual(f.calls,[]);assert.equal((await D.status(f.api,'brave')).state,'BROWSER_MANAGED');
 await D.apply(f.api,'firefox');f.states.dns.levelOfControl='controlled_by_other_extensions';const count=f.calls.length;await D.release(f.api,'firefox');assert.equal(f.calls.length,count);
});
function background(){
  const f=fixture(),handlers={},event=name=>({addListener:fn=>handlers[name]=fn});
  const p={version:1,managerOrigin:'http://127.0.0.1:9080',profileId:'proof',username:'proof',password:'test-only-rtc-credential-not-a-secret',authorization:'StargateProfile proof:'+'a'.repeat(43),proxy:{host:'127.0.0.1',port:8881},desired:true};
  const bag={pairing:p};let proxy={levelOfControl:'controlled_by_this_extension',value:C.configuration('firefox',p.proxy)};
  Object.assign(f.api,{runtime:{id:'test',getURL:s=>'chrome-extension://test/'+s,onMessage:event('message'),onStartup:event('startup'),onInstalled:event('installed')},action:{setBadgeText:async()=>{},setTitle:async()=>{}},storage:{local:{get:async k=>({[k]:bag[k]}),set:async v=>Object.assign(bag,v),remove:async k=>delete bag[k]}},webRequest:{onAuthRequired:event('auth'),onCompleted:event('completed'),onErrorOccurred:event('failed')}});
  const adapter={api:f.api,platform:'firefox',get:async()=>proxy,privateAllowed:async()=>true,apply:async()=>{f.calls.push(['proxy-set']);proxy={levelOfControl:'controlled_by_this_extension',value:C.configuration('firefox',p.proxy)};},clear:async()=>{f.calls.push(['proxy-clear']);proxy={levelOfControl:'controllable_by_this_extension',value:{}};}};
  vm.runInNewContext(fs.readFileSync(require.resolve('../src/background.js'),'utf8'),{StargatePresentation:require('../src/presentation.js'),StargateAdapter:adapter,StargateCore:C,StargateStorage:require('../src/storage.js'),StargateIpfs:require('../src/ipfs.js'),StargateObservations:require('../src/observations.js'),StargateDNS:require('../src/dns.js'),StargateWebRTC:require('../src/webrtc.js'),URL,AbortSignal,fetch:async()=>({ok:true,json:async()=>({profileId:p.profileId,proxyHost:'127.0.0.1',proxyPort:8881,status:{observedAt:new Date().toISOString()}})})});
  return {...f,handlers,bag,adapter,setProxy:value=>proxy=value,send:m=>new Promise(resolve=>handlers.message(m,{id:'test',url:'chrome-extension://test/ui.html'},resolve))};
}

test('background verifies DNS before proxy write, reports missing restriction and keeps residual restriction after failure',async()=>{
 const f=background();assert.equal((await f.send({action:'apply'})).ok,true);
 assert.ok(f.calls.findIndex(x=>x[0]==='dns-set')<f.calls.findIndex(x=>x[0]==='proxy-set'));
 f.states.dns.value=true;assert.equal((await f.send({action:'status'})).status.browser,'DNS_NOT_APPLIED');
 f.states.dns.levelOfControl='controlled_by_other_extensions';const count=f.calls.filter(x=>x[0]==='proxy-set').length;
 assert.equal((await f.send({action:'apply'})).ok,false);assert.equal(f.calls.filter(x=>x[0]==='proxy-set').length,count);
 f.states.dns.levelOfControl='controllable_by_this_extension';f.adapter.apply=async()=>{throw Error('fixture proxy failure');};f.setProxy({value:{},levelOfControl:'controllable_by_this_extension'});
 const answer=await f.send({action:'apply'});assert.equal(answer.ok,false);assert.equal(answer.status.dns.state,'APPLIED');assert.notEqual(answer.status.browser,'APPLIED');
 await f.send({action:'release'});assert.equal(f.states.dns.value,true);
});
test('startup/update independently repair both privacy controls with matching proxy even when one conflicts',async()=>{
 for(const event of ['startup','installed'])for(const conflicted of ['dns','rtc']){
  const f=background();f.states[conflicted].levelOfControl='controlled_by_other_extensions';f.handlers[event]({reason:'update'});await new Promise(r=>setImmediate(r));
  const other=conflicted==='dns'?'rtc':'dns';assert.equal(f.states[other].levelOfControl,'controlled_by_this_extension');assert.equal(f.states[conflicted].levelOfControl,'controlled_by_other_extensions');assert.ok(!f.calls.some(x=>x[0]==='proxy-set'));
 }
});
test('Release attempts both owned clears after either failure and does not reapply on startup',async()=>{
 for(const failure of ['networkPredictionEnabled','webRTCIPHandlingPolicy']){
  const f=background();await f.send({action:'apply'});f.api.privacy.network[failure].clear=async()=>{throw Error('fixture clear failure');};
  assert.equal((await f.send({action:'release'})).ok,false);assert.equal(f.bag.pairing.desired,false);
  assert.equal(f.states[failure==='networkPredictionEnabled'?'rtc':'dns'].levelOfControl,'controllable_by_this_extension');
  const count=f.calls.length;f.handlers.startup();await new Promise(r=>setImmediate(r));assert.equal(f.calls.length,count);
 }
});
test('Forget retains DNS restriction and Release after Forget restores the prior setting',async()=>{
 const f=background();await f.send({action:'apply'});await f.send({action:'forget'});assert.equal(f.states.dns.value,false);assert.equal(f.bag.pairing,undefined);
 assert.equal((await f.send({action:'release'})).ok,true);assert.equal(f.states.dns.value,true);
});

test('Release cannot succeed while startup has a delayed DNS write, and succeeds on retry',async()=>{
 const f=background(),setting=f.api.privacy.network.networkPredictionEnabled,original=setting.set;let resume,entered;
 const started=new Promise(r=>entered=r);setting.set=async v=>{entered();await new Promise(r=>resume=r);await original(v);};
 f.handlers.startup();await started;
 const busy=await f.send({action:'release'});assert.equal(busy.ok,false);assert.equal(busy.code,'OPERATION_IN_PROGRESS');
 resume();await new Promise(r=>setImmediate(r));assert.equal((await f.send({action:'release'})).ok,true);
 assert.equal(f.bag.pairing.desired,false);assert.equal(f.states.dns.value,true);
});
test('update arriving during user mutation is replayed once against current desired state',async()=>{
 for(const action of ['release','ipfs-gateway']){
  const f=background();await f.send({action:'apply'});let resume,entered;const started=new Promise(r=>entered=r);
  if(action==='release'){const original=f.adapter.clear;f.adapter.clear=async()=>{entered();await new Promise(r=>resume=r);await original();};}
  else{const original=f.api.storage.local.set;f.api.storage.local.set=async v=>{if('ipfsGateway' in v){entered();await new Promise(r=>resume=r);}await original(v);};f.states.dns.value=true;}
  const response=f.send({action,gateway:'https://ipfs.io'});await started;f.handlers.installed({reason:'update'});resume();assert.equal((await response).ok,true);await new Promise(r=>setImmediate(r));
  assert.equal(f.states.dns.value,action==='release');assert.equal(f.bag.pairing.desired,action!=='release');
 }
});
