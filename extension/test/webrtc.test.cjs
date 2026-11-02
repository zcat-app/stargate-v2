const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const R=require('../src/webrtc.js'),C=require('../src/core.js');
function fixture(platform='brave'){
  let value='default',owner='controllable_by_this_extension',ignore=false;
  const calls=[],api={privacy:{network:{webRTCIPHandlingPolicy:{
    get:async()=>({value,levelOfControl:owner}),
    set:async v=>{calls.push(['rtc-set',v.value]);if(!ignore){value=v.value;owner='controlled_by_this_extension';}},
    clear:async()=>{calls.push(['rtc-clear']);value='default';owner='controllable_by_this_extension';}
  }}}};
  return {api,calls,platform,conflict:()=>owner='controlled_by_other_extensions',policy:()=>value,ignore:()=>ignore=true};
}
test('each platform confirms its distinct policy and release clears only its own override',async()=>{
  for(const platform of ['firefox','brave']){
    const f=fixture(platform);await R.apply(f.api,platform);
    assert.equal(f.policy(),platform==='firefox'?'proxy_only':'disable_non_proxied_udp');
    assert.equal((await R.status(f.api,platform)).state,'APPLIED');
    await R.release(f.api);assert.equal(f.policy(),'default');
    await R.apply(f.api,platform);f.conflict();const count=f.calls.length;await R.release(f.api);assert.equal(f.calls.length,count);
  }
});
test('missing permission, conflicting owner and ignored writes cannot confirm RTC protection',async()=>{
  await assert.rejects(R.apply({},'brave'),/WEBRTC_UNAVAILABLE/);
  const f=fixture();f.conflict();await assert.rejects(R.apply(f.api,'brave'),/WEBRTC_CONFLICT/);assert.deepEqual(f.calls,[]);
  const ignored=fixture();ignored.ignore();await assert.rejects(R.apply(ignored.api,'brave'),/WEBRTC_NOT_CONFIRMED/);
});
function background(){
  const f=fixture(),handlers={},event=name=>({addListener:fn=>handlers[name]=fn});
  const p={version:1,managerOrigin:'http://127.0.0.1:9080',profileId:'proof',username:'proof',password:'test-only-rtc-credential-not-a-secret',authorization:'StargateProfile proof:'+'a'.repeat(43),proxy:{host:'127.0.0.1',port:8881},desired:true};
  const bag={pairing:p};let proxy={levelOfControl:'controlled_by_this_extension',value:C.configuration('brave',p.proxy)};
  Object.assign(f.api,{runtime:{id:'test',getURL:s=>'chrome-extension://test/'+s,onMessage:event('message'),onStartup:event('startup'),onInstalled:event('installed')},action:{setBadgeText:async()=>{},setTitle:async()=>{}},storage:{local:{get:async k=>({[k]:bag[k]}),set:async v=>Object.assign(bag,v),remove:async k=>delete bag[k]}},webRequest:{onAuthRequired:event('auth'),onCompleted:event('completed'),onErrorOccurred:event('failed')}});
  const adapter={api:f.api,platform:'brave',get:async()=>proxy,privateAllowed:async()=>false,apply:async()=>{f.calls.push(['proxy-set']);proxy={levelOfControl:'controlled_by_this_extension',value:C.configuration('brave',p.proxy)};},clear:async()=>{f.calls.push(['proxy-clear']);proxy={levelOfControl:'controllable_by_this_extension',value:{}};}};
  vm.runInNewContext(fs.readFileSync(require.resolve('../src/background.js'),'utf8'),{StargatePresentation:require('../src/presentation.js'),StargateAdapter:adapter,StargateCore:C,StargateStorage:require('../src/storage.js'),StargateIpfs:require('../src/ipfs.js'),StargateObservations:require('../src/observations.js'),StargateDNS:require('../src/dns.js'),StargateWebRTC:R,URL,AbortSignal,fetch:async()=>({ok:true,json:async()=>({profileId:p.profileId,proxyHost:'127.0.0.1',proxyPort:8881,status:{observedAt:new Date().toISOString()}})})});
  return {...f,handlers,bag,adapter,setProxy:value=>proxy=value,send:m=>new Promise(resolve=>handlers.message(m,{id:'test',url:'chrome-extension://test/ui.html'},resolve))};
}
test('actual background applies RTC first and refuses applied status when only the proxy matches',async()=>{
  const f=background();assert.equal((await f.send({action:'status'})).status.browser,'WEBRTC_NOT_APPLIED');
  assert.equal((await f.send({action:'apply'})).ok,true);assert.deepEqual(f.calls.map(v=>v[0]),['rtc-set','proxy-set']);
  f.conflict();const result=await f.send({action:'apply'});assert.equal(result.ok,false);assert.equal(result.code,'WEBRTC_CONFLICT');assert.equal(result.status.browser,'WEBRTC_CONFLICT');assert.equal(f.calls.length,2);
});
test('actual background repairs RTC on upgrade with matching proxy; forget keeps policy; release restores it',async()=>{
  const f=background();f.handlers.installed({reason:'update'});await new Promise(r=>setImmediate(r));
  assert.equal(f.policy(),'disable_non_proxied_udp');assert.deepEqual(f.calls.map(v=>v[0]),['rtc-set']);
  assert.equal((await f.send({action:'forget'})).ok,true);assert.equal(f.policy(),'disable_non_proxied_udp');assert.equal(f.bag.pairing,undefined);
  assert.equal((await f.send({action:'release'})).ok,true);assert.equal(f.policy(),'default');
});
test('failed RTC release does not silently restore the proxy on the next startup',async()=>{
  const f=background();await f.send({action:'apply'});
  f.api.privacy.network.webRTCIPHandlingPolicy.clear=async()=>{throw Error('controlled test clear failure');};
  const answer=await f.send({action:'release'});assert.equal(answer.ok,false);assert.equal(f.bag.pairing.desired,false);
  const count=f.calls.length;f.handlers.startup();await new Promise(r=>setImmediate(r));assert.equal(f.calls.length,count);
});
test('proxy write failure leaves separately reported RTC restriction and an explicit release path',async()=>{
  const f=background();f.setProxy({levelOfControl:'controllable_by_this_extension',value:{}});f.adapter.apply=async()=>{throw Error('controlled proxy write failure');};
  const answer=await f.send({action:'apply'});assert.equal(answer.ok,false);assert.notEqual(answer.status.browser,'APPLIED');assert.equal(answer.status.webrtc.state,'APPLIED');
  assert.equal((await f.send({action:'release'})).ok,true);assert.equal(f.policy(),'default');assert.equal(f.bag.pairing.desired,false);
});
test('startup does not take RTC ownership while another controller owns the proxy',async()=>{
  const f=background();f.setProxy({levelOfControl:'controlled_by_other_extensions',value:{}});f.handlers.startup();await new Promise(r=>setImmediate(r));
  assert.deepEqual(f.calls,[]);assert.equal((await f.send({action:'status'})).status.browser,'PROXY_CONFLICT');
});
