// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const C=require('../src/core.js');
const previous={version:1,managerOrigin:'http://127.0.0.1:9080',profileId:'old-device',username:'old-device',password:'test-only-existing-device-credential',authorization:'StargateProfile old-device:'+'a'.repeat(43),proxy:{host:'127.0.0.1',port:8881},desired:true,localNetwork:true};
const next={...previous,profileId:'new-device',username:'new-device',password:'test-only-new-device-credential-value',authorization:'StargateProfile new-device:'+'b'.repeat(43),proxy:{host:'127.0.0.1',port:8882},localNetwork:false};
const code='c'.repeat(43),pair={action:'pair',managerOrigin:previous.managerOrigin,code};
const reply=(p=next)=>({credentials:{profileId:p.profileId,username:p.username,password:p.password,authorization:p.authorization},proxyHost:p.proxy.host,proxyPort:p.proxy.port});
const response=(value,status=200)=>({status,ok:status>=200&&status<300,json:async()=>structuredClone(value)});
function background(redeem,{paired=true,statusResponse=null}={}){
  const handlers={},event=name=>({addListener:fn=>handlers[name]=fn});
  const bag=paired?{pairing:structuredClone(previous)}:{},calls={requests:[],writes:[],apply:[],privacy:[]};
  let setting={levelOfControl:paired?'controlled_by_this_extension':'controllable_by_this_extension',value:paired?C.configuration('brave',previous.proxy,true):{}};
  const api={runtime:{id:'test',getURL:s=>'chrome-extension://test/'+s,onMessage:event('message'),onStartup:event('startup'),onInstalled:event('installed')},action:{setBadgeText:async()=>{},setTitle:async()=>{}},storage:{local:{get:async k=>({[k]:structuredClone(bag[k])}),set:async value=>{calls.writes.push(structuredClone(value));Object.assign(bag,structuredClone(value));},remove:async k=>delete bag[k]}},webRequest:{onAuthRequired:event('auth'),onCompleted:event('completed'),onErrorOccurred:event('failed')},tabs:{get:async()=>({incognito:false})}};
  const adapter={api,platform:'brave',get:async()=>structuredClone(setting),privateAllowed:async()=>true,clear:async()=>{setting={levelOfControl:'controllable_by_this_extension',value:{}};},apply:async(proxy,enabled)=>{calls.apply.push({proxy,enabled});setting={levelOfControl:'controlled_by_this_extension',value:C.configuration('brave',proxy,enabled)};}};
  let privacyOwned=paired;
  const privacy={status:async()=>({state:privacyOwned?'APPLIED':'NOT_APPLIED',levelOfControl:privacyOwned?'controlled_by_this_extension':'controllable_by_this_extension'}),apply:async()=>{calls.privacy.push('apply');privacyOwned=true;},release:async()=>{privacyOwned=false;}};
  const fetch=async(url,options)=>{
    calls.requests.push({url,...options});
    if(url.endsWith('/api/pairing/redeem'))return redeem(options);
    assert.ok(url.endsWith('/api/extension/status'));
    if(statusResponse)return statusResponse;
    const p=options.headers.Authorization===next.authorization?next:previous;
    return response({profileId:p.profileId,proxyHost:p.proxy.host,proxyPort:p.proxy.port,status:{observedAt:'2026-10-28T00:00:00Z'}});
  };
  vm.runInNewContext(fs.readFileSync(require.resolve('../src/background.js'),'utf8'),{StargatePresentation:require('../src/presentation.js'),StargateAdapter:adapter,StargateCore:C,StargateStorage:require('../src/storage.js'),StargateIpfs:require('../src/ipfs.js'),StargateObservations:require('../src/observations.js'),StargateDNS:privacy,StargateWebRTC:privacy,URL,AbortSignal,fetch});
  return {bag,calls,api,adapter,privacy,getSetting:()=>structuredClone(setting),redemptions:()=>calls.requests.filter(r=>r.url.endsWith('/api/pairing/redeem')),send:message=>new Promise(resolve=>handlers.message(message,{id:'test',url:'chrome-extension://test/ui.html'},resolve))};
}
function unchanged(f,saved,setting){
  assert.deepEqual(f.bag,saved);assert.deepEqual(f.getSetting(),setting);
  assert.deepEqual(f.calls.writes,[]);assert.deepEqual(f.calls.apply,[]);assert.deepEqual(f.calls.privacy,[]);
  assert.equal(f.redemptions().length,1);
}
test('server accepts and consumes code before transport loss: result unknown, no retry, saved pairing/settings retained',async()=>{
  for(const paired of [false,true])for(const loss of ['fetch','body']){
    const server={pending:true,devices:0};
    const f=background(async options=>{
      assert.equal(options.method,'POST');assert.equal(JSON.parse(options.body).code,code);
      assert.equal(server.pending,true,'a second redemption would reuse a consumed code');
      server.pending=false;server.devices++;
      if(loss==='fetch')throw Error('synthetic response lost after commit');
      return {status:200,ok:true,json:async()=>{throw Error('synthetic body lost after commit');}};
    },{paired});
    const saved=structuredClone(f.bag),setting=f.getSetting();
    const answer=await f.send(pair);
    assert.equal(answer.ok,false);assert.equal(answer.code,'PAIRING_OUTCOME_UNKNOWN');
    assert.equal(answer.status.paired,paired);assert.equal(server.devices,1);assert.equal(server.pending,false);
    unchanged(f,saved,setting);
    await f.send({action:'status'});unchanged(f,saved,setting);
  }
});
test('malformed redemption JSON, error payloads, credentials and endpoints leave outcome unknown without writes',async()=>{
  const malformed=[null,[],42,{}, {...reply(),credentials:{}},{...reply(),proxyPort:0}];
  for(const value of malformed)for(const status of [200,400]){
    const f=background(async()=>response(value,status)),saved=structuredClone(f.bag),setting=f.getSetting();
    assert.equal((await f.send(pair)).code,'PAIRING_OUTCOME_UNKNOWN');unchanged(f,saved,setting);
  }
  const f=background(async()=>({status:200,ok:true,json:async()=>{throw SyntaxError('synthetic invalid JSON');}})),saved=structuredClone(f.bag),setting=f.getSetting();
  assert.equal((await f.send(pair)).code,'PAIRING_OUTCOME_UNKNOWN');unchanged(f,saved,setting);
});
test('definitive invalid/expired/used-code 403 stays a rejection and does not alter pairing/settings',async()=>{
  const f=background(async()=>response({code:'INVALID_OR_EXPIRED_PAIRING_CODE'},403)),saved=structuredClone(f.bag),setting=f.getSetting();
  const answer=await f.send(pair);
  assert.equal(answer.ok,false);assert.equal(answer.code,'INVALID_OR_EXPIRED_PAIRING_CODE');unchanged(f,saved,setting);
});
test('other valid manager rejections retain their codes and never retry redemption',async()=>{
  for(const [code,status] of [['PAIRING_REJECTED',401],['DEVICE_STORE_FULL',409]]){
    const f=background(async()=>response({code},status)),saved=structuredClone(f.bag),setting=f.getSetting();
    assert.equal((await f.send(pair)).code,code);unchanged(f,saved,setting);
  }
});
test('persisted device followed by structured server error leaves outcome unknown with no retry or settings changes',async()=>{
  // DeviceCredentials.write can complete Files.move before directory.force fails;
  // ManagerResource then returns 503 DEVICE_STORE_UNAVAILABLE after code removal.
  for(const paired of [false,true])for(const [status,code] of [[500,'INTERNAL_SERVER_ERROR'],[502,'BAD_GATEWAY'],[503,'DEVICE_STORE_UNAVAILABLE'],[504,'GATEWAY_TIMEOUT'],[599,'INVALID_OR_EXPIRED_PAIRING_CODE']]){
    const server={pending:true,devices:[]};
    const f=background(async()=>{
      assert.equal(server.pending,true,'a second redemption would reuse a consumed code');
      server.pending=false;server.devices.push(next.profileId);
      return response({code},status);
    },{paired}),saved=structuredClone(f.bag),setting=f.getSetting();
    const answer=await f.send(pair);
    assert.equal(answer.ok,false);assert.equal(answer.code,'PAIRING_OUTCOME_UNKNOWN');assert.equal(answer.status.paired,paired);
    assert.deepEqual(server.devices,[next.profileId]);assert.equal(server.pending,false);
    unchanged(f,saved,setting);await f.send({action:'status'});unchanged(f,saved,setting);
  }
});
test('manager status and Apply retain their existing structured server-error semantics',async()=>{
  const f=background(async()=>response(reply()),{statusResponse:response({code:'DEVICE_STORE_UNAVAILABLE'},503)}),saved=structuredClone(f.bag),setting=f.getSetting();
  assert.equal((await f.send({action:'status'})).status.managerError,'DEVICE_STORE_UNAVAILABLE');
  const answer=await f.send({action:'apply'});
  assert.equal(answer.ok,false);assert.equal(answer.code,'DEVICE_STORE_UNAVAILABLE');
  assert.deepEqual(f.bag,saved);assert.deepEqual(f.getSetting(),setting);
  assert.deepEqual(f.calls.writes,[]);assert.deepEqual(f.calls.apply,[]);assert.deepEqual(f.calls.privacy,[]);assert.equal(f.redemptions().length,0);
});
test('local save failure after valid redemption is separate from an unknown manager outcome',async()=>{
  for(const committed of [false,true]){
    const f=background(async()=>response(reply())),setting=f.getSetting(),save=f.api.storage.local.set;
    f.api.storage.local.set=async value=>{if(committed)await save(value);throw Error('SYNTHETIC_LOCAL_SAVE_FAILED');};
    const answer=await f.send(pair);
    assert.equal(answer.ok,false);assert.equal(answer.code,'SYNTHETIC_LOCAL_SAVE_FAILED');
    assert.equal(f.bag.pairing.profileId,committed?next.profileId:previous.profileId);
    assert.deepEqual(f.getSetting(),setting);assert.deepEqual(f.calls.apply,[]);assert.deepEqual(f.calls.privacy,[]);assert.equal(f.redemptions().length,1);
  }
});
test('post-save apply failure retains the new pairing and local-network choice for explicit Apply recovery',async()=>{
  const f=background(async()=>response(reply())),setting=f.getSetting(),apply=f.adapter.apply;
  f.adapter.apply=async()=>{throw Error('SYNTHETIC_PROXY_APPLY_FAILED');};
  const answer=await f.send(pair);
  assert.equal(answer.ok,false);assert.equal(answer.code,'SYNTHETIC_PROXY_APPLY_FAILED');
  assert.equal(answer.status.paired,true);assert.equal(f.bag.pairing.profileId,next.profileId);assert.equal(f.bag.pairing.localNetwork,true);
  assert.deepEqual(f.getSetting(),setting);assert.equal(f.redemptions().length,1);
  f.adapter.apply=apply;
  assert.equal((await f.send({action:'apply'})).ok,true);assert.equal(f.redemptions().length,1);
  assert.equal(C.matches('brave',f.getSetting(),next.proxy,true),true);
});
test('successful redemption still saves and applies the new device while retaining the local-network choice',async()=>{
  const f=background(async()=>response(reply())),answer=await f.send(pair);
  assert.equal(answer.ok,true);assert.equal(answer.status.browser,'APPLIED');assert.equal(f.bag.pairing.profileId,next.profileId);assert.equal(f.bag.pairing.localNetwork,true);
  assert.equal(C.matches('brave',f.getSetting(),next.proxy,true),true);assert.equal(f.redemptions().length,1);
});
test('local status and appearance preferences never call the manager or mutate proxy, pairing or privacy settings',async()=>{
  const f=background(async()=>response(reply())),saved=structuredClone(f.bag.pairing),setting=f.getSetting();
  const local=await f.send({action:'status-local'});assert.equal(local.status.managerPending,true);assert.equal(f.calls.requests.length,0);
  const answer=await f.send({action:'appearance',value:{theme:'stargate',motion:'reduce',advanced:true,password:'ignored'}});
  assert.equal(answer.ok,true);assert.deepEqual(f.bag.appearance,{theme:'stargate',motion:'reduce',advanced:true});assert.deepEqual(f.bag.pairing,saved);assert.deepEqual(f.getSetting(),setting);assert.deepEqual(f.calls.apply,[]);assert.deepEqual(f.calls.privacy,[]);assert.equal(f.calls.requests.length,0);
});
test('disconnect-and-forget retains credentials after failed or unconfirmed release and forgets only after confirmation',async()=>{
  for(const failure of ['proxy','privacy','readback','privacy-unavailable','proxy-unavailable']){
    const f=background(async()=>response(reply())),clear=f.adapter.clear,release=f.privacy.release,get=f.adapter.get,status=f.privacy.status;
    if(failure==='proxy')f.adapter.clear=async()=>{throw Error('SYNTHETIC_CLEAR_FAILED');};
    if(failure==='privacy')f.privacy.release=async()=>{throw Error('SYNTHETIC_PRIVACY_CLEAR_FAILED');};
    if(failure==='readback')f.adapter.clear=async()=>{};
    if(failure==='privacy-unavailable')f.privacy.status=async()=>({state:'UNAVAILABLE'});
    if(failure==='proxy-unavailable')f.adapter.clear=async()=>{await clear();f.adapter.get=async()=>{throw Error('SYNTHETIC_READBACK_UNAVAILABLE');};};
    const answer=await f.send({action:'disconnect-forget'});assert.equal(answer.ok,false);assert.equal(f.bag.pairing.profileId,previous.profileId);
    if(failure==='readback')assert.equal(answer.code,'SETTINGS_RELEASE_NOT_CONFIRMED');
    f.adapter.clear=clear;f.privacy.release=release;f.adapter.get=get;f.privacy.status=status;
    const retried=await f.send({action:'disconnect-forget'});assert.equal(retried.ok,true);assert.equal(f.bag.pairing,undefined);assert.notEqual(f.getSetting().levelOfControl,'controlled_by_this_extension');assert.equal(f.redemptions().length,0);
  }
});
test('release removes owned overrides despite corrupt saved credentials without deleting their bytes',async()=>{
  const f=background(async()=>response(reply()));f.bag.pairing.password=99;
  const corrupt=structuredClone(f.bag.pairing);let owned=true,clears=0;
  f.privacy.status=async()=>({state:owned?'APPLIED':'NOT_APPLIED',levelOfControl:owned?'controlled_by_this_extension':'controllable_by_this_extension'});
  f.privacy.release=async()=>{owned=false;clears++;};
  assert.equal((await f.send({action:'status-local'})).status.browser,'SETTINGS_REMAIN');
  const answer=await f.send({action:'release'});assert.equal(answer.ok,true);assert.ok(clears>0);assert.notEqual(f.getSetting().levelOfControl,'controlled_by_this_extension');assert.deepEqual(f.bag.pairing,corrupt);
});
