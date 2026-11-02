// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
const {test}=require('node:test'),assert=require('node:assert/strict');
const O=require('../src/observations.js');
const tick=()=>new Promise(r=>setImmediate(r)),at='2026-10-25T12:00:00.000Z';
function event(network,statusCode=200,extra={}){return {incognito:false,url:'https://private-fixture.'+({TOR:'onion',I2P:'i2p',WEB:'org'}[network])+'/secret?token=never-store',statusCode,...extra};}
test('request summaries distinguish HTTP errors, cache and transport; exclude cancellations, private and local traffic',()=>{
  assert.equal(O.observation(event('WEB',503),false,at).slot,'failure');
  assert.equal(O.observation(event('WEB',200,{url:'http://EXAMPLE.ONION./'}),false,at).network,'TOR');
  const cache=O.observation(event('WEB',503,{fromCache:true}),false,at);assert.equal(cache.slot,'cached');assert.match(O.describe(cache.value),/Cached HTTP 503.*no fresh connection/);
  const failure=O.observation(event('TOR',0,{error:'unknown-secret.example'}),true,at);assert.equal(failure.value.code,'request');assert.equal(JSON.stringify(failure).includes('secret'),false);
  for(const error of ['NS_BINDING_ABORTED','net::ERR_ABORTED'])assert.equal(O.observation(event('WEB',0,{error}),true,at),null);
  for(const incognito of [true,undefined,null])assert.equal(O.observation(event('I2P',200,{incognito}),false,at),null);
  for(const url of ['http://127.0.0.1/a','http://localhost/a','http://[::1]/a'])assert.equal(O.observation({url,statusCode:200},false,at),null);
});
test('bursts coalesce writes without losing other networks or failures and remain bounded',async()=>{
  let releaseLoad,releaseWrite,writes=0,bag={},blocked=true;
  const area={get:()=>new Promise(r=>releaseLoad=()=>r({})),set:async v=>{writes++;bag=structuredClone(v);if(blocked){blocked=false;await new Promise(r=>releaseWrite=r);}}};
  const s=O.store(area);s.record(O.observation(event('TOR',503),false,at));
  for(let i=0;i<1000;i++)s.record(O.observation(event('WEB'),false,at));
  releaseLoad();await tick();s.record(O.observation(event('I2P'),false,at));
  for(let i=0;i<1000;i++)s.record(O.observation(event('WEB',200,{fromCache:true}),false,at));
  releaseWrite();await tick();await tick();
  assert.ok(writes<=2);assert.equal(bag.browserObservations.TOR.failure.status,503);assert.equal(bag.browserObservations.I2P.response.status,200);assert.equal(bag.browserObservations.WEB.cached.kind,'cached');
  assert.equal(JSON.stringify(bag).includes('private-fixture'),false);assert.equal(JSON.stringify(bag).includes('token'),false);assert.ok(JSON.stringify(bag).length<1500);
  const restored=O.store({get:async()=>bag,set:async()=>{}});assert.deepEqual(await restored.read(),await s.read());assert.deepEqual(await O.store().read(),{});
});
test('cached success and unrelated successes cannot erase a real failure or fresh response history',async()=>{
  const s=O.store();s.record(O.observation(event('WEB'),false,at));s.record(O.observation(event('WEB',0,{error:'net::ERR_TUNNEL_CONNECTION_FAILED'}),true,at));s.record(O.observation(event('WEB',200,{fromCache:true}),false,at));s.record(O.observation(event('TOR'),false,at));
  const r=await s.read();assert.equal(r.WEB.failure.code,'proxy');assert.equal(r.WEB.response.status,200);assert.equal(r.WEB.cached.status,200);assert.ok(r.TOR.response);
});
test('network labels keep listener, readiness and historical access distinct',()=>{
  const text=O.networkState({readiness:'UNKNOWN',socks:{state:'RESPONDING'},destinationAccess:'OBSERVED_THIS_PROCESS'});
  assert.match(text,/Listener responding/);assert.match(text,/readiness unknown/);assert.match(text,/earlier.*not a current/);assert.doesNotMatch(text,/OBSERVED_THIS_PROCESS/);
  assert.match(O.networkState({readiness:'READY',destinationAccess:'NOT_OBSERVED_THIS_PROCESS'}),/No destination traffic/);
  assert.match(O.networkState({readiness:'UNAVAILABLE',socks:{state:'UNAVAILABLE'}}),/Listener check unavailable/);
  assert.match(O.networkState({readiness:'UNAVAILABLE',socks:{state:'UNEXPECTED'}}),/unexpected response/);
  assert.match(O.networkState({readiness:'UNAVAILABLE',socks:{state:'REFUSED'}}),/not listening/);assert.match(O.networkState(null),/No current/);assert.match(O.networkState({readiness:'DISABLED'}),/Not enabled/);
});
test('guidance uses observed setup facts and existing actions without guessing destination failures',()=>{
  const s={paired:true,browser:'APPLIED',manager:{process:{observation:'OBSERVED',activeState:'active'},proxy:{state:'RESPONDING'},nym:{readiness:'UNKNOWN'}}};
  assert.equal(O.guidance(s).action,undefined);
  assert.equal(O.guidance({...s,browser:'PROXY_CHANGED'}).action,'apply');assert.equal(O.guidance({...s,browser:'PROXY_CONFLICT'}).action,undefined);
  assert.match(O.guidance({...s,manager:null}).text,/does not prove.*down/);
  assert.equal(O.guidance({...s,managerError:'PAIRING_REJECTED'}).action,'pair');assert.equal(O.guidance({...s,paired:false}).action,'pair');
  assert.match(O.guidance({...s,manager:{...s.manager,process:{observation:'OBSERVED',activeState:'inactive'}}}).text,/not active/);
  assert.equal(O.guidance({...s,manager:{...s.manager,nym:{readiness:'UNAVAILABLE'}}}).action,'manager');
});

test('Chromium tab privacy is resolved without assuming missing context is regular',async()=>{
  let reads=0;const api={tabs:{get:async id=>{reads++;if(id===3)throw Error('closed');return {incognito:id===2};}}};
  assert.equal(await O.privateContext({incognito:false},api),false);assert.equal(reads,0);
  assert.equal(await O.privateContext({tabId:1},api),false);assert.equal(await O.privateContext({tabId:2},api),true);
  assert.equal(await O.privateContext({tabId:3},api),undefined);assert.equal(await O.privateContext({tabId:-1},api),undefined);assert.equal(reads,3);
});
test('real background listener resolves Brave privacy for both summaries and proxy credentials',async()=>{
  const fs=require('node:fs'),vm=require('node:vm'),C=require('../src/core.js');
  const pairing={version:1,managerOrigin:'http://127.0.0.1:47179',profileId:'brave',username:'brave',password:'test-status-proxy-token-not-a-real-secret',authorization:'StargateProfile brave:'+'a'.repeat(43),proxy:{host:'127.0.0.1',port:42299},desired:true};
  const handlers={},bag={},add={addListener(){}};
  const api={runtime:{id:'test',getURL:p=>'chrome-extension://test/'+p,onMessage:add,onStartup:add,onInstalled:add},action:{setBadgeText:async()=>{},setTitle:async()=>{}},storage:{local:{get:async()=>({pairing})},session:{get:async k=>({[k]:bag[k]}),set:async v=>Object.assign(bag,structuredClone(v)),remove:async k=>delete bag[k]}},tabs:{get:async id=>{if(id===3)throw Error('closed');return {incognito:id===2};}},webRequest:Object.fromEntries(['onAuthRequired','onCompleted','onErrorOccurred'].map(k=>[k,{addListener:f=>handlers[k]=f}]))};
  vm.runInNewContext(fs.readFileSync(require.resolve('../src/background.js'),'utf8'),{StargatePresentation:require('../src/presentation.js'),StargateAdapter:{api,platform:'brave'},StargateCore:C,StargateDNS:require('../src/dns.js'),StargateWebRTC:require('../src/webrtc.js'),StargateStorage:require('../src/storage.js'),StargateIpfs:require('../src/ipfs.js'),StargateObservations:O,URL,AbortSignal});
  for(const tabId of [1,2,3,-1]){
    handlers.onCompleted(event(tabId===1?'TOR':tabId===2?'I2P':'WEB',200,{incognito:undefined,tabId,requestId:'r'+tabId}));
    const answer=await new Promise(resolve=>handlers.onAuthRequired({tabId,requestId:'a'+tabId,isProxy:true,realm:'Stargate',scheme:'basic',challenger:{host:'127.0.0.1',port:42299}},resolve));
    if(tabId===1)assert.equal(answer.authCredentials.username,'brave');else assert.equal(answer.cancel,true);
  }
  await tick();await tick();assert.deepEqual(Object.keys(bag.browserObservations),['TOR']);assert.equal(bag.authObservation.provided,1);assert.equal(bag.authObservation.rejected,0);
});

test('device lifecycle advice never equates local state with network readiness or retries actions',()=>{
  assert.match(O.deviceState({state:'NOT_STARTED'}),/next I2P request/);
  assert.match(O.deviceState({state:'STARTING'}),/retry only when safe.*already have reached/);
  assert.match(O.deviceState({state:'CONNECTIONS_OPEN'}),/does not prove/);
  assert.match(O.deviceState({state:'COOLDOWN'}),/retain your identity/);
  assert.match(O.deviceState({state:'DISABLED'}),/pairing again is unnecessary/);
  for(const d of [undefined,{state:'UNAVAILABLE'},{state:'READY'}])assert.match(O.deviceState(d),/unavailable.*Do not restart/);
  for(const state of ['WAITING','STARTING','CONNECTIONS_OPEN','COOLDOWN','STOPPING','DISABLED']) {
    const s={paired:true,browser:'PROXY_CONFLICT',manager:{i2pDevice:{state}}};
    assert.match(O.guidance(s).text,/Another extension/);assert.equal(O.guidance(s).action,undefined);
  }
});

test('real remote auth callback cancels after ownership or transport changes',async()=>{
  const fs=require('node:fs'),vm=require('node:vm'),C=require('../src/core.js');
  const pairing={version:1,managerOrigin:'https://gate.example:9443',profileId:'remote',username:'remote',password:'test-remote-proxy-token-not-a-real-secret',authorization:'StargateProfile remote:'+'a'.repeat(43),proxy:{scheme:'https',host:'gate.example',port:443,managerOrigin:'https://gate.example:9443'},desired:true};
  const handlers={},bag={},add={addListener(){}};
  const api={runtime:{id:'test',getURL:p=>'chrome-extension://test/'+p,onMessage:add,onStartup:add,onInstalled:add},action:{setBadgeText:async()=>{},setTitle:async()=>{}},storage:{local:{get:async()=>({pairing})},session:{get:async k=>({[k]:bag[k]}),set:async v=>Object.assign(bag,structuredClone(v)),remove:async k=>delete bag[k]}},webRequest:Object.fromEntries(['onAuthRequired','onCompleted','onErrorOccurred'].map(k=>[k,{addListener:f=>handlers[k]=f}]))};
  let setting={levelOfControl:'controlled_by_this_extension',value:C.configuration('brave',pairing.proxy)};
  vm.runInNewContext(fs.readFileSync(require.resolve('../src/background.js'),'utf8'),{StargatePresentation:require('../src/presentation.js'),StargateAdapter:{api,platform:'brave',get:async()=>setting},StargateCore:C,StargateDNS:require('../src/dns.js'),StargateWebRTC:require('../src/webrtc.js'),StargateStorage:require('../src/storage.js'),StargateIpfs:require('../src/ipfs.js'),StargateObservations:O,URL,AbortSignal});
  const request=id=>new Promise(resolve=>handlers.onAuthRequired({incognito:false,requestId:id,isProxy:true,realm:'Stargate',scheme:'basic',challenger:{host:'gate.example',port:443}},resolve));
  assert.equal((await request('valid')).authCredentials.username,'remote');
  setting={...setting,levelOfControl:'controlled_by_other_extensions'};assert.equal((await request('other-owner')).cancel,true);
  setting={levelOfControl:'controlled_by_this_extension',value:C.configuration('brave',pairing.proxy)};setting.value.rules.singleProxy.scheme='http';assert.equal((await request('plaintext')).cancel,true);
  assert.equal(bag.authObservation.provided,1);
});
