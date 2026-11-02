// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const I=require('../src/ipfs.js'),C=require('../src/core.js'),S=require('../src/storage.js');
const cid='bafybeifx7yeb55armcsxwwitkymga5xf53dxiarykms3ygqic223w5sk3m',v0='Qmaisz6NMhDB51cCvNWa1GMS7LU1pAxdF4Ld6Ft9kZEP2a',gateway='https://ipfs.dget.top';
test('published IPFS checker CID normalizes case-sensitive CIDv0 to canonical CIDv1',()=>{
  assert.equal(I.cid(v0),cid);assert.equal(I.cid(cid),cid);
  assert.throws(()=>I.cid(v0.toLowerCase()));
  assert.equal(I.url('ipfs://'+v0+'/nested/file.txt?download=true#part',gateway),'https://'+cid+'.ipfs.dget.top/nested/file.txt?download=true#part');
});
test('malformed, unsupported and noncanonical CID encodings are rejected',()=>{
  for(const bad of ['',cid.toUpperCase(),cid+'a',cid.slice(0,-1)+'n','bafz'+cid.slice(4),'bafkrei'+cid.slice(6,-1),v0+'1','k51qzi5uqu5dgutdk6i1ynyzgkqngpha5xpgia3a5qqp4jsh0u4csozksxel2r'])assert.throws(()=>I.cid(bad),bad);
  const raw='bafkreifx3g6bkkwl7b4v43lvcqfo5vshbiehuvmpky2zayhfpg5qj7y3ca';assert.equal(I.cid(raw),raw);
});
test('gateway config cannot choose another network, local bypass or credential-bearing URL',()=>{
  for(const bad of ['http://ipfs.dget.top','https://user:secret@ipfs.dget.top','https://ipfs.dget.top/path','https://ipfs.dget.top/?q=x','https://ipfs.dget.top/#x','https://127.0.0.1','https://[::1]','https://0x7f000001','https://localhost','https://ipfs.localhost','https://ipfs.local','https://ipfs.internal','https://ipfs.home.arpa','https://ipfs.onion','https://ipfs.i2p','https://ipfs.invalid','https://ipfs.test','https://ipfs.example','https://ipfs.dget.top.','https://ipfs.dget.top:0','https://ipfs.dget.top\\evil','https://ipfs.\ndget.top','https://'+'a'.repeat(64)+'.org','https://'+('a'.repeat(60)+'.').repeat(3)+'a'.repeat(11)])assert.throws(()=>I.gateway(bad),bad);
  assert.equal(I.gateway('https://IPFS.DGET.TOP/'),gateway);
  assert.equal(I.url(cid,'https://ipfs.example.org:8443'),'https://'+cid+'.ipfs.example.org:8443/');
});
test('paths, encodings and fragments cannot replace the CID authority',()=>{
  for(const value of ['https://ipfs.dget.top/a/..','\x01https://ipfs.dget.top','https://@ipfs.dget.top','https://ipfs.dget.top/\x00'])assert.throws(()=>I.gateway(value));
  for(const path of ['//evil.org/path','/%2f%2fevil.org/','/%5cevil.org/','/%2e%2e/other','/?next=https://evil.org','#https://evil.org']) {
    const u=new URL(I.url('ipfs://'+cid+path,gateway));assert.equal(u.origin,'https://'+cid+'.ipfs.dget.top');
  }
  for(const input of ['https://evil.org/'+cid,'ipns://'+cid,'ipfs://user@'+cid,'ipfs://'+cid+':443/','ipfs://'+cid+'/bad\\path','ipfs://'+cid+'/%zz','ipfs://'+cid+'/a\nb'])assert.throws(()=>I.url(input,gateway));
});

function harness() {
  const pairing={version:1,managerOrigin:'http://127.0.0.1:47179',profileId:'firefox',username:'firefox',password:'test-proxy-token-for-ipfs-not-a-real-secret',authorization:'StargateProfile firefox:'+'a'.repeat(43),proxy:{host:'127.0.0.1',port:42299},desired:true};
  let listener,bag={pairing},opened=[],sets=0,reads=0,setting={levelOfControl:'controlled_by_this_extension',value:C.configuration('brave',pairing.proxy)};
  let response={profileId:'firefox',proxyHost:'127.0.0.1',proxyPort:42299,status:{observedAt:new Date().toISOString(),nym:{readiness:'UNKNOWN'}}},unavailable=false;
  const add={addListener(){}},api={runtime:{id:'test',getURL:p=>'chrome-extension://test/'+p,onMessage:{addListener:f=>listener=f},onStartup:add,onInstalled:add},action:{setBadgeText:async()=>{},setTitle:async()=>{}},storage:{local:{get:async k=>k?{[k]:bag[k]}:bag,set:async v=>Object.assign(bag,v),remove:async k=>delete bag[k]}},tabs:{create:async v=>opened.push(v)},webRequest:{onAuthRequired:add,onCompleted:add,onErrorOccurred:add}};
  api.privacy={network:{webRTCIPHandlingPolicy:{get:async()=>({value:'disable_non_proxied_udp',levelOfControl:'controlled_by_this_extension'})}}};
  const adapter={api,platform:'brave',get:async()=>{reads++;return setting;},privateAllowed:async()=>false,apply:async()=>{sets++;}};
  const context={StargatePresentation:require('../src/presentation.js'),StargateAdapter:adapter,StargateCore:C,StargateDNS:require('../src/dns.js'),StargateWebRTC:require('../src/webrtc.js'),StargateStorage:S,StargateIpfs:I,StargateObservations:require('../src/observations.js'),URL,AbortSignal,console,fetch:async()=>{if(unavailable)throw Error('offline');return {ok:true,json:async()=>response};}};
  vm.runInNewContext(fs.readFileSync(require.resolve('../src/background.js'),'utf8'),context);
  return {send:m=>new Promise(resolve=>listener(m,{id:'test',url:'chrome-extension://test/ui.html'},resolve)),opened,bag,pairing,
    setSetting:v=>setting=v,setResponse:v=>response=v,unavailable:()=>unavailable=true,counts:()=>({sets,reads}),response};
}
test('opening and protocol resolution require fresh owned settings, matching endpoint, manager and enabled Nym',async()=>{
  for(const action of ['ipfs-open','ipfs-resolve'])for(const scenario of ['released','conflict','changed','endpoint','disabled','manager','unpaired']) {
    const h=harness();
    if(scenario==='released')h.setSetting({levelOfControl:'controllable_by_this_extension',value:{}});
    if(scenario==='conflict')h.setSetting({levelOfControl:'controlled_by_other_extensions',value:C.configuration('brave',h.pairing.proxy)});
    if(scenario==='changed')h.setSetting({levelOfControl:'controlled_by_this_extension',value:{}});
    if(scenario==='endpoint')h.setResponse({...h.response,proxyPort:42298});
    if(scenario==='disabled')h.setResponse({...h.response,status:{...h.response.status,nym:{readiness:'DISABLED'}}});
    if(scenario==='manager')h.unavailable();
    if(scenario==='unpaired')delete h.bag.pairing;
    const r=await h.send({action,address:cid});assert.equal(r.ok,false,action+':'+scenario);assert.equal(r.url,undefined);assert.equal(h.opened.length,0,scenario);assert.equal(h.counts().sets,0,scenario);
  }
});
test('protocol resolution uses the saved gateway without opening a tab, changing settings or storing the URI',async()=>{
  const h=harness();await h.send({action:'ipfs-gateway',gateway:'https://ipfs.storry.tv'});
  const r=await h.send({action:'ipfs-resolve',address:'ipfs://'+v0+'/nested/file?x=%2F#part'});
  assert.equal(r.ok,true);assert.equal(r.url,'https://'+cid+'.ipfs.storry.tv/nested/file?x=%2F#part');
  assert.equal(h.opened.length,0);assert.equal(h.counts().sets,0);assert.equal(JSON.stringify(h.bag).includes(v0),false);
});
test('browser protocol input is decoded once, bounded and limited to IPFS while retaining CID case',()=>{
  const uri='IPFS://'+v0+'/file?x=%2F#part',decoded=I.protocolAddress('#'+encodeURIComponent(uri));
  assert.equal(decoded,'ipfs://'+v0+'/file?x=%2F#part');assert.equal(I.url(decoded,gateway),'https://'+cid+'.ipfs.dget.top/file?x=%2F#part');
  for(const bad of ['', '#', '#%zz', '#'+encodeURIComponent('https://evil.org/'), '#'+encodeURIComponent('ipns://'+cid), '#'+encodeURIComponent(encodeURIComponent('ipfs://'+cid)), '#'+encodeURIComponent('ipfs://'+cid+'/'+ 'a'.repeat(4096)), '#'+ 'a'.repeat(12289)])assert.throws(()=>I.protocolAddress(bad));
});
test('successful open stores only chosen gateway and never the CID or navigation URL',async()=>{
  const h=harness();assert.equal((await h.send({action:'ipfs-gateway',gateway:'https://ipfs.storry.tv/'})).ok,true);
  assert.equal((await h.send({action:'ipfs-open',address:'ipfs://'+v0+'/file?x=1'})).ok,true);
  assert.equal(h.opened.length,1);assert.equal(h.opened[0].url,'https://'+cid+'.ipfs.storry.tv/file?x=1');
  assert.equal(h.bag.ipfsGateway,'https://ipfs.storry.tv');assert.equal(JSON.stringify(h.bag).includes(cid),false);assert.equal(JSON.stringify(h.bag).includes(v0),false);
  assert.equal(h.counts().sets,0);assert.ok(h.counts().reads>=3);
  assert.equal((await h.send({action:'ipfs-gateway',gateway:'https://x.onion'})).ok,false);assert.equal(h.bag.ipfsGateway,'https://ipfs.storry.tv');
});
