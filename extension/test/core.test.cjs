// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
const {test}=require('node:test');
const assert=require('node:assert/strict');
const C=require('../src/core.js'),S=require('../src/storage.js');
const p={version:1,managerOrigin:'http://127.0.0.1:9080',profileId:'browser',username:'browser',password:'synthetic-proxy-token-for-extension-tests',authorization:'StargateProfile browser:'+'a'.repeat(43),proxy:{host:'127.0.0.1',port:8881},desired:true};

test('manager URLs allow HTTPS or numeric-loopback HTTP only',()=>{
  assert.equal(C.managerOrigin('http://127.0.0.1:9080/'),'http://127.0.0.1:9080');
  for(const url of ['http://example.com','http://localhost:9080','http://127.0.0.1:9080/path','http://secret@127.0.0.1:9080','http://127.0.0.1:9080/?token=secret'])assert.throws(()=>C.managerOrigin(url));
});
test('pairing validates profile credentials and local endpoints at the boundary',()=>{
  assert.equal(C.validatePairing(p).profileId,'browser');
  for(const bad of [{...p,password:'short'},{...p,proxy:{host:'example.com',port:8881}},{...p,username:'another'},{...p,authorization:'Bearer administrator'}])assert.throws(()=>C.validatePairing(bad));
});
test('JavaScript coercion and extra grant fields cannot make malformed credentials valid',()=>{
  for(const bad of [{...p,profileId:null,username:null,authorization:'StargateProfile null:'+'a'.repeat(43)},{...p,password:[p.password]},{...p,authorization:p.authorization+':extra'},{...p,managerOrigin:[p.managerOrigin]}])assert.throws(()=>C.validatePairing(bad));
});
test('actual settings and ownership must match before reporting applied',()=>{
  for(const platform of ['firefox','brave']){
    const setting={levelOfControl:'controlled_by_this_extension',value:C.configuration(platform,p.proxy)};
    assert.equal(C.browserState(platform,setting,p,true),'APPLIED');
    assert.equal(C.browserState(platform,{...setting,levelOfControl:'controlled_by_other_extensions'},p,true),'PROXY_CONFLICT');
    assert.equal(C.browserState(platform,{...setting,value:{}},p,true),'PROXY_CHANGED');
    assert.equal(C.browserState(platform,undefined,p,undefined),'BROWSER_SETTINGS_UNAVAILABLE');
  }
});
test('unexpected bypass rules cannot retain an applied indication',()=>{
  const firefox=C.configuration('firefox',p.proxy);firefox.passthrough+=',*.onion';
  assert.equal(C.matches('firefox',{value:firefox},p.proxy),false);
  const brave=C.configuration('brave',p.proxy);brave.rules.bypassList.push('*.onion');
  assert.equal(C.matches('brave',{value:brave},p.proxy),false);
});
test('Firefox permission is required without fabricating a missing setting',()=>{
  const setting={levelOfControl:'controlled_by_this_extension',value:C.configuration('firefox',p.proxy)};
  assert.equal(C.browserState('firefox',setting,p,false),'FIREFOX_PRIVATE_PERMISSION_REQUIRED');
  assert.equal(C.browserState('firefox',setting,null,false),'UNPAIRED');
});
test('only the exact local proxy receives credentials; retries and private contexts cancel',()=>{
  const d={isProxy:true,realm:'Stargate',scheme:'basic',challenger:{host:'127.0.0.1',port:8881},incognito:false};
  assert.equal(C.authDecision(p,d,0),'credentials');
  for(const url of ['https://controlled.example.com/','http://controlled.i2p/','https://'+'b'.repeat(52)+'.b32.i2p/','http://controlled.onion/']){
    assert.equal(C.authDecision(p,{...d,url},0),'credentials');
    assert.equal(C.authDecision(p,{...d,url,isProxy:false},0),'ignore');
    assert.equal(C.authDecision(p,{...d,url,challenger:{host:'controlled.i2p',port:8881}},0),'ignore');
  }
  for(const wrong of [{...d,isProxy:false},{...d,realm:'website'},{...d,scheme:'digest'},{...d,challenger:{host:'127.0.0.1',port:8882}},{...d,challenger:{host:'attacker.invalid',port:8881}}])assert.equal(C.authDecision(p,wrong,0),'ignore');
  assert.equal(C.authDecision(p,d,1),'cancel');assert.equal(C.authDecision(p,{...d,incognito:true},0),'cancel');assert.equal(C.authDecision(null,d,0),'ignore');
});
test('storage preserves absent credentials and round trips the selected pairing',async()=>{
  let bag={};const api={storage:{local:{get:async()=>bag,set:async x=>{bag=x},remove:async()=>{bag={}}}}};
  assert.equal(await S.read(api),undefined);await S.write(api,p);assert.equal(await S.read(api),p);await S.forget(api);assert.equal(await S.read(api),undefined);
});

const remote={...p,managerOrigin:'https://gate.example:9443',proxy:{scheme:'https',host:'gate.example',port:443,managerOrigin:'https://gate.example:9443'}};
test('remote pairing rejects plaintext, wrong authority and transport downgrades',()=>{
  assert.equal(C.validatePairing(remote).proxy.scheme,'https');
  for(const bad of [{...remote,proxy:{host:'127.0.0.1',port:8881}},{...remote,proxy:{...remote.proxy,host:'attacker.example'}},{...remote,proxy:{...remote.proxy,managerOrigin:'https://gate.example:9444'}}])assert.throws(()=>C.validatePairing(bad));
  assert.throws(()=>C.fromRedeem(remote.managerOrigin,{credentials:{profileId:p.profileId,username:p.username,password:p.password,authorization:p.authorization},proxyHost:'127.0.0.1',proxyPort:8881,proxyScheme:'http'}));
});
test('remote Firefox PAC has one TLS route and only exact control-origin or loopback bypass',()=>{
  const vm=require('node:vm'),config=C.configuration('firefox',remote.proxy),context={};
  vm.runInNewContext(decodeURIComponent(config.autoConfigUrl.split(',').slice(1).join(',')),context);
  for(const url of ['http://site.onion/','http://site.i2p/','https://ordinary.example/','https://gate.example:9444/','http://gate.example:9443/','https://gate.example.attacker.example:9443/'])assert.equal(context.FindProxyForURL(url,new URL(url).hostname),'HTTPS gate.example:443');
  assert.equal(context.FindProxyForURL(remote.managerOrigin+'/api/extension/status','gate.example'),'DIRECT');
  assert.equal(C.matches('firefox',{value:config},remote.proxy),true);
  assert.equal(C.matches('firefox',{value:{...config,autoConfigUrl:config.autoConfigUrl+'invalid'}},remote.proxy),false);
});
test('Brave remote setting confirms TLS and exact HTTPS API port independent of property order',()=>{
  const proxy={...remote.proxy,managerOrigin:'https://gate.example'},config=C.configuration('brave',proxy);
  assert.deepEqual(config.rules.bypassList,['127.0.0.1','localhost','https://gate.example:443']);
  assert.equal(C.matches('brave',{value:{mode:'fixed_servers',rules:{bypassList:[...config.rules.bypassList].reverse(),singleProxy:{port:443,host:'gate.example',scheme:'https'}}}},proxy),true);
  const wrong=structuredClone(config);wrong.rules.singleProxy.scheme='http';assert.equal(C.matches('brave',{value:wrong},proxy),false);
  const bypass=structuredClone(config);bypass.rules.bypassList[2]='gate.example';assert.equal(C.matches('brave',{value:bypass},proxy),false);
});
test('remote credentials remain restricted to an exact proxy challenger',()=>{
  const d={isProxy:true,realm:'Stargate',scheme:'basic',challenger:{host:'gate.example',port:443},incognito:false};
  assert.equal(C.authDecision(remote,d,0),'credentials');
  for(const bad of [{...d,isProxy:false},{...d,challenger:{host:'gate.example.attacker.example',port:443}},{...d,challenger:{host:'gate.example',port:9443}}])assert.equal(C.authDecision(remote,bad,0),'ignore');
});

test('remote status cannot downgrade a saved HTTPS route before apply',()=>{
  for(const value of [{proxyScheme:'http',proxyHost:'127.0.0.1',proxyPort:8881},{proxyHost:'127.0.0.1',proxyPort:8881},{proxyScheme:'https',proxyHost:'attacker.example',proxyPort:443}])assert.throws(()=>C.responseEndpoint(remote.managerOrigin,value));
  assert.equal(C.responseEndpoint(remote.managerOrigin,{proxyScheme:'https',proxyHost:'gate.example',proxyPort:443}).scheme,'https');
});

test('remote auth rejects released pairing and an explicitly plaintext Firefox proxy',()=>{
  const d={isProxy:true,realm:'Stargate',scheme:'basic',challenger:{host:'gate.example',port:443},incognito:false,proxyInfo:{type:'https',host:'gate.example',port:443}};
  assert.equal(C.authDecision(remote,d,0),'credentials');
  assert.equal(C.authDecision(remote,{...d,proxyInfo:{...d.proxyInfo,type:'http'}},0),'cancel');
  assert.equal(C.authDecision({...remote,desired:false},d,0),'cancel');
});
