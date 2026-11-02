// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const C=require('../src/core.js');
const local={version:1,managerOrigin:'http://127.0.0.1:9080',profileId:'lan',username:'lan',password:'test-only-local-network-credential-value',authorization:'StargateProfile lan:'+'a'.repeat(43),proxy:{host:'127.0.0.1',port:8881},desired:true};
const remote={...local,managerOrigin:'https://gate.example:9443',proxy:{scheme:'https',host:'gate.example',port:443,managerOrigin:'https://gate.example:9443'}};
const ranges=['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'];
const direct=['10.0.0.0','10.255.255.255','172.16.0.0','172.31.255.255','192.168.0.0','192.168.255.255','::ffff:10.1.2.3','[::ffff:ac10:1]','0:0:0:0:0:ffff:c0a8:ffff','[0:0:0:0:0:FFFF:192.168.1.1]'];
const routed=['9.255.255.255','11.0.0.0','172.15.255.255','172.32.0.0','192.167.255.255','192.169.0.0','100.64.0.1','169.254.1.1','8.8.8.8','fc00::1','fe80::1','::192.168.1.1','64:ff9b::c0a8:101','2001:db8::1','::ffff:8.8.8.8','printer','printer.local','10.0.0.1.example','ordinary.example','site.onion','site.i2p'];
test('private literal boundaries include only RFC1918 IPv4 and equivalent mapped forms',()=>{
  for(const host of direct)assert.equal(C.privateLiteral(host),true,host);
  for(const host of [...routed,'10.0.0.256','010.0.0.1','10.1','[10.0.0.1]','::ffff:10.0.0.256','::fffff:a00:1','::ffff:a00:1%zone','::ffff::a00:1','::ffff:a00:1:',':::ffff:a00:1','[::ffff:a00:1',null,{},1])assert.equal(C.privateLiteral(host),false,String(host));
});
test('old pairings default off, malformed choices reject, and both manual browsers use exactly the three CIDRs',()=>{
  assert.equal(C.validatePairing(local).localNetwork,false);
  assert.equal(C.validatePairing({...local,localNetwork:true}).localNetwork,true);
  for(const value of [null,'true',1,{}])assert.throws(()=>C.validatePairing({...local,localNetwork:value}));
  for(const p of [local,remote])for(const platform of ['firefox','brave'])for(const enabled of [false,true]){
    const config=C.configuration(platform,p.proxy,enabled),setting={value:config,levelOfControl:'controlled_by_this_extension'};
    assert.equal(C.matches(platform,setting,p.proxy,enabled),true);
    assert.equal(C.matches(platform,setting,p.proxy,!enabled),false);
    const extra=structuredClone(config);if(platform==='brave')extra.rules.bypassList.push('*.onion');else extra.passthrough+=',*.onion';
    assert.equal(C.matches(platform,{value:extra},p.proxy,enabled),false);
    assert.equal(C.browserState(platform,setting,{...p,localNetwork:enabled},true),'APPLIED');
    assert.equal(C.browserState(platform,setting,{...p,localNetwork:!enabled},true),'PROXY_CHANGED');
    assert.equal(C.browserState(platform,{...setting,levelOfControl:'controlled_by_other_extensions'},{...p,localNetwork:enabled},true),'PROXY_CONFLICT');
    if(platform==='brave')assert.deepEqual(config.rules.bypassList,['127.0.0.1','localhost',...(enabled?ranges:[]),...(p===remote?['https://gate.example:9443']:[])]);
    else if(p===local){assert.equal(config.proxyType,'manual');assert.equal(config.passthrough,['127.0.0.1','localhost',...(enabled?ranges:[])].join(','));}
  }
});
test('embedded remote Firefox PAC has the same literal policy without DNS, discovery or direct fallback',()=>{
  for(const enabled of [false,true]){
    const config=C.configuration('firefox',remote.proxy,enabled),source=decodeURIComponent(config.autoConfigUrl.split(',').slice(1).join(',')),context={};
    assert.doesNotMatch(source,/dnsResolve|isInNet|myIpAddress|isResolvable/);
    vm.runInNewContext(source,context);
    for(const host of [...direct,...routed])assert.equal(context.FindProxyForURL('https://unused.example/',host),enabled&&direct.includes(host)?'DIRECT':'HTTPS gate.example:443',host);
    // Browser URL normalization supplies canonical literal hostnames to PAC.
    for(const address of ['http://0x0a000001/','http://167772161/','http://[::ffff:192.168.1.1]/']){
      const url=new URL(address);assert.equal(context.FindProxyForURL(url.href,url.hostname),enabled?'DIRECT':'HTTPS gate.example:443');
    }
    assert.equal(context.FindProxyForURL(remote.managerOrigin+'/api/extension/status','gate.example'),'DIRECT');
    assert.equal(context.FindProxyForURL('https://gate.example:9444/','gate.example'),'HTTPS gate.example:443');
    const changed={...config,passthrough:'*.onion'};assert.equal(C.matches('firefox',{value:changed},remote.proxy,enabled),false);
  }
});
function background(platform='brave',p=local){
  const handlers={},event=name=>({addListener:fn=>handlers[name]=fn}),bag={pairing:structuredClone(p)},calls=[];
  let setting={levelOfControl:'controlled_by_this_extension',value:C.configuration(platform,p.proxy,p.localNetwork)};
  const api={runtime:{id:'test',getURL:s=>'chrome-extension://test/'+s,onMessage:event('message'),onStartup:event('startup'),onInstalled:event('installed')},action:{setBadgeText:async()=>{},setTitle:async()=>{}},extension:{},storage:{local:{get:async k=>({[k]:bag[k]}),set:async v=>Object.assign(bag,structuredClone(v)),remove:async k=>delete bag[k]}},webRequest:{onAuthRequired:event('auth'),onCompleted:event('completed'),onErrorOccurred:event('failed')},tabs:{get:async()=>({incognito:false}),create:async()=>{}}};
  const adapter={api,platform,get:async()=>structuredClone(setting),privateAllowed:async()=>true,apply:async(proxy,enabled)=>{calls.push(enabled);setting={levelOfControl:'controlled_by_this_extension',value:C.configuration(platform,proxy,enabled)};},clear:async()=>{setting={levelOfControl:'controllable_by_this_extension',value:{}};}};
  const privacy={status:async()=>({state:'APPLIED'}),apply:async()=>{},release:async()=>{}};
  vm.runInNewContext(fs.readFileSync(require.resolve('../src/background.js'),'utf8'),{StargatePresentation:require('../src/presentation.js'),StargateAdapter:adapter,StargateCore:C,StargateStorage:require('../src/storage.js'),StargateIpfs:require('../src/ipfs.js'),StargateObservations:require('../src/observations.js'),StargateDNS:privacy,StargateWebRTC:privacy,URL,AbortSignal,fetch:async()=>({ok:true,json:async()=>({profileId:p.profileId,proxyHost:p.proxy.host,proxyPort:p.proxy.port,proxyScheme:p.proxy.scheme,status:{observedAt:new Date().toISOString()},credentials:{profileId:p.profileId,username:p.username,password:p.password,authorization:p.authorization}})})});
  return {handlers,bag,calls,api,adapter,getSetting:()=>setting,setSetting:s=>setting=s,send:(m,sender={id:'test',url:'chrome-extension://test/ui.html'})=>new Promise(resolve=>{if(handlers.message(m,sender,resolve)===false)resolve(null);})};
}
test('choice round trips through apply, startup, release and re-pair, and forgetting leaves settings in place',async()=>{
  for(const platform of ['firefox','brave'])for(const p of [local,remote]){
    const f=background(platform,p);
    const enable=await f.send({action:'local-network',enabled:true});assert.equal(enable.ok,true);assert.deepEqual(structuredClone(enable.status.localNetwork),{enabled:true,effective:true});
    f.setSetting({levelOfControl:'controllable_by_this_extension',value:{}});f.handlers.startup();await new Promise(r=>setImmediate(r));assert.equal(f.calls.at(-1),true);
    assert.equal((await f.send({action:'pair',managerOrigin:p.managerOrigin,code:'b'.repeat(43)})).ok,true);assert.equal(f.bag.pairing.localNetwork,true);
    await f.send({action:'release'});assert.equal(f.bag.pairing.localNetwork,true);assert.equal((await f.send({action:'status'})).status.localNetwork.effective,null);
    await f.send({action:'apply'});assert.equal(f.calls.at(-1),true);
    const setting=f.getSetting();await f.send({action:'forget'});assert.equal(f.bag.pairing,undefined);assert.equal(f.getSetting(),setting);
  }
});
test('enabling respects ownership, active route and extension message authorization',async()=>{
  for(const control of ['controlled_by_other_extensions','not_controllable','controllable_by_this_extension']){
    const f=background();f.setSetting({...f.getSetting(),levelOfControl:control});const answer=await f.send({action:'local-network',enabled:true});assert.equal(answer.ok,false);assert.equal(f.calls.length,0);assert.equal(f.bag.pairing.localNetwork,undefined);
  }
  for(const sender of [{id:'other',url:'chrome-extension://test/ui.html'},{id:'test',url:'https://attacker.example/'},{id:'test',url:'chrome-extension://test/ui.html',tab:{incognito:true}}]){const f=background();assert.equal(await f.send({action:'local-network',enabled:true},sender),null);assert.equal(f.calls.length,0);}
  const f=background();await f.send({action:'release'});assert.equal((await f.send({action:'local-network',enabled:true})).ok,false);
  for(const enabled of [undefined,null,'true',1])assert.equal((await background().send({action:'local-network',enabled})).code,'INVALID_LOCAL_NETWORK_CHOICE');
});
test('failed enable rolls back partial writes and does not persist opt-in; failed disable stays saved off and reports residual bypass',async()=>{
  for(const failure of ['set','confirm','storage','partial-storage']){
    const f=background(),apply=f.adapter.apply;
    f.adapter.apply=async(proxy,enabled)=>{await apply(proxy,enabled);if(enabled&&failure==='set')throw Error('fixture set failure');if(enabled&&failure==='confirm')f.setSetting({...f.getSetting(),value:{}});};
    if(failure==='storage')f.api.storage.local.set=async()=>{throw Error('fixture storage failure');};
    if(failure==='partial-storage'){const write=f.api.storage.local.set;f.api.storage.local.set=async v=>{await write(v);if(v.pairing.localNetwork)throw Error('fixture committed storage failure');};}
    const answer=await f.send({action:'local-network',enabled:true});assert.equal(answer.ok,false);assert.notEqual(f.bag.pairing.localNetwork,true);assert.equal(answer.status.localNetwork.effective,false);assert.deepEqual(f.calls,[true,false]);
  }
  const f=background();await f.send({action:'local-network',enabled:true});f.adapter.apply=async()=>{throw Error('fixture disable failure');};
  const answer=await f.send({action:'local-network',enabled:false});assert.equal(answer.ok,false);assert.equal(f.bag.pairing.localNetwork,false);assert.deepEqual(structuredClone(answer.status.localNetwork),{enabled:false,effective:true});assert.equal(answer.status.browser,'PROXY_CHANGED');
});
test('failure after ownership loss does not overwrite another controller and remote auth checks the chosen bypass',async()=>{
  const f=background();f.adapter.apply=async()=>{f.setSetting({...f.getSetting(),levelOfControl:'controlled_by_other_extensions'});throw Error('fixture takeover');};
  assert.equal((await f.send({action:'local-network',enabled:true})).ok,false);assert.equal(f.calls.length,0);
  const r=background('firefox',remote);await r.send({action:'local-network',enabled:true});
  const details={requestId:'auth',isProxy:true,realm:'Stargate',scheme:'basic',challenger:{host:remote.proxy.host,port:443},incognito:false};
  const reply=()=>new Promise(resolve=>r.handlers.auth(details,resolve));
  assert.ok((await reply()).authCredentials);r.handlers.completed({...details,incognito:true});
  r.setSetting({levelOfControl:'controlled_by_this_extension',value:C.configuration('firefox',remote.proxy,false)});
  assert.equal((await reply()).cancel,true);
});

test('browser adapters forward the opt-in and keep Firefox private permission enforcement',async()=>{
  for(const platform of ['firefox','brave']){
    const writes=[],api={proxy:{settings:{set:async value=>writes.push(value)}},extension:{isAllowedIncognitoAccess:async()=>true}},context={[platform==='firefox'?'browser':'chrome']:api,StargateCore:C};
    vm.runInNewContext(fs.readFileSync(require.resolve('../src/adapter-'+platform+'.js'),'utf8'),context);
    await context.StargateAdapter.apply(local.proxy,true);
    assert.equal(C.matches(platform,{value:writes[0].value},local.proxy,true),true);
    if(platform==='firefox'){api.extension.isAllowedIncognitoAccess=async()=>false;await assert.rejects(context.StargateAdapter.apply(local.proxy,true),/FIREFOX_PRIVATE_PERMISSION_REQUIRED/);assert.equal(writes.length,1);}
    else assert.equal(writes[0].scope,'regular');
  }
});

test('invalid saved pairing leaves the local-network choice unknown and remains recoverable by pairing',async()=>{
  const f=background();f.bag.pairing.localNetwork='true';
  const status=(await f.send({action:'status'})).status;assert.equal(status.problem,'INVALID_SAVED_PAIRING');assert.equal(status.localNetwork.enabled,null);assert.equal(status.localNetwork.effective,null);
  const repaired=await f.send({action:'pair',managerOrigin:local.managerOrigin,code:'c'.repeat(43)});assert.equal(repaired.ok,true);assert.equal(repaired.status.localNetwork.enabled,false);assert.equal(f.bag.pairing.localNetwork,false);
});
