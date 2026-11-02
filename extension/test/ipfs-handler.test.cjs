// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const I=require('../src/ipfs.js'),P=require('../src/presentation.js');
const source=fs.readFileSync(require.resolve('../src/ipfs-handler.js'),'utf8'),cid='bafybeifx7yeb55armcsxwwitkymga5xf53dxiarykms3ygqic223w5sk3m';
const tick=()=>new Promise(r=>setImmediate(r));
function load({privateContext=false,fragment='#'+encodeURIComponent('ipfs://'+cid),answer={ok:false,code:'IPFS_PROXY_NOT_APPLIED'}}={}){
  const elements=Object.fromEntries(['app','extension-version','ipfs-result','ipfs-retry'].map(id=>[id,{textContent:'',hidden:id==='ipfs-retry',dataset:{},addEventListener(e,f){this[e]=f;}}]));
  const calls=[],navigations=[],events={},location={hash:fragment,pathname:'/ipfs-handler.html',replace:u=>navigations.push(u)};
  const api={extension:{inIncognitoContext:privateContext},runtime:{getManifest:()=>({version:'0.8.3'}),sendMessage:async m=>{calls.push(m);return typeof answer==='function'?answer(m):answer;}},storage:{local:{get:async()=>({appearance:{theme:'stargate'}})}}};
  const document={body:{style:{}},documentElement:{style:{}},getElementById:id=>elements[id]};
  vm.runInNewContext(source,{chrome:api,document,window:{addEventListener:(e,f)=>events[e]=f},location,history:{replaceState:(a,b,path)=>{assert.equal(path,location.pathname);location.hash='';}},StargateIpfs:I,StargatePresentation:P,getComputedStyle:()=>({getPropertyValue:()=>''})});
  return {elements,calls,navigations,location,events};
}
test('protocol receiver rejects private and malformed handoffs without asking for a destination',async()=>{
  for(const options of [{privateContext:true},{fragment:'#%zz'},{fragment:'#'+encodeURIComponent('https://evil.org/')}]){
    const h=load(options);await tick();assert.equal(h.calls.length,0);assert.equal(h.navigations.length,0);assert.equal(h.location.hash,'');assert.equal(h.elements['ipfs-retry'].hidden,true);
  }
});
test('receiver stays local on policy failure, clears handoff URL and retries only on request',async()=>{
  for(const code of ['IPFS_PROXY_NOT_APPLIED','MANAGER_UNAVAILABLE','IPFS_NYM_DISABLED','INVALID_IPFS_CID']){
    const h=load({answer:{ok:false,code}});await tick();assert.equal(h.navigations.length,0);assert.equal(h.calls.length,1);assert.equal(h.calls[0].action,'ipfs-resolve');assert.equal(h.location.hash,'');assert.equal(h.elements['ipfs-retry'].hidden,false);assert.doesNotMatch(h.elements['ipfs-result'].textContent,new RegExp(cid));
    h.elements['ipfs-retry'].click();await tick();assert.equal(h.calls.length,2);
  }
});
test('receiver replaces its own page only with the successful HTTPS gateway result',async()=>{
  const url=I.url(cid,I.DEFAULT_GATEWAY),h=load({answer:{ok:true,url}});await tick();assert.deepEqual(h.navigations,[url]);
  for(const url of [undefined,'http://ipfs.dget.top/','javascript:alert(1)']){const h=load({answer:{ok:true,url}});await tick();assert.deepEqual(h.navigations,[]);}
});
test('a later malformed address cancels a pending receiver navigation',async()=>{
  let complete;const h=load({answer:()=>new Promise(r=>complete=r)});h.location.hash='#'+encodeURIComponent('https://evil.org/');h.events.hashchange();complete({ok:true,url:I.url(cid,I.DEFAULT_GATEWAY)});await tick();assert.equal(h.navigations.length,0);assert.equal(h.elements['ipfs-retry'].hidden,true);
});
