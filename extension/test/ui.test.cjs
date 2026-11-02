// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const O=require('../src/observations.js'),P=require('../src/presentation.js');
const html=fs.readFileSync(require.resolve('../src/ui.html'),'utf8'),source=fs.readFileSync(require.resolve('../src/ui.js'),'utf8');
const tick=()=>new Promise(resolve=>setImmediate(resolve));
function element(attrs={}){return Object.assign({hidden:false,textContent:'',value:'',checked:false,disabled:false,dataset:{},handlers:{},children:[],classList:{toggle(){}},addEventListener(e,h){this.handlers[e]=h;},replaceChildren(){this.children=[];},append(...c){this.children.push(...c);},prepend(...c){this.children.unshift(...c);},focus(){this.focused=true;},scrollIntoView(){this.scrolled=true;},setAttribute(k,v){this[k]=v;},getAttribute(k){return this[k];},removeAttribute(k){delete this[k];},closest(s){return s==='#page-nav'&&this.nav?{}:null;},querySelector(){return null;},showModal(){this.open=true;}},attrs);}
function load(platform,{browser='APPLIED',paired=true,privateAllowed=false,privateContext=false,fail=false,pending=false,pairError=null,pairErrorPaired=false,managerError=null,managerMissing=false,actionError=null,localNetwork={enabled:false,effective:false},managerOrigin='http://127.0.0.1:9080'}={}){
  const all=[...html.matchAll(/<([a-z][a-z0-9]*)\b([^>]*)>/g)].map(match=>{
    const attrs=Object.fromEntries([...match[2].matchAll(/([\w-]+)="([^"]*)"/g)].map(x=>[x[1],x[2]]));
    const node=element({tag:match[1],hidden:/\shidden(?:\s|$)/.test(match[2]),value:attrs.value||'',dataset:Object.fromEntries(Object.entries(attrs).filter(([k])=>k.startsWith('data-')).map(([k,v])=>[k.slice(5),v])),nav:match.index>html.indexOf('<nav id="page-nav"')&&match.index<html.indexOf('</nav>'),mutation:/\sdata-mutation(?:\s|$)/.test(match[2])});
    Object.assign(node,attrs);return node;
  });
  const elements=Object.fromEntries(all.filter(x=>x.id).map(x=>[x.id,x]));
  const actions=Object.fromEntries(all.filter(x=>x.dataset.action).map(x=>[x.dataset.action,x]));
  function query(selector){return [...new Set(selector.split(',').flatMap(sel=>{
    sel=sel.trim();if(sel.startsWith('#'))return elements[sel.slice(1)]?[elements[sel.slice(1)]]:[];
    if(sel==='[data-mutation]')return all.filter(x=>x.mutation);
    const m=sel.match(/^(button)?\[data-([\w-]+)(?:="([^"]+)")?\]$/);if(m)return all.filter(x=>(!m[1]||x.tag===m[1])&&x.dataset[m[2]]!==undefined&&(m[3]===undefined||x.dataset[m[2]]===m[3]));
    return [];
  }))];}
  const messages=[];let appearance=P.preferences(),completeAction;
  const status=()=>({platform,browser,localNetwork,paired,privateAllowed,profileId:paired?'test':null,managerOrigin:paired?managerOrigin:null,managerError,appearance,levelOfControl:browser==='RELEASED'?'controllable_by_this_extension':'controlled_by_this_extension',webrtc:{state:browser==='RELEASED'?'NOT_APPLIED':'APPLIED',levelOfControl:browser==='RELEASED'?'controllable_by_this_extension':'controlled_by_this_extension'},dns:{state:platform==='brave'?'BROWSER_MANAGED':browser==='RELEASED'?'NOT_APPLIED':'APPLIED',levelOfControl:browser==='RELEASED'?'controllable_by_this_extension':'controlled_by_this_extension'},manager:managerMissing?null:{process:{observation:'OBSERVED',activeState:'active'},proxy:{state:'RESPONDING'}}});
  const api={runtime:{getManifest:()=>({version:'9.8.7'}),getURL:p=>(platform==='brave'?'chrome-extension://test/':'moz-extension://test/')+p,sendMessage:async message=>{messages.push(message);if(fail)throw Error('unavailable');if(pending)return new Promise(()=>{});if(actionError?.action===message.action){if(actionError.delay)await new Promise(resolve=>{completeAction=resolve;});if(!actionError.ok)return {ok:false,code:actionError.code,status:status()};}if(message.action==='pair'&&pairError){if(pairErrorPaired)paired=true;return {ok:false,code:pairError,status:status()};}if(message.action==='pair'){paired=true;browser='APPLIED';managerOrigin=message.managerOrigin;}if(message.action==='release')browser='RELEASED';if(message.action==='apply')browser='APPLIED';if(message.action==='appearance')appearance=P.preferences(message.value);if(message.action==='local-network')localNetwork={enabled:message.enabled,effective:message.enabled};return {ok:true,status:status()};}},storage:{},extension:{inIncognitoContext:privateContext}};
  const document={hidden:false,body:element({style:{}}),documentElement:{style:{}},getElementById:id=>{assert.ok(elements[id],id);return elements[id];},createElement:()=>element(),querySelector:s=>query(s)[0]||null,querySelectorAll:query};
  vm.runInNewContext(source,{[platform==='brave'?'chrome':'browser']:api,document,StargateCore:require('../src/core.js'),StargatePresentation:P,StargateArt:require('../src/art.js'),StargateObservations:O,setInterval(){},Date,URL,URLSearchParams,location:{search:'',hash:''},history:{replaceState(){}},getComputedStyle:()=>({getPropertyValue:()=>''})});
  return {elements,actions,messages,query,resume(){assert.ok(completeAction);completeAction();},respond(value){elements.confirmation.returnValue=value;elements.confirmation.open=false;elements.confirmation.handlers.close();}};
}
test('Brave warning precedes setup and discloses direct traffic; help retains the non-enforcement limit',()=>{
  const warning=html.match(/<p id="brave-private-warning"[^>]*>([\s\S]*?)<\/p>/)[0];
  assert.ok(html.indexOf(warning)<html.indexOf('<form id="pair-form"'));
  assert.match(warning,/notice warning/);assert.match(warning,/<strong>Do not use Brave private windows with Stargate\.<\/strong>/);
  assert.match(warning,/connect directly, outside Stargate/);assert.match(html,/warning does not block private-window traffic/);assert.match(html,/allowing Stargate in private windows has not been verified as protection/);
});
test('warning persists across permission/proxy states and the settings status retains regular-window scope',async()=>{
  for(const platform of ['brave','firefox'])for(const privateAllowed of [false,true])for(const browser of ['APPLIED','RELEASED','PROXY_CONFLICT','UNPAIRED']){
    const ui=load(platform,{browser,paired:browser!=='UNPAIRED',privateAllowed});await tick();
    assert.equal(ui.elements['extension-version'].textContent,'Version 9.8.7');assert.equal(ui.elements['brave-private-warning'].hidden,platform!=='brave');assert.equal(ui.elements['pair-form'].hidden,browser!=='UNPAIRED');
    if(browser==='APPLIED')assert.equal(ui.elements['browser-state'].textContent,'Applied by Stargate · regular windows');
    assert.deepEqual(ui.messages.map(m=>m.action),['status-local','status']);
  }
});
test('warning is immediate and survives pending status, background failure and private UI refusal',async()=>{
  for(const options of [{pending:true},{fail:true},{privateContext:true}]){
    const ui=load('brave',options);assert.equal(ui.elements['brave-private-warning'].hidden,false);await tick();assert.equal(ui.elements['brave-private-warning'].hidden,false);
    assert.equal(ui.elements['extension-version'].textContent,'Version 9.8.7');
    if(options.fail){assert.match(ui.elements.message.textContent,/background unavailable/);assert.equal(ui.elements['connection-title'].textContent,'Status is unknown');assert.equal(ui.elements['page-details'].hidden,false);}
    if(options.privateContext){assert.equal(ui.elements['private-context-warning'].hidden,false);assert.equal(ui.elements['connection-action'].disabled,true);assert.equal(ui.messages.length,0);}
  }
  assert.equal(load('firefox',{privateContext:true}).elements['brave-private-warning'].hidden,true);
});
test('Disconnect requires confirmation; cancel retains routing and accepted release still permits Connect',async()=>{
  const ui=load('brave');await tick();ui.elements['connection-action'].handlers.click();await tick();
  assert.equal(ui.elements.confirmation.open,true);assert.match(ui.elements['confirmation-copy'].textContent,/may go directly/);assert.equal(ui.messages.some(m=>m.action==='release'),false);
  assert.equal(ui.elements['confirmation-title'].textContent,'Disconnect Stargate?');assert.equal(ui.elements['confirmation-cancel'].textContent,'Stay connected');assert.equal(ui.elements['confirmation-accept'].textContent,'Disconnect');assert.match(ui.elements['confirmation-copy'].textContent,/Your saved access is kept/);assert.match(ui.elements['confirmation-copy'].textContent,/without another code/);
  ui.respond('cancel');await tick();assert.equal(ui.messages.some(m=>m.action==='release'),false);
  ui.elements['connection-action'].handlers.click();ui.respond('accept');await tick();assert.equal(ui.messages.at(-1).action,'release');assert.match(ui.elements['browser-state'].textContent,/Released to previous/);
  ui.elements['connection-action'].handlers.click();await tick();assert.equal(ui.messages.at(-1).action,'apply');assert.match(ui.elements['browser-state'].textContent,/Applied by Stargate · regular windows/);assert.equal(ui.elements['brave-private-warning'].hidden,false);
});
test('local-address disclosures, saved/effective mismatch, confirmed enable and immediate disable are retained',async()=>{
  for(const pattern of [/bypasses Stargate profile-wide/,/Hostnames \(including local names\)/,/IPv4-mapped IPv6 literals/,/Off by default/])assert.match(html,pattern);
  for(const state of [{enabled:false,effective:false},{enabled:true,effective:true},{enabled:false,effective:true},{enabled:true,effective:null},{enabled:null,effective:null}]){
    const ui=load('firefox',{localNetwork:state});await tick();assert.match(ui.elements['local-network-state'].textContent,state.enabled===null?/Saved choice: Unknown/:state.enabled?/Saved choice: On/:/Saved choice: Off/);assert.match(ui.elements['local-network-state'].textContent,state.effective===null?/Browser bypass: Unknown/:state.effective?/Browser bypass: On/:/Browser bypass: Off/);if(state.enabled===false&&state.effective===true)assert.match(ui.elements['local-network-state'].textContent,/Settings differ/);
  }
  const ui=load('brave');await tick();ui.elements['local-network-enable'].handlers.click();assert.equal(ui.messages.some(m=>m.action==='local-network'),false);ui.respond('accept');await tick();assert.equal(ui.messages.at(-1).enabled,true);ui.elements['local-network-disable'].handlers.click();await tick();assert.equal(ui.messages.at(-1).enabled,false);
  const unpaired=load('brave',{paired:false});await tick();assert.equal(unpaired.elements['local-network-controls'].hidden,true);
});
test('unknown redemption and expired-code feedback go to the operator without an automatic second redemption',async()=>{
  for(const code of ['PAIRING_OUTCOME_UNKNOWN','INVALID_OR_EXPIRED_PAIRING_CODE']){
    const ui=load('brave',{paired:false,pairError:code});await tick();ui.elements['manager-url'].value='https://gate.example:9443';ui.elements.code.value='c'.repeat(43);ui.elements['pair-form'].handlers.submit({preventDefault(){}});await tick();
    const msg=ui.elements['pair-error'].textContent;assert.match(msg,/operator/);assert.match(msg,/new code/);if(code==='PAIRING_OUTCOME_UNKNOWN'){assert.match(msg,/result unknown/);assert.match(msg,/code may have been used/);assert.match(msg,/check for an unused device, revoke it if identified/);assert.match(msg,/Existing pairing and proxy settings are kept/);}
    assert.equal(ui.messages.filter(m=>m.action==='pair').length,1);
  }
});
test('remote recovery offers help rather than prohibited remote manager administration',async()=>{
  const ui=load('brave',{managerOrigin:'https://gate.example:9443'});await tick();assert.equal(ui.actions.manager.hidden,true);
});
test('details pairing recovery opens setup instead of redeeming an absent code',async()=>{
  for(const paired of [false,true]){
    const ui=load('brave',{paired,managerError:paired?'PAIRING_REJECTED':null});await tick();
    ui.elements['recovery-action'].handlers.click();await tick();
    assert.equal(ui.elements['pair-form'].hidden,false);assert.equal(ui.messages.some(m=>m.action==='pair'),false);
    if(paired)assert.equal(ui.elements['manager-url'].value,'http://127.0.0.1:9080');
  }
});
test('first pairing saved before an apply failure shows the reason outside the hidden code form',async()=>{
  const ui=load('brave',{paired:false,browser:'PROXY_CONFLICT',pairError:'PROXY_CONFLICT',pairErrorPaired:true});await tick();
  ui.elements['manager-url'].value='https://gate.example:9443';ui.elements.code.value='c'.repeat(43);ui.elements['pair-form'].handlers.submit({preventDefault(){}});await tick();
  assert.equal(ui.elements['pair-form'].hidden,true);assert.equal(ui.elements['setup-existing'].hidden,false);assert.match(ui.elements.message.textContent,/Access saved/);assert.match(ui.elements.message.textContent,/Another extension or policy controls the proxy/);assert.equal(ui.elements.code['aria-invalid'],undefined);assert.equal(ui.elements.code.focused,undefined);
});

test('outage and rejected access retain confirmed manual disconnect without discarding access',async()=>{
  for(const platform of ['firefox','brave'])for(const managerError of ['MANAGER_UNAVAILABLE','PAIRING_REJECTED']){
    const ui=load(platform,{managerError,managerMissing:true});await tick();
    assert.equal(ui.elements['disconnect-secondary'].hidden,false);assert.equal(ui.elements['disconnect-secondary'].disabled,false);
    ui.elements['disconnect-secondary'].handlers.click();assert.equal(ui.elements.confirmation.open,true);ui.respond('cancel');await tick();assert.equal(ui.messages.some(m=>m.action==='release'),false);
    ui.elements['disconnect-secondary'].handlers.click();ui.respond('accept');await tick();assert.equal(ui.messages.at(-1).action,'release');assert.match(ui.elements.message.textContent,/Stargate is off.*saved access is kept/);assert.equal(ui.elements['disconnect-secondary'].hidden,true);
  }
});
test('browser-specific IPFS steps are visible in settings and reachable from help',async()=>{
  for(const platform of ['firefox','brave']){
    const ui=load(platform);await tick();assert.equal(ui.elements['firefox-ipfs-steps'].hidden,platform==='brave');assert.equal(ui.elements['enable-ipfs-links'].hidden,platform!=='brave');
    ui.elements['help-ipfs-setup'].handlers.click();assert.equal(ui.elements['page-settings'].hidden,false);assert.equal(ui.elements['ipfs-link-setup'].scrolled,true);assert.equal(ui.elements['ipfs-links-guidance'].focused,true);
  }
  assert.match(html,/about:preferences#downloads/);assert.match(html,/Use Stargate IPFS through Nym/);assert.match(html,/Open IPFS setup instructions/);
});


test('IPFS validation errors identify and focus the input without duplicate status announcements',async()=>{
  for(const platform of ['firefox','brave'])for(const [action,code,input,form,error] of [
    ['ipfs-open','INVALID_IPFS_CID','ipfs-address','ipfs-form','ipfs-error'],
    ['ipfs-open','INVALID_IPFS_ADDRESS','ipfs-address','ipfs-form','ipfs-error'],
    ['ipfs-gateway','INVALID_IPFS_GATEWAY','ipfs-gateway','ipfs-gateway-form','ipfs-gateway-error']
  ]){
    const ui=load(platform,{actionError:{action,code}});await tick();ui.elements[input].value='invalid input';
    ui.elements[form].handlers.submit({preventDefault(){}});await tick();
    assert.equal(ui.elements[input]['aria-invalid'],'true');assert.equal(ui.elements[input].focused,true);
    assert.equal(ui.elements[input]['aria-describedby'],error);assert.equal(ui.elements[input].value,'invalid input');
    assert.equal(ui.elements[error].hidden,false);assert.ok(ui.elements[error].textContent);assert.equal(ui.elements.message.textContent,'');
    ui.elements[input].handlers.input();assert.equal(ui.elements[input]['aria-invalid'],undefined);assert.equal(ui.elements[error].hidden,true);assert.equal(ui.elements[error].textContent,'');
  }
});
test('network failures are not described as invalid IPFS input',async()=>{
  const ui=load('brave',{actionError:{action:'ipfs-open',code:'MANAGER_UNAVAILABLE'}});await tick();
  ui.elements['ipfs-address'].value='saved input';ui.elements['ipfs-form'].handlers.submit({preventDefault(){}});await tick();
  assert.equal(ui.elements['ipfs-address']['aria-invalid'],undefined);assert.equal(ui.elements['ipfs-error'].hidden,true);assert.match(ui.elements.message.textContent,/Server observations are unavailable/);assert.equal(ui.elements['ipfs-address'].value,'saved input');
});

test('confirmation Tab wraps in both directions without overriding Escape or normal Tab',async()=>{
  for(const platform of ['firefox','brave']){
    const ui=load(platform);await tick();const cancel=ui.elements['confirmation-cancel'],accept=ui.elements['confirmation-accept'];
    let prevented=0;const key=(target,key,shiftKey=false)=>ui.elements.confirmation.handlers.keydown({target,key,shiftKey,preventDefault(){prevented++;}});
    key(accept,'Tab');assert.equal(cancel.focused,true);assert.equal(prevented,1);
    key(cancel,'Tab',true);assert.equal(accept.focused,true);assert.equal(prevented,2);
    key(cancel,'Tab');key(accept,'Tab',true);key(cancel,'Escape');assert.equal(prevented,2);assert.equal(ui.messages.some(m=>m.action==='release'),false);
  }
});

test('delayed validation does not invalidate or refocus edited input, including edit then undo',async()=>{
  for(const platform of ['firefox','brave'])for(const [action,code,input,form,error] of [
    ['ipfs-open','INVALID_IPFS_CID','ipfs-address','ipfs-form','ipfs-error'],
    ['ipfs-gateway','INVALID_IPFS_GATEWAY','ipfs-gateway','ipfs-gateway-form','ipfs-gateway-error']
  ])for(const undo of [false,true]){
    const ui=load(platform,{actionError:{action,code,delay:true}});await tick();ui.elements[input].value='submitted';
    ui.elements[form].handlers.submit({preventDefault(){}});await tick();
    ui.elements[input].value='edited';ui.elements[input].handlers.input();
    if(undo){ui.elements[input].value='submitted';ui.elements[input].handlers.input();}
    ui.resume();await tick();assert.equal(ui.elements[input]['aria-invalid'],undefined);assert.equal(ui.elements[input].focused,undefined);assert.equal(ui.elements[error].hidden,true);assert.equal(ui.elements[input].value,undo?'submitted':'edited');assert.match(ui.elements.message.textContent,/input changed.*Submit it again/);
  }
});
test('successful delayed IPFS opening does not erase newly edited input',async()=>{
  const ui=load('brave',{actionError:{action:'ipfs-open',ok:true,delay:true}});await tick();ui.elements['ipfs-address'].value='submitted';ui.elements['ipfs-form'].handlers.submit({preventDefault(){}});await tick();ui.elements['ipfs-address'].value='next address';ui.elements['ipfs-address'].handlers.input();ui.resume();await tick();assert.equal(ui.elements['ipfs-address'].value,'next address');assert.match(ui.elements.message.textContent,/opened in a new tab/);
});

test('browser preparation precedes pairing, reports Firefox permission and keeps Brave checks manual',async()=>{
  assert.ok(html.indexOf('id="browser-preparation"')<html.indexOf('id="pair-form"'));
  for(const privateAllowed of [false,true]){
    const ff=load('firefox',{paired:false,browser:'UNPAIRED',privateAllowed});await tick();
    assert.equal(ff.elements['firefox-preparation'].hidden,false);assert.equal(ff.elements['brave-note'].hidden,true);assert.equal(ff.elements['firefox-note'].hidden,privateAllowed);
    assert.match(ff.elements['firefox-preparation-state'].textContent,privateAllowed?/Permission confirmed/:/not enabled yet/);assert.equal(ff.messages.some(m=>m.action==='pair'),false);
    const brave=load('brave',{privateAllowed});await tick();assert.equal(brave.elements['firefox-preparation'].hidden,true);assert.equal(brave.elements['brave-note'].hidden,false);assert.match(brave.elements['setup-preparation-state'].textContent,/Manual check/);
  }
  const unknown=load('firefox',{fail:true});await tick();assert.match(unknown.elements['firefox-preparation-state'].textContent,/not confirmed/);assert.equal(unknown.elements['firefox-note'].hidden,false);
});
test('first-run completion reviews the real server, keeps access, and leaves IPFS setup optional',async()=>{
  for(const platform of ['firefox','brave']){
    const ui=load(platform,{paired:false,browser:'UNPAIRED',privateAllowed:true});await tick();
    ui.elements['manager-url'].value='https://gate.example:9443';ui.elements.code.value='c'.repeat(43);ui.elements['pair-form'].handlers.submit({preventDefault(){}});await tick();
    assert.equal(ui.elements['setup-success'].hidden,false);assert.equal(ui.elements['setup-server'].textContent,'https://gate.example:9443');assert.equal(ui.elements.code.value,'');assert.equal(ui.elements['setup-summary-title'].focused,true);
    assert.equal(ui.messages.filter(m=>m.action==='pair').length,1);assert.equal(ui.messages.some(m=>m.action.startsWith('ipfs')),false);
    ui.elements['setup-ipfs'].handlers.click();assert.equal(ui.elements['page-settings'].hidden,false);assert.equal(ui.elements['ipfs-link-setup'].scrolled,true);assert.equal(ui.elements['ipfs-links-guidance'].focused,true);assert.equal(ui.messages.some(m=>m.action.startsWith('ipfs')),false);
  }
});
test('saved-access apply recovery reaches the recap without another pairing attempt',async()=>{
  const ui=load('firefox',{paired:true,browser:'FIREFOX_PRIVATE_PERMISSION_REQUIRED',privateAllowed:true});await tick();
  ui.elements['connection-action'].handlers.click();await tick();ui.actions.apply.handlers.click();await tick();
  assert.equal(ui.elements['setup-success'].hidden,false);assert.equal(ui.elements['setup-summary-title'].focused,true);assert.equal(ui.messages.filter(m=>m.action==='pair').length,0);assert.equal(ui.messages.filter(m=>m.action==='apply').length,1);
});
