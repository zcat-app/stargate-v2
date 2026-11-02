// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
'use strict';
(() => {
  const A=StargateAdapter,api=A.api,C=StargateCore,S=StargateStorage,I=StargateIpfs,O=StargateObservations,R=StargateWebRTC,D=StargateDNS,P=StargatePresentation;
  const own=api.runtime.getURL('').replace(/\/$/,''),attempts=new Map();
  const observations=O.store(api.storage.session);
  let memoryAuth={provided:0,rejected:0,lastAt:null},operation=false,operationKind=null,restorePending=false,pendingContexts=0,toolbarGeneration=0,toolbarRunning=false,remoteGeneration=0,lastRemote=null;
  async function pairing(){const p=await S.read(api);return p===undefined ? null : C.validatePairing(p);}
  async function authState(){return api.storage.session ? (await api.storage.session.get('authObservation')).authObservation || {provided:0,rejected:0,lastAt:null} : memoryAuth;}
  async function recordAuth(kind){const value=await authState();value[kind]++;value.lastAt=new Date().toISOString();memoryAuth=value;if(api.storage.session)await api.storage.session.set({authObservation:value});}
  async function appearance(){return P.preferences((await api.storage.local.get('appearance')).appearance);}
  // Presentation failures must never change a routing/authentication outcome.
  async function badge(){
    ++toolbarGeneration;if(toolbarRunning)return;toolbarRunning=true;
    try {
      for(;;){
        const generation=toolbarGeneration,s=await status(false,false),prefs=s.appearance,v=P.view(s);
        if(generation!==toolbarGeneration)continue;
        await api.action.setIcon({path:{16:`icons/${prefs.theme}-${v.icon}-16.png`,32:`icons/${prefs.theme}-${v.icon}-32.png`}});
        await api.action.setBadgeText({text:v.icon==='attention'?'!':v.icon==='unknown'?'?':''});
        await api.action.setTitle({title:'Stargate: '+v.title+' · regular windows. '+v.text});
        if(generation===toolbarGeneration)break;
      }
    }catch{ /* Browser/settings observations remain authoritative when artwork fails. */ }
    finally{toolbarRunning=false;}
  }
  async function manager(p,path,method='GET',body) {
    let response;
    try {
      response=await fetch(p.managerOrigin+path,{method,cache:'no-store',credentials:'omit',redirect:'error',signal:AbortSignal.timeout(8000),
        headers:{'X-Stargate-Extension':own,...(p.authorization?{Authorization:p.authorization}:{}),...(method==='POST'?{'Content-Type':'application/json'}:{})},
        ...(method==='POST'?{body:JSON.stringify(body)}:{})});
    }catch{throw Error('MANAGER_UNAVAILABLE');}
    let value;try{value=await response.json();}catch{throw Error('INVALID_MANAGER_RESPONSE');}
    if(!value || typeof value!=='object' || Array.isArray(value))throw Error('INVALID_MANAGER_RESPONSE');
    if(!response.ok){
      if(typeof value.code!=='string' || !value.code)throw Error('INVALID_MANAGER_RESPONSE');
      const error=Error(value.code);error.status=response.status;throw error;
    }
    return value;
  }
  async function redeem(origin,code){
    let value;
    try{value=await manager({managerOrigin:origin},'/api/pairing/redeem','POST',{code});}
    catch(error){
      // A server error may follow persistence (for example directory fsync),
      // so even a well-formed 5xx error cannot establish that no device exists.
      if(['MANAGER_UNAVAILABLE','INVALID_MANAGER_RESPONSE'].includes(error.message) || (error.status>=500 && error.status<600))throw Error('PAIRING_OUTCOME_UNKNOWN');
      throw error;
    }
    // The one-time code may already be consumed. Validate before touching saved
    // credentials/settings; never retry redemption after an uncertain response.
    try{return C.fromRedeem(origin,value);}catch{throw Error('PAIRING_OUTCOME_UNKNOWN');}
  }
  async function managerStatus(p){
    const value=await manager(p,'/api/extension/status');
    if(value.profileId!==p.profileId || !value.status?.observedAt)throw Error('INVALID_MANAGER_RESPONSE');
    C.responseEndpoint(p.managerOrigin,value);return value;
  }
  async function status(remote=true,updateBadge=true) {
    let p,problem=null;try{p=await pairing();}catch(e){problem=e.message;p=null;}
    let setting,allowed;try{[setting,allowed]=await Promise.all([A.get(),A.privateAllowed()]);}catch{problem='BROWSER_SETTINGS_UNAVAILABLE';}
    let observed=null,managerError=null,cached=false;
    if(p&&remote){
      const request=++remoteGeneration;
      try{observed=await managerStatus(p);}catch(e){managerError=e.message;}
      if(request===remoteGeneration)lastRemote={profileId:p.profileId,origin:p.managerOrigin,observed,managerError};
    }else if(p&&lastRemote?.profileId===p.profileId&&lastRemote.origin===p.managerOrigin){
      observed=lastRemote.observed;managerError=lastRemote.managerError;cached=true;
    }
    let browser=C.browserState(A.platform,setting,p,allowed);
    const webrtc=await R.status(api,A.platform);
    if(browser==='APPLIED' && webrtc.state!=='APPLIED')browser='WEBRTC_'+webrtc.state;
    const dns=await D.status(api,A.platform);
    if(browser==='APPLIED' && A.platform==='firefox' && dns.state!=='APPLIED')browser='DNS_'+dns.state;
    if(p && observed && (JSON.stringify(C.responseEndpoint(p.managerOrigin,observed))!==JSON.stringify(p.proxy)))browser='PROXY_ENDPOINT_CHANGED';
    if(!p&&(setting?.levelOfControl==='controlled_by_this_extension'||webrtc.levelOfControl==='controlled_by_this_extension'||dns.levelOfControl==='controlled_by_this_extension'))browser='SETTINGS_REMAIN';
    const localNetworkEffective=p && setting?.levelOfControl==='controlled_by_this_extension'
      ? C.matches(A.platform,setting,p.proxy,true)?true:C.matches(A.platform,setting,p.proxy,false)?false:null : null;
    const savedGateway=(await api.storage.local.get('ipfsGateway')).ipfsGateway;
    const result={platform:A.platform,paired:!!p,profileId:p?.profileId || null,managerOrigin:p?.managerOrigin || null,
      localNetwork:{enabled:p?p.localNetwork:problem?null:false,effective:localNetworkEffective},
      ipfsGateway:savedGateway===undefined?I.DEFAULT_GATEWAY:savedGateway,
      browser,webrtc,dns,privateAllowed:!!allowed,levelOfControl:setting?.levelOfControl || 'unknown',problem,managerError,
      manager:observed?.status || null,managerPending:!!p&&!remote,managerCached:cached,operation:operationKind,
      appearance:await appearance(),browserObservations:await observations.read(),auth:await authState()};
    if(updateBadge)await badge();
    return result;
  }
  async function apply() {
    let p=await pairing();if(!p)throw Error('NOT_PAIRED');
    try{const fresh=await managerStatus(p);p.proxy=C.responseEndpoint(p.managerOrigin,fresh);}
    catch(e){if(e.message!=='MANAGER_UNAVAILABLE')throw e;}
    const current=await A.get();
    if(['controlled_by_other_extensions','not_controllable'].includes(current.levelOfControl))throw Error('PROXY_CONFLICT');
    await privacyApply();
    await A.apply(p.proxy,p.localNetwork);p.desired=true;await S.write(api,p);await badge();
    if(!C.matches(A.platform,await A.get(),p.proxy,p.localNetwork))throw Error('PROXY_SETTING_NOT_CONFIRMED');
  }
  async function localNetwork(enabled) {
    C.localNetworkChoice(enabled);
    const p=await pairing();if(!p)throw Error('NOT_PAIRED');
    const setting=await A.get();
    if(['controlled_by_other_extensions','not_controllable'].includes(setting.levelOfControl))throw Error('PROXY_CONFLICT');
    // Enabling is permitted only from a confirmed, owned, active route. A
    // disable may also repair an owned mismatch left by an interrupted change.
    if(setting.levelOfControl!=='controlled_by_this_extension' || !p.desired ||
      (enabled && !C.matches(A.platform,setting,p.proxy,p.localNetwork)))throw Error('LOCAL_NETWORK_PROXY_NOT_APPLIED');
    if(enabled===p.localNetwork && C.matches(A.platform,setting,p.proxy,enabled))return;
    await privacyApply();
    const next={...p,localNetwork:enabled};
    // Persist a disable before changing the browser: recovery must never
    // reinstate a bypass the user has asked to remove.
    if(!enabled)await S.write(api,next);
    try {
      await A.apply(p.proxy,enabled);
      const actual=await A.get();
      if(actual.levelOfControl!=='controlled_by_this_extension' || !C.matches(A.platform,actual,p.proxy,enabled))throw Error('PROXY_SETTING_NOT_CONFIRMED');
      if(enabled)await S.write(api,next);
    } catch(error) {
      // A failed enable must not become a saved opt-in. Remove any partial
      // bypass while we still own settings; never overwrite another owner.
      if(enabled && !p.localNetwork) {
        try{await S.write(api,{...p,localNetwork:false});}catch{}
        try{if((await A.get()).levelOfControl==='controlled_by_this_extension')await A.apply(p.proxy,false);}catch{}
      }
      throw error;
    }
  }
  async function release(){
    // Invalid saved bytes must not trap our overrides. A storage read failure
    // still fails the operation; malformed pairing is never silently replaced.
    const saved=await S.read(api);let p=null;
    try{if(saved!==undefined)p=C.validatePairing(saved);}catch{}
    const current=await A.get();if(current.levelOfControl==='controlled_by_this_extension')await A.clear();
    if(p){p.desired=false;await S.write(api,p);}
    const released=await Promise.allSettled([R.release(api),D.release(api,A.platform)]);
    const failed=released.find(v=>v.status==='rejected');if(failed)throw failed.reason;
  }
  async function handle(message) {
    if(message.action==='status')return status();
    if(message.action==='status-local')return status(false);
    if(message.action==='options'){
      const page=['setup','settings','details','tools','help'].includes(message.page)?message.page:'settings';
      await api.tabs.create({url:api.runtime.getURL('ui.html')+'#'+page+(page==='setup'&&message.replace===true?'-repair':'')});return status(false);
    }
    if(operation)throw Error('OPERATION_IN_PROGRESS');operation=true;
    operationKind=['pair','apply','release','disconnect-forget','local-network'].includes(message.action)?message.action:null;
    if(operationKind)void badge();
    try {
      if(message.action==='pair') {
        const origin=C.managerOrigin(message.managerOrigin);
        if(typeof message.code!=='string' || !/^[A-Za-z0-9_-]{43}$/.test(message.code.trim()))throw Error('INVALID_PAIRING_CODE');
        const p=await redeem(origin,message.code.trim());
        let previous;try{previous=await pairing();}catch{}
        p.localNetwork=previous?.localNetwork===true;await S.write(api,p);await badge();await apply();
      } else if(message.action==='appearance') {
        await api.storage.local.set({appearance:P.preferences(message.value)});
        return status(false);
      } else if(message.action==='local-network') {
        await localNetwork(message.enabled);
      } else if(message.action==='ipfs-gateway') {
        await api.storage.local.set({ipfsGateway:I.gateway(message.gateway)});
      } else if(message.action==='ipfs-open'||message.action==='ipfs-resolve') {
        const saved=(await api.storage.local.get('ipfsGateway')).ipfsGateway;
        const url=I.url(message.address,saved===undefined?I.DEFAULT_GATEWAY:saved);
        const fresh=await status();
        if(fresh.browser!=='APPLIED')throw Error('IPFS_PROXY_NOT_APPLIED');
        if(!fresh.manager)throw Error('MANAGER_UNAVAILABLE');
        if(!fresh.manager.nym || fresh.manager.nym.readiness==='DISABLED')throw Error('IPFS_NYM_DISABLED');
        // Settings are checked again after the manager request. This is not a
        // browser-wide kill switch against subsequent external setting changes.
        const p=await pairing(),setting=await A.get();
        if(!p || setting.levelOfControl!=='controlled_by_this_extension' || !C.matches(A.platform,setting,p.proxy,p.localNetwork))throw Error('IPFS_PROXY_NOT_APPLIED');
        if(message.action==='ipfs-resolve')return url;
        await api.tabs.create({url});
      } else if(message.action==='apply')await apply();
      else if(message.action==='release')await release();
      else if(message.action==='disconnect-forget') {
        await release();
        const remaining=await status(false,false);
        if(!P.releaseConfirmed(remaining))throw Error('SETTINGS_RELEASE_NOT_CONFIRMED');
        await S.forget(api);
      } else if(message.action==='forget') {await S.forget(api);await badge();}
      else if(message.action==='manager') {const p=await pairing();if(!p)throw Error('NOT_PAIRED');if(p.managerOrigin.startsWith('https:'))throw Error('ADMIN_ACCESS_IS_SEPARATE');await api.tabs.create({url:p.managerOrigin+'/'});}
      else if(message.action==='brave-settings')await api.tabs.create({url:'brave://settings/privacy'});
      else throw Error('UNKNOWN_ACTION');
      return status();
    } finally {finishOperation();}
  }
  // Register synchronously: credentials are loaded afresh when a dormant worker wakes.
  api.webRequest.onAuthRequired.addListener((details,reply)=>{
    (async()=>{
      const privacy=await O.privateContext(details,api);
      const p=await pairing(),count=attempts.get(details.requestId)?.count || 0,decision=C.authDecision(p,{...details,incognito:privacy!==false},count);
      if(decision==='credentials'){
        if(p.proxy.scheme==='https'){
          const setting=await A.get();
          if(setting.levelOfControl!=='controlled_by_this_extension' || !C.matches(A.platform,setting,p.proxy,p.localNetwork)){reply({cancel:true});return;}
        }
        if(attempts.size>256)attempts.clear();attempts.set(details.requestId,{count:count+1,at:Date.now()});
        await recordAuth('provided').catch(()=>{});
        reply({authCredentials:{username:p.username,password:p.password}});
      }else if(decision==='cancel'){
        if(privacy===false)await recordAuth('rejected').catch(()=>{});
        reply({cancel:true});
      }else reply({});
    })().catch(()=>reply({cancel:true}));
  },{urls:['<all_urls>']},['asyncBlocking']);
  const webDestinations={urls:['http://*/*','https://*/*','ws://*/*','wss://*/*']};
  function observe(details,failed) {
    if(typeof details.incognito==='boolean'){observations.record(O.observation(details,failed));return;}
    // Chromium does not include incognito on webRequest details. Resolve only
    // the tab's non-sensitive privacy flag; closed/unknown contexts are excluded.
    // Bound in-flight lookups as well as stored rows. Observations are best effort.
    if(pendingContexts>=32)return;
    const row=O.observation({...details,incognito:false},failed);if(!row)return;
    pendingContexts++;
    void O.privateContext(details,api).then(privateMode=>{if(privateMode===false)observations.record(row);}).finally(()=>pendingContexts--);
  }
  // Request classes are browser observations, never proof of the upstream route.
  api.webRequest.onCompleted.addListener(details=>{
    attempts.delete(details.requestId);observe(details,false);
  },webDestinations);
  api.webRequest.onErrorOccurred.addListener(details=>{
    attempts.delete(details.requestId);observe(details,true);
  },webDestinations);
  api.runtime.onMessage.addListener((message,sender,reply)=>{
    if(sender.id!==api.runtime.id || typeof sender.url!=='string' || !sender.url.startsWith(api.runtime.getURL('')) || sender.tab?.incognito)return false;
    handle(message).then(value=>reply(message.action==='ipfs-resolve'?{ok:true,url:value}:{ok:true,status:value})).catch(async error=>reply({ok:false,code:error.message,status:await status().catch(()=>null)}));return true;
  });
  async function privacyApply(){
    // Restore both independently: an RTC conflict must not leave an existing
    // Firefox PAC configuration without its DNS restriction (or vice versa).
    const applied=await Promise.allSettled([R.apply(api,A.platform),D.apply(api,A.platform)]);
    const failed=applied.find(v=>v.status==='rejected');if(failed)throw failed.reason;
  }
  async function restore(){
    // A successful Release must not be followed by a late startup privacy write.
    // Coalesce startup/update notifications that arrive during another mutation.
    if(operation){restorePending=true;return;}operation=true;
    try {
    const p=await pairing();await badge();
    if(p?.desired){
      const setting=await A.get();
      if(['controlled_by_other_extensions','not_controllable'].includes(setting.levelOfControl))return;
      // Updates must acquire RTC policy even when proxy settings already match.
      await privacyApply();
      if(!C.matches(A.platform,setting,p.proxy,p.localNetwork) && setting.levelOfControl==='controllable_by_this_extension')await A.apply(p.proxy,p.localNetwork);
    }
    } finally {finishOperation();}
  }
  function finishOperation(){
    operation=false;operationKind=null;void badge();
    if(restorePending){restorePending=false;void restore().catch(()=>{});}
  }
  api.runtime.onStartup.addListener(()=>void restore().catch(()=>{}));
  api.runtime.onInstalled.addListener(details=>{void restore().catch(()=>{});if(details.reason==='install')void api.runtime.openOptionsPage().catch(()=>{});});
  if(api.storage.local.setAccessLevel)void api.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'}).catch(()=>{});
  if(api.storage.session)void api.storage.session.remove('lastBrowserEvent').catch(()=>{});
  // Observe changes made outside our UI without adding any network polling.
  for(const setting of [api.proxy?.settings,R.setting?.(api),D.setting?.(api)])setting?.onChange?.addListener(()=>void badge());
  api.storage.onChanged?.addListener((changes,area)=>{if(area==='local'&&(changes.pairing||changes.appearance))void badge();});
  void badge();
})();
