// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
'use strict';
(function(root){
  const networks=['TOR','I2P','WEB'];
  async function privateContext(details,api) {
    if(typeof details.incognito==='boolean')return details.incognito;
    if(!Number.isInteger(details.tabId)||details.tabId<0)return undefined;
    try{const tab=await api.tabs.get(details.tabId);return typeof tab.incognito==='boolean'?tab.incognito:undefined;}catch{return undefined;}
  }
  function observation(details,failed,at=new Date().toISOString()) {
    if(details.incognito!==false)return null;
    let host;try{host=new URL(details.url).hostname.toLowerCase().replace(/\.+$/,'');}catch{return null;}
    if(['localhost','127.0.0.1','[::1]'].includes(host))return null;
    const network=host.endsWith('.onion')?'TOR':host.endsWith('.i2p')?'I2P':'WEB';
    if(failed) {
      if(['NS_BINDING_ABORTED','net::ERR_ABORTED'].includes(details.error))return null;
      const codes={NS_ERROR_PROXY_CONNECTION_REFUSED:'proxy',NS_ERROR_PROXY_BAD_GATEWAY:'proxy','net::ERR_PROXY_CONNECTION_FAILED':'proxy','net::ERR_TUNNEL_CONNECTION_FAILED':'proxy',NS_ERROR_NET_TIMEOUT:'timeout','net::ERR_TIMED_OUT':'timeout',NS_ERROR_UNKNOWN_HOST:'dns','net::ERR_NAME_NOT_RESOLVED':'dns'};
      return {network,slot:'failure',value:{at,kind:'transport',code:Object.hasOwn(codes,details.error)?codes[details.error]:'request'}};
    }
    if(!Number.isInteger(details.statusCode)||details.statusCode<100||details.statusCode>599)return null;
    const cached=!!details.fromCache,status=details.statusCode;
    return {network,slot:cached?'cached':status>=400?'failure':'response',value:{at,kind:cached?'cached':'http',status}};
  }
  function clean(input) {
    const out={};
    for(const n of networks)for(const slot of ['response','failure','cached']){
      const v=input?.[n]?.[slot];if(!v||typeof v.at!=='string'||!Number.isFinite(Date.parse(v.at)))continue;
      const fake={incognito:false,url:'https://'+(n==='TOR'?'fixture.onion':n==='I2P'?'fixture.i2p':'fixture.org'),statusCode:v.status,fromCache:slot==='cached'};
      const row=v.kind==='transport'&&slot==='failure'?{network:n,slot,value:{at:v.at,kind:'transport',code:['proxy','timeout','dns','request'].includes(v.code)?v.code:'request'}}:observation(fake,false,v.at);
      if(row&&row.slot===slot)(out[n]||={})[slot]=row.value;
    }return out;
  }
  function store(area) {
    let state={},pending={},loaded=false,loading=null,writing=false,dirty=false;
    function merge(target,row){const old=target[row.network]?.[row.slot];if(!old||old.at<=row.value.at)(target[row.network]||={})[row.slot]=row.value;}
    async function ready(){
      if(!loading)loading=(async()=>{try{state=clean(area?(await area.get('browserObservations')).browserObservations:{});}catch{}for(const n of networks)for(const [slot,value] of Object.entries(pending[n]||{}))merge(state,{network:n,slot,value});pending={};loaded=true;})();
      await loading;
    }
    async function flush(){
      if(writing)return;writing=true;
      try{await ready();while(dirty){dirty=false;if(area)await area.set({browserObservations:JSON.parse(JSON.stringify(state))});}}
      catch{ /* Live memory remains usable if session storage is unavailable. */ }
      finally{writing=false;}
    }
    return {record(row){if(!row)return;merge(loaded?state:pending,row);dirty=true;void flush();},async read(){await ready();return clean(state);}};
  }
  function age(at,now=Date.now()) {const t=Date.parse(at);if(!Number.isFinite(t))return 'time unknown';const s=Math.max(0,Math.floor((now-t)/1000));return (s<60?s+' seconds':Math.floor(s/60)+' minutes')+' ago';}
  function describe(v,now=Date.now()) {
    if(!v)return 'Not observed in this browser session.';
    const text=v.kind==='cached'?'Cached HTTP '+v.status+' — no fresh connection demonstrated':v.kind==='transport'?({proxy:'Proxy connection failed; network or destination cause unconfirmed',timeout:'Request timed out; cause unconfirmed',dns:'Browser reported name resolution failure',request:'Browser request failed; cause unconfirmed'}[v.code]||'Browser request failed'):v.status>=400?'HTTP '+v.status+' error response; source unconfirmed':'HTTP '+v.status+' response observed';
    return text+' · '+age(v.at,now)+'.';
  }
  function networkState(n) {
    if(!n)return 'No current observation.';
    if(n.code==='I2P_DEVICE_ON_DEMAND')return 'Device route is not listening; it starts on demand. Destination readiness is unknown.';
    if(n.readiness==='DISABLED')return 'Not enabled in this deployment.';
    const ready={READY:'Network readiness reported ready',NOT_READY:'Network not ready',UNKNOWN:'Network readiness unknown',UNAVAILABLE:'Network observation unavailable'}[n.readiness]||'Network readiness unknown';
    const listener=n.socks?({RESPONDING:'Listener responding. ',REFUSED:'Listener not listening. ',UNAVAILABLE:'Listener check unavailable. ',UNEXPECTED:'Listener returned an unexpected response. '}[n.socks.state]||'Listener status unknown. '):'';
    const traffic=n.destinationAccess==='OBSERVED_THIS_PROCESS'?' Traffic received earlier in this proxy process; not a current reachability check.':['NOT_OBSERVED','NOT_OBSERVED_THIS_PROCESS'].includes(n.destinationAccess)?' No destination traffic observed in this proxy process.':n.destinationAccess?' Past destination traffic unknown.':'';
    return listener+ready+(Number.isInteger(n.bootstrapPercent)?' · bootstrap '+n.bootstrapPercent+'%':'')+'.'+traffic;
  }
  function deviceState(d) {
    const messages={
      NOT_STARTED:'Not started. Opens on the next I2P request; your saved identity is retained.',
      WAITING:'Waiting for local activation. Leave the request open; other routes may be starting.',
      STARTING:'Starting or connecting. Leave the request open; a cold route can take minutes. If it fails, retry only when safe; a submitted action may already have reached its destination.',
      CONNECTIONS_OPEN:'Connections open. Silent connections keep your route running; this does not prove the next destination is reachable.',
      COOLDOWN:'Cooling down. No connections are held; the route will unload and retain your identity.',
      STOPPING:'Unloading the previous route. Any new request waits for removal before starting again.',
      DISABLED:'Disabled for this device. Ask the administrator to enable I2P; pairing again is unnecessary.',
      NOT_CONFIGURED:'Per-device lifecycle is not configured for this deployment.'
    };
    return messages[d?.state]||'Local lifecycle observation unavailable. Refresh observations; ask the administrator to inspect I2P if this persists. Do not restart or pair again just because status is unknown.';
  }
  function guidance(s) {
    if(s.problem)return {text:'Browser configuration could not be confirmed. Check the setup message before browsing.'};
    if(!s.paired)return {text:'Pair with the local manager to configure Stargate.',action:'pair',label:'Enter pairing code'};
    if(s.managerError==='PAIRING_REJECTED')return {text:'The manager rejected saved pairing. Create a new code in the manager, then pair again.',action:'pair',label:'Enter new pairing code'};
    if(s.browser==='FIREFOX_PRIVATE_PERMISSION_REQUIRED')return {text:'Allow Run in Private Windows for Stargate in about:addons, then Apply proxy. Regular windows are the supported use case.'};
    if(s.browser==='DNS_CONFLICT')return {text:'Another extension or policy controls Firefox speculation. Resolve the conflict before applying Stargate.'};
    if(s.browser==='DNS_UNAVAILABLE')return {text:'Firefox speculation controls could not be confirmed. Check Stargate permissions before browsing.'};
    if(s.browser==='DNS_NOT_APPLIED')return {text:'Firefox speculation restriction is not applied. Apply Stargate before browsing.',action:'apply',label:'Apply proxy'};
    if(s.browser==='WEBRTC_CONFLICT')return {text:'Another extension or policy controls WebRTC. Resolve the conflict before applying Stargate.'};
    if(s.browser==='WEBRTC_UNAVAILABLE')return {text:'WebRTC controls could not be confirmed. Check Stargate permissions before browsing.'};
    if(s.browser==='WEBRTC_NOT_APPLIED')return {text:'WebRTC restrictions are not applied. Close existing WebRTC tabs, then apply Stargate.',action:'apply',label:'Apply proxy'};
    if(s.browser==='PROXY_CONFLICT')return {text:'Another extension or policy controls proxy settings. Resolve that conflict first; Stargate will not overwrite it.'};
    if(['RELEASED','PROXY_CHANGED','PROXY_ENDPOINT_CHANGED'].includes(s.browser))return {text:'Stargate settings are not confirmed. Apply proxy explicitly to restore the configured endpoint.',action:'apply',label:'Apply proxy'};
    if(s.browser!=='APPLIED')return {text:'Browser proxy settings for regular windows are unknown. Refresh observations before browsing.'};
    if(!s.manager)return {text:'Manager observations are unavailable. Proxy settings remain applied for regular windows; this does not prove the proxy or networks are down.',action:'manager',label:'Open manager'};
    if(s.manager.process?.observation==='OBSERVED'&&s.manager.process.activeState!=='active')return {text:'The proxy process is not active. Open the manager to inspect it and use Start if appropriate.',action:'manager',label:'Open manager'};
    if(s.manager.proxy?.state==='REFUSED')return {text:'The configured proxy endpoint is not listening. Inspect the proxy in the manager.',action:'manager',label:'Open manager'};
    const unavailable=['tor','i2p','nym'].filter(k=>s.manager[k]?.readiness==='UNAVAILABLE');
    if(unavailable.length)return {text:unavailable.map(k=>({tor:'Tor',i2p:'I2P',nym:'Nym'}[k])).join(', ')+' has an unavailable network observation. Inspect the details in the manager. Network services are managed separately.',action:'manager',label:'Open manager'};
    return {text:'Proxy settings are applied for regular windows. If a page fails, compare the observations below; listener readiness and past responses do not establish current destination access.'};
  }
  const value={networks,privateContext,observation,clean,store,age,describe,networkState,deviceState,guidance};root.StargateObservations=value;if(typeof module==='object')module.exports=value;
})(globalThis);
