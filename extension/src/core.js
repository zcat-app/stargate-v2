// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
'use strict';
(function(root) {
  function managerOrigin(input) {
    if(typeof input!=='string')throw Error('INVALID_MANAGER_URL');
    let url;try { url=new URL(input); } catch { throw Error('INVALID_MANAGER_URL'); }
    if((url.protocol!=='https:' && !(url.protocol==='http:' && url.hostname==='127.0.0.1')) || url.username || url.password || url.search || url.hash || !['','/'].includes(url.pathname) || url.port==='0')throw Error('INVALID_MANAGER_URL');
    if(url.protocol==='https:')remoteHost(url.hostname);
    return url.origin;
  }
  function remoteHost(value) {
    if(typeof value!=='string' || value.length>253 || value!==value.toLowerCase() || !value.split('.').every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) || /\.(onion|i2p)$/.test(value))throw Error('INVALID_PROXY_ENDPOINT');
    return value;
  }
  function host(value) {
    if(value==='127.0.0.1')return value;
    try{if(new URL('http://['+String(value).replace(/^\[|\]$/g,'')+']:1').hostname==='[::1]')return '::1';}catch{}
    throw Error('INVALID_PROXY_ENDPOINT');
  }
  function endpoint(value) {
    if(!value || !Number.isInteger(value.port) || value.port<1 || value.port>65535)throw Error('INVALID_PROXY_ENDPOINT');
    if(value.scheme==='https') {
      const origin=managerOrigin(value.managerOrigin);
      if(!origin.startsWith('https:') || new URL(origin).hostname!==remoteHost(value.host))throw Error('INVALID_PROXY_ENDPOINT');
      return {scheme:'https',host:value.host,port:value.port,managerOrigin:origin};
    }
    if(value.scheme!==undefined && value.scheme!=='http')throw Error('INVALID_PROXY_ENDPOINT');
    return {host:host(value.host),port:value.port};
  }
  function responseEndpoint(origin,value) {
    origin=managerOrigin(origin);
    const proxy=endpoint({scheme:value?.proxyScheme,host:value?.proxyHost,port:value?.proxyPort,managerOrigin:origin});
    if(origin.startsWith('https:') !== (proxy.scheme==='https'))throw Error('INVALID_PROXY_ENDPOINT');
    return proxy;
  }
  function validatePairing(value) {
    if(!value || value.version!==1 || typeof value.profileId!=='string' || !/^[A-Za-z0-9_-]{1,64}$/.test(value.profileId) || value.username!==value.profileId || typeof value.password!=='string' || !/^[A-Za-z0-9_-]{32,128}$/.test(value.password) || typeof value.desired!=='boolean' || (value.localNetwork!==undefined && typeof value.localNetwork!=='boolean'))throw Error('INVALID_SAVED_PAIRING');
    const grant=typeof value.authorization==='string' && /^StargateProfile ([A-Za-z0-9_-]{1,64}):([A-Za-z0-9_-]{43})$/.exec(value.authorization);
    if(!grant || grant[1]!==value.profileId)throw Error('INVALID_SAVED_PAIRING');
    const origin=managerOrigin(value.managerOrigin),proxy=endpoint(value.proxy);
    if(origin.startsWith('https:') && (proxy.scheme!=='https' || proxy.managerOrigin!==origin))throw Error('INVALID_PROXY_ENDPOINT');
    if(!origin.startsWith('https:') && proxy.scheme==='https')throw Error('INVALID_PROXY_ENDPOINT');
    return {...value,managerOrigin:origin,proxy,localNetwork:value.localNetwork===true};
  }
  function fromRedeem(origin,value) {
    const c=value?.credentials;
    return validatePairing({version:1,managerOrigin:managerOrigin(origin),authorization:c?.authorization,profileId:c?.profileId,username:c?.username,password:c?.password,proxy:responseEndpoint(origin,value),desired:true});
  }
  const bypass=['127.0.0.1','localhost'];
  function authority(proxy) { return (proxy.host.includes(':')?'['+proxy.host+']':proxy.host)+':'+proxy.port; }
  const privateRanges=['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'];
  // No DNS: accept dotted IPv4 or its equivalent IPv4-mapped IPv6 literal.
  // This mirrors the CIDR matching used by Firefox and Chromium manual settings.
  function privateLiteral(host) {
    if(typeof host!=='string')return false;
    let value=host.toLowerCase();
    if(value[0]==='[' && value[value.length-1]===']'){if(!value.includes(':'))return false;value=value.slice(1,-1);}
    if(value.includes(':')) {
      const dotted=value.match(/(?:^|:)([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$/);
      if(dotted){
        const bytes=dotted[1].split('.');
        if(bytes.some(b=>! /^(0|[1-9][0-9]{0,2})$/.test(b) || +b>255))return false;
        value=value.slice(0,-dotted[1].length)+((+bytes[0]*256)+ +bytes[1]).toString(16)+':'+((+bytes[2]*256)+ +bytes[3]).toString(16);
      }
      if(!/^[0-9a-f:]+$/.test(value) || value.split('::').length>2)return false;
      const halves=value.split('::'),left=halves[0]?halves[0].split(':'):[],right=halves.length===2 && halves[1]?halves[1].split(':'):[];
      if([...left,...right].some(v=>! /^[0-9a-f]{1,4}$/.test(v)))return false;
      const missing=8-left.length-right.length;
      if(halves.length===1 ? left.length!==8 : missing<1)return false;
      const words=halves.length===1?left:[...left,...Array(missing).fill('0'),...right];
      if(words.slice(0,5).some(v=>parseInt(v,16)!==0) || parseInt(words[5],16)!==65535)return false;
      const hi=parseInt(words[6],16),lo=parseInt(words[7],16);
      value=[hi>>>8,hi&255,lo>>>8,lo&255].join('.');
    }
    if(!/^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/.test(value))return false;
    const bytes=value.split('.').map(Number);
    return bytes.every(b=>b<=255) && (bytes[0]===10 || (bytes[0]===172 && bytes[1]>=16 && bytes[1]<=31) || (bytes[0]===192 && bytes[1]===168));
  }
  function localNetworkChoice(value){if(typeof value!=='boolean')throw Error('INVALID_LOCAL_NETWORK_CHOICE');return value;}
  function remotePac(proxy,localNetwork) {
    // Embedded deterministic PAC: no network fetch, DNS helper or DIRECT fallback.
    return (localNetwork?'var privateLiteral='+privateLiteral.toString()+';':'')+'function FindProxyForURL(url,host){'+(localNetwork?'if(privateLiteral(host))return "DIRECT";':'')+'if(host==="127.0.0.1"||host==="localhost"||host==="::1"||host==="[::1]"||url.indexOf('+JSON.stringify(proxy.managerOrigin+'/')+')===0)return "DIRECT";return '+JSON.stringify('HTTPS '+authority(proxy))+';}';
  }
  function configuration(platform,proxy,localNetwork=false) {
    proxy=endpoint(proxy);localNetworkChoice(localNetwork);
    const exceptions=[...bypass,...(localNetwork?privateRanges:[])];
    if(proxy.scheme==='https')return platform==='firefox'
      ? {proxyType:'autoConfig',autoConfigUrl:'data:application/x-ns-proxy-autoconfig,'+encodeURIComponent(remotePac(proxy,localNetwork)),passthrough:''}
      : {mode:'fixed_servers',rules:{singleProxy:{scheme:'https',host:proxy.host,port:proxy.port},bypassList:[...exceptions,proxy.managerOrigin+(new URL(proxy.managerOrigin).port?'':':443')]}};
    return platform==='firefox' ? {proxyType:'manual',http:authority(proxy),ssl:authority(proxy),httpProxyAll:false,passthrough:exceptions.join(','),proxyDNS:true}
      : {mode:'fixed_servers',rules:{singleProxy:{scheme:'http',host:proxy.host,port:proxy.port},bypassList:exceptions}};
  }
  function sameBypass(value,expected) { return Array.isArray(value) && value.every(s=>typeof s==='string') && JSON.stringify(value.map(s=>s.trim()).sort())===JSON.stringify([...expected].sort()); }
  function matches(platform,setting,proxy,localNetwork=false) {
    try {
      proxy=endpoint(proxy);const value=setting.value,expected=configuration(platform,proxy,localNetwork);
      if(proxy.scheme==='https') {
        if(platform==='firefox')return value.proxyType==='autoConfig' && value.autoConfigUrl===expected.autoConfigUrl && value.passthrough==='';
        const rules=value.rules,single=rules?.singleProxy;
        return value.mode==='fixed_servers' && single?.scheme==='https' && single.host===proxy.host && single.port===proxy.port
          && Object.keys(single).every(k=>['scheme','host','port'].includes(k)) && Object.keys(rules).every(k=>['singleProxy','bypassList'].includes(k))
          && Array.isArray(rules.bypassList) && JSON.stringify([...rules.bypassList].sort())===JSON.stringify([...expected.rules.bypassList].sort());
      }
      if(platform==='firefox')return value.proxyType==='manual' && value.http===authority(proxy) && value.ssl===authority(proxy) && !value.socks && sameBypass((value.passthrough || '').split(','),expected.passthrough.split(','));
      const rules=value.rules,single=rules?.singleProxy;
      return value.mode==='fixed_servers' && single?.scheme==='http' && host(single.host)===host(proxy.host) && single.port===proxy.port && sameBypass(rules.bypassList,expected.rules.bypassList) && Object.keys(rules).every(key=>['singleProxy','bypassList'].includes(key));
    } catch { return false; }
  }
  function browserState(platform,setting,pairing,privateAllowed) {
    if(!pairing)return 'UNPAIRED';
    if(!setting || privateAllowed===undefined)return 'BROWSER_SETTINGS_UNAVAILABLE';
    if(platform==='firefox' && !privateAllowed)return 'FIREFOX_PRIVATE_PERMISSION_REQUIRED';
    if(['controlled_by_other_extensions','not_controllable'].includes(setting?.levelOfControl))return 'PROXY_CONFLICT';
    if(setting?.levelOfControl==='controlled_by_this_extension' && matches(platform,setting,pairing.proxy,pairing.localNetwork))return 'APPLIED';
    return pairing.desired ? 'PROXY_CHANGED' : 'RELEASED';
  }
  function authDecision(pairing,details,attempts) {
    if(!pairing || !details.isProxy || details.realm!=='Stargate' || details.scheme?.toLowerCase()!=='basic')return 'ignore';
    try{const normalize=pairing.proxy.scheme==='https'?remoteHost:host;if(normalize(details.challenger?.host)!==normalize(pairing.proxy.host) || details.challenger.port!==pairing.proxy.port)return 'ignore';}catch{return 'ignore';}
    if(pairing.proxy.scheme==='https' && (!pairing.desired || (details.proxyInfo && (details.proxyInfo.type!=='https' || details.proxyInfo.host!==pairing.proxy.host || details.proxyInfo.port!==pairing.proxy.port))))return 'cancel';
    return details.incognito || attempts>0 ? 'cancel' : 'credentials';
  }
  const core={privateLiteral,localNetworkChoice,managerOrigin,endpoint,responseEndpoint,validatePairing,fromRedeem,configuration,matches,browserState,authDecision};
  root.StargateCore=core;if(typeof module==='object')module.exports=core;
})(globalThis);
