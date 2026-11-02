// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
'use strict';
var StargatePresentation = (() => {
  const themes = ['clear', 'stargate', 'observatory'];
  function preferences(value) {
    return {theme:themes.includes(value?.theme)?value.theme:'stargate',
      motion:value?.motion==='reduce'?'reduce':'system',advanced:value?.advanced===true};
  }
  function releaseConfirmed(s){
    const released=value=>['controllable_by_this_extension','controlled_by_other_extensions','not_controllable'].includes(value);
    return !!s&&!s.problem&&released(s.levelOfControl)&&s.webrtc?.state!=='UNAVAILABLE'&&released(s.webrtc?.levelOfControl)&&
      (s.platform!=='firefox'||(s.dns?.state!=='UNAVAILABLE'&&released(s.dns?.levelOfControl)));
  }
  function ownsSettings(s){
    return !!s&&!s.privateContext&&[s.levelOfControl,s.webrtc?.levelOfControl,
      s.platform==='firefox'?s.dns?.levelOfControl:null].includes('controlled_by_this_extension');
  }
  function resultText(action,values,s){
    if(action==='release')return releaseConfirmed(s)
      ?'Stargate is off. Your saved access is kept. New connections use your previous browser settings, which may connect directly.'
      :'Disconnect is not fully confirmed. Your saved access is kept. Check connection details.';
    if(action==='apply')return s?.browser==='APPLIED'?'Stargate is on. Browser settings are applied.':'Browser settings need attention. Check connection details.';
    if(action==='local-network')return s?.localNetwork?.effective===values.enabled
      ?(values.enabled?'Direct private-address access is on for this browser profile.':'Direct private-address access is off for this browser profile.')
      :'Local-network choice saved. Check connection details to confirm browser settings.';
    return {appearance:'Appearance saved.','ipfs-gateway':'IPFS gateway saved. New IPFS opens will use it.',
      'ipfs-open':'IPFS gateway opened in a new tab.','disconnect-forget':'Saved access removed from this browser. Server access has not been revoked.',
      manager:'Local manager opened in a new tab.','brave-settings':'Brave privacy settings opened in a new tab.'}[action]||'Check connection details for the result.';
  }
  function view(s) {
    const result=(icon,title,text,action,label)=>({icon,title,text,action,label});
    if(!s)return result('unknown','Status is unknown','The extension background is unavailable. Reopen Stargate to check again.','refresh','Check again');
    if(s.privateContext)return result('attention','Use a regular window','Private windows are unsupported. They may connect outside Stargate.','help','Connection limits');
    if(s.operation)return result('working','Updating browser settings…','You can close this popup. Reopen it to check the result.',null,'Working…');
    if(s.browser==='SETTINGS_REMAIN')return result('attention','Finish resetting Stargate','Saved access is missing, but Stargate settings remain in this browser.','reset','Review browser settings');
    if(s.problem)return result('unknown','Settings are not confirmed','Check the setup message before browsing. Saved access and settings have not been reset.','details','Connection details');
    if(!s.paired)return result('setup','Set up Stargate','Use one connection for the web, Tor and I2P. No account needed.','setup','I have an access code');
    if(s.managerError==='PAIRING_REJECTED')return result('attention','Access wasn’t accepted','Ask for a new code. Your settings are unchanged.','repair','Enter a new code');
    if(s.browser==='FIREFOX_PRIVATE_PERMISSION_REQUIRED')return result('attention','Access saved. Finish setup.','Firefox needs its “Run in Private Windows” permission to change proxy settings. Regular windows remain the supported use case.','setup','Finish setup');
    if(s.browser==='PROXY_CONFLICT'||s.browser?.endsWith('_CONFLICT'))return result('attention','Settings need attention','Another extension or browser policy controls a required setting. Stargate will not overwrite it.','help','How to fix this');
    if(['PROXY_CHANGED','PROXY_ENDPOINT_CHANGED','DNS_NOT_APPLIED','WEBRTC_NOT_APPLIED'].includes(s.browser))return result('attention','Settings need updating','Apply Stargate again after resolving the reported setting problem.','apply','Apply browser settings');
    if(s.browser==='RELEASED'&&!releaseConfirmed(s))return result('attention','Finish disconnecting','Proxy settings were released, but privacy-setting release is not confirmed. Your previous browser routing may connect directly.','release','Retry disconnect');
    if(s.browser==='RELEASED')return result('off','Stargate is off','Your previous browser connection may connect directly. Saved access is kept.','apply','Connect');
    if(s.browser!=='APPLIED')return result('unknown','Settings are not confirmed','Open connection details before browsing. Stargate has not switched to a different route.','details','Connection details');
    if(!s.manager&&(s.managerError||!s.managerPending))return result('attention','Settings are on','Server status is unavailable. Your browser settings stay on.','refresh','Refresh status');
    if(s.manager?.proxy?.state==='REFUSED'||(s.manager?.process?.observation==='OBSERVED'&&s.manager.process.activeState!=='active'))return result('attention','Stargate is having trouble','Keep settings on while the person who runs the server checks it. New requests do not switch to a direct route.','details','Connection details');
    if(['tor','i2p','nym'].some(k=>s.manager?.[k]?.readiness==='UNAVAILABLE'))return result('attention','One network needs attention','Each network has a separate observation. Other routes may still work.','details','Connection details');
    return result('on','Stargate is on','Browser settings applied.','release','Disconnect');
  }
  return {themes,preferences,view,releaseConfirmed,ownsSettings,resultText};
})();
if(typeof module==='object')module.exports=StargatePresentation;
