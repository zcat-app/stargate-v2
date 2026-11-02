// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
'use strict';
(() => {
  const api=globalThis.browser||globalThis.chrome,$=id=>document.getElementById(id),P=StargatePresentation,O=StargateObservations;
  const popup=new URLSearchParams(location.search).get('view')==='popup';
  const privateContext=api.extension.inIncognitoContext===true;
  const brave=api.runtime.getURL('').startsWith('chrome-extension://');
  const pages=['setup','settings','details','tools','help'];
  let current=null,prefs=P.preferences(),generation=0,busy=false,polling=false,initialized=false,gatewayLoaded=false;
  let page=location.hash==='#setup-repair'?'setup':pages.includes(location.hash.slice(1))?location.hash.slice(1):null,repairPairing=location.hash==='#setup-repair',primary=null,recovery=null,dialogAction=null,artKey='',observationsKey='';
  const errors={
    OPERATION_IN_PROGRESS:'Stargate is updating settings. Wait a moment, then try again.',
    INVALID_MANAGER_URL:'Use the HTTPS server address from your operator, or http://127.0.0.1:9080 for a local installation.',
    INVALID_PROXY_ENDPOINT:'Use the complete Stargate server address supplied by your operator.',
    INVALID_PAIRING_CODE:'Paste the complete one-time code supplied by your operator.',
    INVALID_OR_EXPIRED_PAIRING_CODE:'Code invalid, expired or already used. Ask the operator for a new code.',
    PAIRING_OUTCOME_UNKNOWN:'Pairing result unknown; the code may have been used. Ask the operator to check for an unused device, revoke it if identified, and send a new code. Existing pairing and proxy settings are kept.',
    PAIRING_REJECTED:'Saved access was not accepted. Ask the operator for a new access code.',
    DEVICE_STORE_FULL:'Device storage is full. Ask the operator to revoke an unused device, then create a new pairing code.',
    FIREFOX_PRIVATE_PERMISSION_REQUIRED:'Access saved. Allow “Run in Private Windows” for Stargate in about:addons, then apply browser settings. Use regular windows.',
    MANAGER_UNAVAILABLE:'Server observations are unavailable. Existing proxy settings are kept.',
    PROXY_CONFLICT:'Another extension or policy controls the proxy. Stargate did not overwrite it.',
    WEBRTC_CONFLICT:'Another extension or policy controls WebRTC. Resolve the conflict before applying Stargate.',
    WEBRTC_UNAVAILABLE:'WebRTC controls are unavailable. Check Stargate permissions before browsing.',
    WEBRTC_NOT_CONFIRMED:'WebRTC restriction could not be confirmed. Check connection details before browsing.',
    DNS_CONFLICT:'Another extension or policy controls Firefox speculation. Resolve the conflict before applying Stargate.',
    DNS_UNAVAILABLE:'Firefox speculation controls are unavailable. Check Stargate permissions.',
    DNS_NOT_CONFIRMED:'Firefox speculation restriction could not be confirmed. Check connection details before browsing.',
    PROXY_SETTING_NOT_CONFIRMED:'Browser settings could not be confirmed. Check saved and effective settings before browsing.',
    SETTINGS_RELEASE_NOT_CONFIRMED:'Some Stargate settings remain. Saved access was kept so you can retry safely.',
    INVALID_IPFS_CID:'Unsupported or invalid CID. Use CIDv0 or lowercase base32 CIDv1 with raw/dag-pb and SHA-256.',
    INVALID_IPFS_ADDRESS:'Enter a CID or ipfs://CID/path without spaces or backslashes.',
    INVALID_IPFS_GATEWAY:'Use an HTTPS subdomain gateway with a public DNS hostname and no path, credentials, query or fragment.',
    IPFS_PROXY_NOT_APPLIED:'Connect Stargate and resolve setting conflicts before opening IPFS.',
    IPFS_NYM_DISABLED:'Nym is not enabled in this Stargate deployment.',
    LOCAL_NETWORK_PROXY_NOT_APPLIED:'Connect Stargate and resolve proxy conflicts before changing direct private-address access.',
    ADMIN_ACCESS_IS_SEPARATE:'Ask the person who runs your server for help. Administration is separate from device access.'
  };
  const validationFields={
    'ipfs-open':{input:'ipfs-address',error:'ipfs-error',revision:0,codes:['INVALID_IPFS_CID','INVALID_IPFS_ADDRESS']},
    'ipfs-gateway':{input:'ipfs-gateway',error:'ipfs-gateway-error',revision:0,codes:['INVALID_IPFS_GATEWAY']}
  };
  function clearValidation(action){
    const v=validationFields[action];if(!v)return;
    $(v.input).removeAttribute('aria-invalid');$(v.error).hidden=true;$(v.error).textContent='';
  }
  const text=(id,value)=>{value=String(value??'Unknown');if($(id).textContent!==value)$(id).textContent=value;};
  const errorText=code=>errors[code]||'The change could not be completed. Check connection details before retrying.';
  function applyAppearance(value){
    prefs=P.preferences(value);$('app').dataset.skin=prefs.theme;document.body.dataset.theme=prefs.theme;
    $('app').classList.toggle('sg-animate',prefs.motion!=='reduce');
    document.querySelectorAll('button[data-theme]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.theme===prefs.theme)));
    $('motion').value=prefs.motion;$('advanced-mode').checked=prefs.advanced;$('advanced-settings').hidden=!prefs.advanced;
    const style=getComputedStyle($('app'));document.body.style.background=style.getPropertyValue('--sg-bg');
    document.documentElement.style.colorScheme=prefs.theme==='clear'?'light':'dark';
  }
  function showPage(value,focus=false){
    if(popup){void send('options',{page:value}).catch(()=>text('message','Could not open settings. Reopen Stargate to retry.'));return;}
    page=pages.includes(value)?value:'settings';
    if(page==='details')$('page-details').prepend($('overview'));
    $('overview').hidden=page!=='details';$('full-page').hidden=false;
    document.querySelectorAll('[data-panel]').forEach(p=>p.hidden=p.dataset.panel!==page);
    document.querySelectorAll('[data-nav]').forEach(b=>{if(b.closest('#page-nav')){if(b.dataset.nav===page)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');}});
    history.replaceState(null,'','#'+page);
    if(focus)$('page-'+page).querySelector('input:not([type="checkbox"]),button,select,summary')?.focus();
  }
  function focusSetupSummary(){if(!popup&&page==='setup'&&!$('setup-success').hidden)$('setup-summary-title').focus();}
  function ipfsSetup(){showPage('settings');$('ipfs-link-setup').scrollIntoView({block:'start'});$('ipfs-links-guidance').focus();}
  function setup(replace=false){
    repairPairing=replace;
    if(current?.managerOrigin&&!$('manager-url').value)$('manager-url').value=current.managerOrigin;
    if(popup){void send('options',{page:'setup',replace});return;}
    $('pair-form').hidden=!!current?.paired&&!repairPairing;$('setup-existing').hidden=!current?.paired||repairPairing||current?.browser==='APPLIED';
    $('setup-success').hidden=!current?.paired||repairPairing||current?.browser!=='APPLIED';
    showPage('setup',true);focusSetupSummary();
  }
  function eligibility(){
    document.querySelectorAll('[data-mutation],button[data-theme],#motion,#advanced-mode').forEach(b=>b.disabled=busy||privateContext);
    $('connection-action').disabled=busy||privateContext||!primary;
    $('disconnect-secondary').disabled=busy||privateContext||!!current?.operation;
    $('local-network-enable').disabled=busy||privateContext||current?.browser!=='APPLIED';
    $('local-network-disable').disabled=busy||privateContext||!current?.paired;
    $('forget-access').disabled=busy||privateContext||!current?.paired;
  }
  function render(s){
    current=s;const v=P.view(s);primary=v.action;
    applyAppearance(s?.appearance||prefs);
    text('connection-title',v.title);text('connection-description',v.text);text('connection-action',v.label||'Working…');
    $('disconnect-secondary').hidden=!P.ownsSettings(s)||['release','reset'].includes(v.action);
    const key=v.icon+':'+(s?.browser==='APPLIED');
    if(key!==artKey){$('connection-art').innerHTML=StargateArt.html(v.icon,s?.browser==='APPLIED');artKey=key;}
    $('server-identity').hidden=!s?.managerOrigin;text('server-name',s?.managerOrigin?new URL(s.managerOrigin).host:'');
    text('settings-server',s?.managerOrigin||'No server saved');text('pair-state',s?.paired?'Access saved for this browser.':'No access saved.');
    text('device-identity',s?.profileId?'Device identifier: '+s.profileId:'No saved device.');
    $('pair-form').hidden=!!s?.paired&&!repairPairing;$('setup-existing').hidden=!s?.paired||repairPairing||s?.browser==='APPLIED';
    $('setup-success').hidden=!s?.paired||repairPairing||s?.browser!=='APPLIED';
    $('need-access').hidden=!!s?.paired;$('connection-details').hidden=!s?.paired&&s?.browser!=='SETTINGS_REMAIN';
    const firefoxPermission=s?.platform==='firefox'&&!s.problem&&typeof s.privateAllowed==='boolean'?s.privateAllowed:null;
    text('firefox-preparation-state',firefoxPermission===true?'Permission confirmed for proxy settings. Use a regular window.':firefoxPermission===false?'Permission is not enabled yet. Follow the step below.':'Firefox permission is not confirmed. Reopen Stargate to check.');
    $('firefox-note').hidden=brave||firefoxPermission===true;
    text('setup-server',s?.managerOrigin||'Not confirmed');
    text('setup-preparation-state',brave?'Manual check: confirm both Brave Tor options are off.':firefoxPermission===true?'Firefox permission confirmed; use a regular window.':'Firefox permission is not confirmed.');
    if(!initialized){initialized=true;if(s?.managerOrigin&&!$('manager-url').value)$('manager-url').value=s.managerOrigin;if(!popup)showPage(page||(!s?'details':s.paired?'settings':'setup'));}
    const lan=s?.localNetwork,enabled=lan?.enabled===true,effective=lan?.effective;
    $('active-bypass').hidden=!enabled&&effective!==true;
    text('local-network-state','Saved choice: '+(typeof lan?.enabled==='boolean'?(enabled?'On':'Off'):'Unknown')+' · Browser bypass: '+(effective===true?'On':effective===false?'Off':'Unknown or not owned by Stargate')+(typeof effective==='boolean'&&enabled!==effective?' · Settings differ. Apply browser settings or disable direct access.':''));
    $('local-network-controls').hidden=!s?.paired;$('local-network-enable').hidden=enabled;$('local-network-disable').hidden=!enabled&&effective!==true;
    text('ipfs-selected-gateway',s?.ipfsGateway||'Not configured');if(!gatewayLoaded&&s?.ipfsGateway){$('ipfs-gateway').value=s.ipfsGateway;gatewayLoaded=true;}
    const labels={APPLIED:'Applied by Stargate · regular windows',RELEASED:'Released to previous browser settings',SETTINGS_REMAIN:'Stargate settings remain without saved access',UNPAIRED:'No access saved',PROXY_CHANGED:'Settings changed — not confirmed',PROXY_ENDPOINT_CHANGED:'Server endpoint changed — apply again',PROXY_CONFLICT:'Controlled by another extension or policy',FIREFOX_PRIVATE_PERMISSION_REQUIRED:'Firefox permission required',DNS_CONFLICT:'DNS speculation controlled elsewhere',DNS_UNAVAILABLE:'DNS speculation controls unavailable',DNS_NOT_APPLIED:'DNS speculation restriction not applied',WEBRTC_CONFLICT:'WebRTC setting controlled elsewhere',WEBRTC_UNAVAILABLE:'WebRTC controls unavailable',WEBRTC_NOT_APPLIED:'WebRTC restriction not applied',BROWSER_SETTINGS_UNAVAILABLE:'Browser settings unavailable'};
    text('browser-state',s?labels[s.browser]||s.browser:'Unknown');
    text('dns-state',s?.dns?.state==='APPLIED'?'Firefox speculation disabled':s?.dns?.state==='BROWSER_MANAGED'?'Managed by browser':s?.dns?.state==='CONFLICT'?'Controlled elsewhere':s?.dns?.state==='NOT_APPLIED'?'Not applied':'Unknown or unavailable');
    text('webrtc-state',s?.webrtc?.state==='APPLIED'?'Restricted for new connections':s?.webrtc?.state==='CONFLICT'?'Controlled elsewhere':s?.webrtc?.state==='NOT_APPLIED'?'Not applied':'Unknown or unavailable');
    text('manager-state',s?.manager?(s.managerCached?'Last observation available · refresh pending':'Available · see observation time'):s?.managerError==='PAIRING_REJECTED'?'Saved access rejected':s?.managerError?'Unknown or unavailable':s?.managerPending?'Not checked yet':'Unknown or unavailable');
    const m=s?.manager;text('process-state',m?.process?.observation==='OBSERVED'?m.process.activeState:'Unknown');
    text('endpoint-state',m?.proxy?.state==='RESPONDING'?'Responding'+(m.proxy.ownedByProcess?' · service owns listener':' · ownership unconfirmed'):m?.proxy?.state==='REFUSED'?'Not listening':'Unknown');
    for(const k of ['tor','i2p','nym'])text(k+'-state',O.networkState(m?.[k]));text('i2p-device-state',m?O.deviceState(m.i2pDevice):'No current observation.');
    text('auth-state',s?.auth?.lastAt?new Date(s.auth.lastAt).toLocaleTimeString()+' · credentials provided '+s.auth.provided+' · rejected '+s.auth.rejected:'Not observed in this session');
    text('freshness',m?'Server observed '+O.age(m.observedAt)+' ('+new Date(m.observedAt).toLocaleTimeString()+').':'No current server observation.');
    const observations=JSON.stringify(s?.browserObservations||{});
    if(observations!==observationsKey){observationsKey=observations;$('observations').replaceChildren();for(const n of O.networks){const h=document.createElement('h3');h.textContent={TOR:'Onion requests · Tor policy',I2P:'I2P requests · I2P policy',WEB:'Web requests · includes IPFS gateways and configured direct exceptions'}[n];const dl=document.createElement('dl');for(const [slot,label] of [['response','Last uncached response'],['failure','Last failure'],['cached','Last cached response']]){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.id='observation-'+n+'-'+slot;dd.textContent=O.describe(s?.browserObservations?.[n]?.[slot]);dl.append(dt,dd);}$('observations').append(h,dl);}}
    let help=s?O.guidance(s):{text:v.text};
    if(help.action==='manager'&&s?.managerOrigin?.startsWith('https:'))help={text:'Your Stargate settings are kept. Ask the person who runs this server to inspect it. Remote administration is separate.',action:'help',label:'Get server help'};
    if(s?.browser==='SETTINGS_REMAIN')help={text:v.text,action:'reset',label:'Review browser settings'};
    if(s?.browser==='RELEASED'&&v.action==='release')help={text:v.text,action:'release',label:v.label};
    text('guidance',help.text);recovery=help.action||null;$('recovery-action').hidden=!recovery;text('recovery-action',help.label||'');
    document.querySelector('[data-action="manager"]').hidden=!s?.paired||!s?.managerOrigin?.startsWith('http:');
    eligibility();
  }
  async function send(action,values={}){if(privateContext)throw Error('PRIVATE_CONTEXT');return api.runtime.sendMessage({action,...values});}
  async function refresh(){
    if(busy||polling||privateContext)return;polling=true;const own=++generation;
    try{
      if(!current){const local=await send('status-local');if(own===generation&&local.status)render(local.status);}
      const answer=await send('status');if(own===generation){if(answer.status)render(answer.status);if(!answer.ok)text('message',errorText(answer.code));}
    }catch{if(own===generation){render(null);text('message','Extension background unavailable. Current status is unknown. Reopen Stargate to retry.');}}
    finally{polling=false;}
  }
  async function act(action,values={}){
    if(busy||privateContext)return;clearValidation(action);const previousProfile=current?.profileId,initiator=document.activeElement,validationRevision=validationFields[action]?.revision;busy=true;generation++;eligibility();text('message','Working…');
    if(current&&['pair','apply','release','disconnect-forget','local-network'].includes(action))render({...current,operation:action});
    try{
      const answer=await send(action,values);
      if(answer.status)render(answer.status);
      if(action==='pair'){
        if(answer.status?.paired)$('code').value='';
        if(answer.ok){repairPairing=false;setup(false);text('message','Stargate settings applied. Use your normal address bar. Fully quit and reopen the browser before sensitive browsing: existing connections may keep their old route.');}
        else if(answer.status?.paired&&(!repairPairing||answer.status.profileId!==previousProfile)){
          repairPairing=false;render(answer.status);text('message','Access saved. '+errorText(answer.code));$('pair-error').hidden=true;
          Promise.resolve().then(()=>$('setup-existing').querySelector('button')?.focus());
        }else{const msg=errorText(answer.code);text('pair-error',msg);$('pair-error').hidden=false;text('message','');if(['INVALID_PAIRING_CODE','INVALID_OR_EXPIRED_PAIRING_CODE'].includes(answer.code))$('code').setAttribute('aria-invalid','true');$('code').focus();}
      }else if(!answer.ok&&validationFields[action]?.codes.includes(answer.code)){
        const v=validationFields[action];
        if(v.revision!==validationRevision)text('message','Your input changed. Submit it again to check it.');
        else{text('message','');text(v.error,errorText(answer.code));$(v.error).hidden=false;$(v.input).setAttribute('aria-invalid','true');$(v.input).focus();}
      }else text('message',answer.ok?P.resultText(action,values,answer.status):errorText(answer.code));
      if(answer.ok&&action==='ipfs-open'&&validationFields[action].revision===validationRevision)$('ipfs-address').value='';
      if(answer.ok&&action==='disconnect-forget')showPage('setup',true);
      if(answer.ok&&action==='apply'&&[document.body,document.documentElement,initiator].includes(document.activeElement))focusSetupSummary();
    }catch{render(null);text('message','The result could not be confirmed. Refresh status before retrying; existing settings may remain.');}
    finally{
      busy=false;eligibility();
      // Disabling a working control can move native keyboard focus to the body.
      // Restore it only when no error, navigation or user action chose a target.
      if(initiator?.isConnected&&!initiator.disabled&&initiator.getClientRects().length&&
        [document.body,document.documentElement].includes(document.activeElement))initiator.focus();
    }
  }
  function confirm(action){
    if(busy||privateContext)return;dialogAction=action;
    const lan=action==='local-network',forget=action==='disconnect-forget';
    text('confirmation-title',lan?'Allow direct local access?':forget?'Remove saved access?':'Disconnect Stargate?');
    text('confirmation-copy',lan?'Private IP addresses would connect directly, outside Stargate. This applies across this browser profile. Hostnames keep their current routing.':forget?'First restore your previous browser settings, then remove this browser’s saved access. This does not revoke access on the server.':'Your saved access is kept. You can connect again without another code. New connections will use your previous browser settings and may go directly.');
    text('confirmation-note','Existing connections can keep their previous route until closed. This does not stop the server.');
    text('confirmation-cancel',lan?'Keep direct access off':forget||!current?.paired?'Cancel':'Stay connected');text('confirmation-accept',lan?'Enable direct private addresses':forget?'Disconnect and forget':'Disconnect');
    $('confirmation').returnValue='cancel';$('confirmation').showModal();$('confirmation-cancel').focus();
  }
  function dispatch(action){
    if(action==='setup')setup(false);else if(action==='repair'||action==='pair')setup(action==='repair'||current?.paired===true);else if(action==='reset'||action==='release')confirm('release');
    else if(action==='help'||action==='details')showPage(action,true);else if(action==='refresh')void refresh();else if(action)void act(action);
  }
  text('extension-version','Version '+api.runtime.getManifest().version);
  $('firefox-ipfs-steps').hidden=brave;$('firefox-preparation').hidden=brave;$('brave-note').hidden=!brave;
  $('enable-ipfs-links').hidden=!brave||privateContext;
  if(brave)text('ipfs-links-guidance','Select Enable IPFS links, then Allow in the browser prompt. Keep this tab open until you have chosen. The browser manages approval; Stargate cannot confirm it from this page.');
  $('enable-ipfs-links').addEventListener('click',()=>{
    if(privateContext)return;
    try{
      navigator.registerProtocolHandler('ipfs',api.runtime.getURL('ipfs-handler.html')+'#%s');
      text('ipfs-links-guidance','Choose Allow in the browser prompt before entering an IPFS address. If no prompt appears, check IPFS handlers in brave://settings/handlers; the handler may already be allowed or blocked.');
    }catch{text('ipfs-links-guidance','The browser could not request IPFS handling. You can still use Stargate’s IPFS tool.');}
  });
  document.body.dataset.view=popup?'popup':'page';$('app').classList.toggle('sg-full',!popup);
  $('brave-private-warning').hidden=!brave;$('overview').hidden=!popup;$('full-page').hidden=popup;
  document.querySelectorAll('[data-nav]').forEach(b=>b.addEventListener('click',()=>showPage(b.dataset.nav,true)));
  document.querySelectorAll('[data-action]').forEach(b=>b.addEventListener('click',()=>void act(b.dataset.action)));
  $('settings-open').addEventListener('click',()=>showPage('settings',true));
  $('help-ipfs-setup').addEventListener('click',ipfsSetup);$('setup-ipfs').addEventListener('click',ipfsSetup);
  $('connection-action').addEventListener('click',()=>dispatch(primary));$('recovery-action').addEventListener('click',()=>dispatch(recovery));
  $('disconnect-secondary').addEventListener('click',()=>confirm('release'));
  $('refresh-status').addEventListener('click',()=>void refresh());$('help-setup').addEventListener('click',()=>setup(false));
  $('change-server').addEventListener('click',()=>setup(true));$('replace-access').addEventListener('click',()=>setup(true));
  $('local-install').addEventListener('click',()=>{$('manager-url').value='http://127.0.0.1:9080';$('manager-url').focus();});
  $('show-code').addEventListener('change',()=>{$('code').type=$('show-code').checked?'text':'password';});
  $('pair-form').addEventListener('submit',event=>{
    event.preventDefault();$('pair-error').hidden=true;$('manager-url').removeAttribute('aria-invalid');$('code').removeAttribute('aria-invalid');
    let origin;try{origin=StargateCore.managerOrigin($('manager-url').value.trim());}catch{text('pair-error',errors.INVALID_MANAGER_URL);$('pair-error').hidden=false;$('manager-url').setAttribute('aria-invalid','true');$('manager-url').focus();return;}
    text('origin-preview','Connecting this browser to '+origin+'.');void act('pair',{managerOrigin:origin,code:$('code').value});
  });
  for(const [action,v] of Object.entries(validationFields))$(v.input).addEventListener('input',()=>{v.revision++;clearValidation(action);});
  $('ipfs-form').addEventListener('submit',event=>{event.preventDefault();void act('ipfs-open',{address:$('ipfs-address').value.trim()});});
  $('ipfs-gateway-form').addEventListener('submit',event=>{event.preventDefault();void act('ipfs-gateway',{gateway:$('ipfs-gateway').value.trim()});});
  $('local-network-enable').addEventListener('click',()=>confirm('local-network'));$('local-network-disable').addEventListener('click',()=>void act('local-network',{enabled:false}));
  $('forget-access').addEventListener('click',()=>confirm('disconnect-forget'));$('brave-settings').addEventListener('click',()=>void act('brave-settings'));
  $('confirmation').addEventListener('keydown',event=>{
    if(event.key!=='Tab')return;
    const first=$('confirmation-cancel'),last=$('confirmation-accept');
    if(event.shiftKey&&event.target===first){event.preventDefault();last.focus();}
    else if(!event.shiftKey&&event.target===last){event.preventDefault();first.focus();}
  });
  $('confirmation').addEventListener('close',()=>{const action=dialogAction;dialogAction=null;if($('confirmation').returnValue==='accept'&&action)void act(action,action==='local-network'?{enabled:true}:{});});
  function savePreferences(value){if(busy||privateContext)return;void act('appearance',{value:{...prefs,...value}});}
  document.querySelectorAll('button[data-theme]').forEach(b=>b.addEventListener('click',()=>savePreferences({theme:b.dataset.theme})));
  $('motion').addEventListener('change',()=>savePreferences({motion:$('motion').value}));$('advanced-mode').addEventListener('change',()=>savePreferences({advanced:$('advanced-mode').checked}));
  api.storage.onChanged?.addListener((changes,area)=>{if(area==='local'&&changes.appearance)applyAppearance(changes.appearance.newValue);});
  if(privateContext){$('private-context-warning').hidden=false;render({privateContext:true});document.querySelectorAll('form input,form button,[data-mutation],#connection-action').forEach(b=>b.disabled=true);if(!popup)showPage('help');return;}
  applyAppearance(prefs);void refresh();setInterval(()=>{if(!document.hidden)void refresh();},3000);
})();
