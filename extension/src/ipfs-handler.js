// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
'use strict';
(() => {
  const api=globalThis.browser||globalThis.chrome,$=id=>document.getElementById(id);
  const errors={
    INVALID_IPFS_ADDRESS:'This IPFS address is invalid. Use ipfs:// followed by a supported CID and optional path.',
    INVALID_IPFS_CID:'This CID is invalid or unsupported. Use CIDv0 or base32 CIDv1 with raw/dag-pb and SHA-256.',
    INVALID_IPFS_GATEWAY:'Your saved gateway is invalid. Choose a valid HTTPS subdomain gateway in advanced settings.',
    IPFS_PROXY_NOT_APPLIED:'Connect Stargate and resolve browser-setting conflicts, then return here and try again.',
    IPFS_NYM_DISABLED:'Nym is not enabled on this server. Ask the person who runs it for help.',
    MANAGER_UNAVAILABLE:'Server status is unavailable. Stargate has kept your settings. Try again when status is available.',
    OPERATION_IN_PROGRESS:'Stargate is updating settings. Wait a moment, then try again.',
    PRIVATE_CONTEXT:'IPFS links are unsupported in private windows. Use a regular window.'
  };
  let address,busy=false,generation=0;
  function failed(code){$('ipfs-result').textContent=errors[code]||'Stargate could not confirm this connection. Check its settings before trying again.';}
  async function open(){
    if(busy)return;const own=++generation;busy=true;$('ipfs-retry').hidden=true;
    $('ipfs-result').textContent='Checking Stargate before opening your configured gateway…';
    try{
      const answer=await api.runtime.sendMessage({action:'ipfs-resolve',address});
      if(own!==generation)return;
      if(!answer?.ok){failed(answer?.code);return;}
      if(typeof answer.url!=='string'||!answer.url.startsWith('https://')){failed();return;}
      location.replace(answer.url);
    }catch{if(own===generation)failed();}
    finally{if(own===generation){busy=false;$('ipfs-retry').hidden=false;}}
  }
  $('extension-version').textContent='Version '+api.runtime.getManifest().version;
  // Clear the handoff URL before any asynchronous operation. Never persist or
  // log the input, and never let the browser's protocol choice bypass policy.
  function receive(){
    const fragment=location.hash;history.replaceState(null,'',location.pathname);
    ++generation;busy=false;$('ipfs-retry').hidden=true;
    if(api.extension.inIncognitoContext===true){failed('PRIVATE_CONTEXT');return;}
    try{address=StargateIpfs.protocolAddress(fragment);}catch{failed('INVALID_IPFS_ADDRESS');return;}
    void open();
  }
  void api.storage.local.get('appearance').then(value=>{
    const theme=StargatePresentation.preferences(value.appearance).theme;
    $('app').dataset.skin=theme;document.documentElement.style.colorScheme=theme==='clear'?'light':'dark';
    document.body.style.background=getComputedStyle($('app')).getPropertyValue('--sg-bg');
  }).catch(()=>{});
  $('ipfs-retry').addEventListener('click',()=>void open());window.addEventListener('hashchange',receive);receive();
})();
