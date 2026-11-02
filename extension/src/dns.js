// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
'use strict';
// Firefox PAC does not initially suppress page-initiated speculative DNS.
// This controls future speculation, not all DNS or requests already started.
var StargateDNS={
  setting(api){return api.privacy?.network?.networkPredictionEnabled;},
  async status(api,platform){
    if(platform!=='firefox')return {state:'BROWSER_MANAGED'};
    try {
      const setting=this.setting(api);if(!setting)return {state:'UNAVAILABLE'};
      const current=await setting.get({});
      const state=['not_controllable','controlled_by_other_extensions'].includes(current.levelOfControl)?'CONFLICT':
        current.levelOfControl==='controlled_by_this_extension' && current.value===false?'APPLIED':'NOT_APPLIED';
      return {state,enabled:current.value,levelOfControl:current.levelOfControl};
    }catch{return {state:'UNAVAILABLE'};}
  },
  async apply(api,platform){
    if(platform!=='firefox')return;
    const before=await this.status(api,platform);
    if(before.state==='UNAVAILABLE')throw Error('DNS_UNAVAILABLE');
    if(before.state==='CONFLICT')throw Error('DNS_CONFLICT');
    await this.setting(api).set({value:false});
    if((await this.status(api,platform)).state!=='APPLIED')throw Error('DNS_NOT_CONFIRMED');
  },
  async release(api,platform){
    if(platform!=='firefox')return;
    const setting=this.setting(api);if(!setting)return;
    if((await setting.get({})).levelOfControl==='controlled_by_this_extension')await setting.clear({});
  }
};
if(typeof module==='object')module.exports=StargateDNS;
