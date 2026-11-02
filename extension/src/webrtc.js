// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
'use strict';
var StargateWebRTC={
  policy(platform){return platform==='firefox'?'proxy_only':'disable_non_proxied_udp';},
  setting(api){return api.privacy?.network?.webRTCIPHandlingPolicy;},
  async status(api,platform){
    try {
      const setting=this.setting(api);if(!setting)return {state:'UNAVAILABLE'};
      const current=await setting.get({});
      const state=['not_controllable','controlled_by_other_extensions'].includes(current.levelOfControl)?'CONFLICT':
        current.levelOfControl==='controlled_by_this_extension' && current.value===this.policy(platform)?'APPLIED':'NOT_APPLIED';
      return {state,policy:current.value,levelOfControl:current.levelOfControl};
    }catch{return {state:'UNAVAILABLE'};}
  },
  async apply(api,platform){
    const before=await this.status(api,platform);
    if(before.state==='UNAVAILABLE')throw Error('WEBRTC_UNAVAILABLE');
    if(before.state==='CONFLICT')throw Error('WEBRTC_CONFLICT');
    await this.setting(api).set({value:this.policy(platform),...(platform==='brave'?{scope:'regular'}:{})});
    if((await this.status(api,platform)).state!=='APPLIED')throw Error('WEBRTC_NOT_CONFIRMED');
  },
  async release(api){
    const setting=this.setting(api);if(!setting)return;
    if((await setting.get({})).levelOfControl==='controlled_by_this_extension')await setting.clear({});
  }
};
if(typeof module==='object')module.exports=StargateWebRTC;
