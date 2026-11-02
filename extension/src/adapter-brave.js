// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
'use strict';
var StargateAdapter={
  api:chrome,platform:'brave',
  get(){return chrome.proxy.settings.get({incognito:false});},
  privateAllowed(){return chrome.extension.isAllowedIncognitoAccess();},
  apply(proxy,localNetwork=false){return chrome.proxy.settings.set({value:StargateCore.configuration('brave',proxy,localNetwork),scope:'regular'});},
  clear(){return chrome.proxy.settings.clear({scope:'regular'});}
};
