// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
'use strict';
var StargateAdapter={
  api:browser,platform:'firefox',
  get(){return browser.proxy.settings.get({});},
  privateAllowed(){return browser.extension.isAllowedIncognitoAccess();},
  async apply(proxy,localNetwork=false){
    if(!await this.privateAllowed())throw Error('FIREFOX_PRIVATE_PERMISSION_REQUIRED');
    await browser.proxy.settings.set({value:StargateCore.configuration('firefox',proxy,localNetwork)});
  },
  clear(){return browser.proxy.settings.clear({});}
};
