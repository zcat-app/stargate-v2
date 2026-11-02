// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
// Adapted from v1 lib/storage.js: absent stored credentials stay absent.
'use strict';
var StargateStorage={
  async read(api){const data=await api.storage.local.get('pairing');return data.pairing;},
  async write(api,pairing){await api.storage.local.set({pairing});},
  async forget(api){await api.storage.local.remove('pairing');}
};
if(typeof module==='object')module.exports=StargateStorage;
