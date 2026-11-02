// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
const {test}=require('node:test'),assert=require('node:assert/strict'),P=require('../src/presentation.js');
test('saved access, applied settings, unavailable observations and idle I2P are distinct',()=>{
  assert.equal(P.view(null).icon,'unknown');
  assert.equal(P.view({paired:false}).icon,'setup');
  assert.equal(P.view({paired:false,browser:'SETTINGS_REMAIN'}).action,'reset');
  assert.equal(P.view({paired:true,browser:'RELEASED',levelOfControl:'controllable_by_this_extension',webrtc:{state:'NOT_APPLIED',levelOfControl:'controllable_by_this_extension'}}).icon,'off');
  assert.equal(P.view({paired:true,browser:'RELEASED',levelOfControl:'controllable_by_this_extension',webrtc:{state:'APPLIED',levelOfControl:'controlled_by_this_extension'}}).action,'release');
  assert.equal(P.releaseConfirmed({levelOfControl:'controllable_by_this_extension',webrtc:{state:'UNAVAILABLE'}}),false);
  assert.equal(P.view({paired:true,browser:'APPLIED',managerPending:true}).icon,'on');
  assert.equal(P.view({paired:true,browser:'APPLIED',manager:null}).icon,'attention');
  assert.equal(P.view({paired:true,browser:'APPLIED',manager:{i2p:{code:'I2P_DEVICE_ON_DEMAND',readiness:'UNKNOWN'}}}).icon,'on');
  assert.equal(P.view({paired:true,browser:'APPLIED',managerError:'PAIRING_REJECTED'}).action,'repair');
  assert.equal(P.view({privateContext:true,paired:true,browser:'APPLIED'}).icon,'attention');
  assert.equal(P.view({paired:true,browser:'DNS_CONFLICT'}).action,'help');
});
test('appearance is constrained to local presentation choices; malformed input has safe defaults',()=>{
  assert.deepEqual(P.preferences(),{theme:'stargate',motion:'system',advanced:false});
  assert.deepEqual(P.preferences({theme:'https://outside.invalid/theme',advanced:'yes',motion:'always'}),{theme:'stargate',motion:'system',advanced:false});
  for(const theme of P.themes)assert.equal(P.preferences({theme}).theme,theme,'Existing theme choices are preserved');
  assert.deepEqual(P.preferences({theme:'stargate',advanced:true,motion:'reduce',password:'not-an-appearance-field'}),{theme:'stargate',motion:'reduce',advanced:true});
});
test('manual disconnect depends on observed ownership, independently of the recovery action',()=>{
  for(const managerError of ['MANAGER_UNAVAILABLE','PAIRING_REJECTED']){
    const s={paired:true,browser:'APPLIED',levelOfControl:'controlled_by_this_extension',managerError};
    assert.notEqual(P.view(s).action,'release');assert.equal(P.ownsSettings(s),true);
  }
  assert.equal(P.ownsSettings({webrtc:{levelOfControl:'controlled_by_this_extension'}}),true);
  assert.equal(P.ownsSettings({platform:'firefox',dns:{levelOfControl:'controlled_by_this_extension'}}),true);
  for(const s of [null,{}, {levelOfControl:'controlled_by_other_extensions'},{levelOfControl:'unknown'},{privateContext:true,levelOfControl:'controlled_by_this_extension'}])assert.equal(P.ownsSettings(s),false);
});
test('completion copy distinguishes confirmed disconnect from incomplete release and setting outcomes',()=>{
  const off={levelOfControl:'controllable_by_this_extension',webrtc:{state:'NOT_APPLIED',levelOfControl:'controllable_by_this_extension'}};
  assert.match(P.resultText('release',{},off),/Stargate is off.*saved access is kept/);
  assert.doesNotMatch(P.resultText('release',{}, {...off,webrtc:{state:'UNAVAILABLE'}}),/Stargate is off/);
  assert.match(P.resultText('release',{}, {...off,webrtc:{state:'UNAVAILABLE'}}),/not fully confirmed/);
  assert.match(P.resultText('ipfs-gateway',{},{}),/IPFS gateway saved/);
  assert.match(P.resultText('local-network',{enabled:true},{localNetwork:{effective:null}}),/confirm browser settings/);
});
