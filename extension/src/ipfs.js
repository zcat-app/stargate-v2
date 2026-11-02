// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
'use strict';
(function(root) {
  const DEFAULT_GATEWAY='https://ipfs.dget.top';
  const base32='abcdefghijklmnopqrstuvwxyz234567',base58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function encode32(bytes) {
    let bits=0,value=0,out='b';
    for(const byte of bytes){value=(value<<8)|byte;bits+=8;while(bits>=5){bits-=5;out+=base32[(value>>>bits)&31];}}
    if(bits)out+=base32[(value<<(5-bits))&31];return out;
  }
  function cid(input) {
    if(typeof input!=='string')throw Error('INVALID_IPFS_CID');
    let bytes=[];
    if(/^Qm[1-9A-HJ-NP-Za-km-z]{44}$/.test(input)) {
      let n=0n;for(const c of input)n=n*58n+BigInt(base58.indexOf(c));
      while(n){bytes.unshift(Number(n&255n));n>>=8n;}
      if(bytes.length!==34 || bytes[0]!==0x12 || bytes[1]!==0x20)throw Error('INVALID_IPFS_CID');
      bytes=[1,0x70,...bytes];
    } else if(/^b[a-z2-7]{58}$/.test(input)) {
      let bits=0,value=0;
      for(const c of input.slice(1)){value=(value<<5)|base32.indexOf(c);bits+=5;if(bits>=8){bits-=8;bytes.push((value>>>bits)&255);}}
      if(encode32(bytes)!==input)throw Error('INVALID_IPFS_CID');
    } else throw Error('INVALID_IPFS_CID');
    // Deliberately bounded support: CIDv0 dag-pb, CIDv1 raw/dag-pb, sha2-256.
    if(bytes.length!==36 || bytes[0]!==1 || ![0x55,0x70].includes(bytes[1]) || bytes[2]!==0x12 || bytes[3]!==0x20)
      throw Error('INVALID_IPFS_CID');
    return encode32(bytes);
  }
  function gateway(input) {
    if(typeof input!=='string' || input.length>300 || !/^https:\/\/[a-z0-9.-]+(?::[0-9]{1,5})?\/?$/i.test(input))throw Error('INVALID_IPFS_GATEWAY');
    let u;try{u=new URL(input);}catch{throw Error('INVALID_IPFS_GATEWAY');}
    if(u.protocol!=='https:' || u.username || u.password || u.search || u.hash || u.pathname!=='/' || u.port==='0')throw Error('INVALID_IPFS_GATEWAY');
    const h=u.hostname;
    if(!h.includes('.') || h.length>193 || !h.split('.').every(l=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l)) || !/^[a-z][a-z0-9-]*$/.test(h.split('.').at(-1)))throw Error('INVALID_IPFS_GATEWAY');
    for(const suffix of ['localhost','local','internal','home.arpa','invalid','test','example','onion','i2p'])
      if(h===suffix || h.endsWith('.'+suffix))throw Error('INVALID_IPFS_GATEWAY');
    return u.origin;
  }
  function url(input,configuredGateway) {
    if(typeof input!=='string' || input.length>4096 || /[\s\\\x00-\x1f\x7f]/.test(input))throw Error('INVALID_IPFS_ADDRESS');
    const match=/^(?:ipfs:\/\/)?([^/?#]+)(.*)$/.exec(input);
    if(!match)throw Error('INVALID_IPFS_ADDRESS');
    const canonical=cid(match[1]),g=new URL(gateway(configuredGateway)),tail=match[2];
    if(/%(?![0-9a-f]{2})/i.test(tail))throw Error('INVALID_IPFS_ADDRESS');
    // Concatenate after the fixed authority, never resolve a user-supplied URL.
    const result=new URL('https://'+canonical+'.'+g.host+(tail.startsWith('/')?tail:'/'+tail));
    if(result.hostname!==canonical+'.'+g.hostname || result.origin!=='https://'+canonical+'.'+g.host)throw Error('INVALID_IPFS_ADDRESS');
    return result.href;
  }
  function protocolAddress(fragment) {
    if(typeof fragment!=='string' || !fragment.startsWith('#') || fragment.length>12289)throw Error('INVALID_IPFS_ADDRESS');
    let address;try{address=decodeURIComponent(fragment.slice(1));}catch{throw Error('INVALID_IPFS_ADDRESS');}
    if(address.length>4096 || !/^ipfs:\/\//i.test(address))throw Error('INVALID_IPFS_ADDRESS');
    // Browser templates escape the entire URI. Decode once; preserve CID case
    // and percent-encoded path data for the existing validator.
    return address.replace(/^ipfs:/i,'ipfs:');
  }
  const value={DEFAULT_GATEWAY,cid,gateway,url,protocolAddress};root.StargateIpfs=value;
  if(typeof module==='object')module.exports=value;
})(globalThis);
