// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
'use strict';
var StargateArt={html(icon,applied=false){
const c={active:applied,busy:icon==='working',mark:({on:'✓',off:'—',setup:'+',working:'…',attention:'!',unknown:'?'})[icon]||'?',attention:['attention','unknown'].includes(icon)};

    const engravings=Array.from({length:36},(_,i)=>`<span class="sg-art-detail sg-engraving" style="--angle:${i*10}deg"></span>`).join('');
    const chevrons=Array.from({length:7},(_,i)=>`<span class="sg-chevron" style="--angle:${i*360/7}deg"></span>`).join('');
    const stars=[[4,17,.6],[91,7,.9],[103,64,.5],[15,77,.8],[78,89,.55],[108,30,.45]].map(([x,y,opacity])=>`<span class="sg-art-detail sg-star" style="--star-x:${x}px;--star-y:${y}px;--star-opacity:${opacity}"></span>`).join('');
    return `<div class="sg-art ${c.active?'sg-on':''} ${c.busy?'sg-working':''}" aria-hidden="true">${stars}<span class="sg-art-detail sg-gate-bezel"></span><span class="sg-art-detail sg-saturn-rings"></span><span class="sg-orb"><span class="sg-art-detail sg-water"></span><span class="sg-art-detail sg-planet-shadow"></span></span><span class="sg-art-detail sg-gate-track"></span>${engravings}${chevrons}<span class="sg-art-detail sg-saturn-rings sg-rings-front"></span><span class="sg-status-mark ${c.attention?'sg-attention':!c.active?'sg-off-mark':''}">${c.mark}</span></div>`;

}};
if(typeof module==='object')module.exports=StargateArt;
