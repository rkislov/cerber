const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const path=require('node:path');
function setup(){
 const nodes=new Map();
 function node(){return {open:false,children:[],handlers:{},scrollTop:99,addEventListener(k,f){this.handlers[k]=f},append(...v){this.children.push(...v)},replaceChildren(...v){this.children=v},showModal(){this.open=true},close(){this.open=false},getBoundingClientRect(){return {left:100,right:600,top:100,bottom:500}}}}
 const $=id=>{if(!nodes.has(id))nodes.set(id,node());return nodes.get(id)};
 const errors=[];
 const document={getElementById:$,querySelectorAll:()=>[]};
 const ctx=vm.createContext({document,$,el:()=>node(),api:async()=>({title:'ThreatFox',id:'threatfox.ip_match',version:1,false_positives:null,investigation:null,references:null}),date:String,short:String,error:e=>errors.push(e),URL});
 for(const name of ['dialogs.js','attack.js','events.js','investigation.js'])vm.runInContext(fs.readFileSync(path.join(__dirname,'../static',name),'utf8'),ctx);
 return {$,ctx,errors};
}
test('ThreatFox rule with absent optional lists opens repeatedly and switches inspector layers',async()=>{
 const {$,ctx,errors}=setup();
 for(let i=0;i<3;i++){
  await vm.runInContext('showRule({rule:"threatfox.ip_match",version:1,agent_id:"a",evidence:["e"]})',ctx);
  assert.equal($('rule-dialog').open,true);assert.deepEqual(errors,[]);
  vm.runInContext('showAttack(null,"IOC")',ctx);
  assert.equal($('rule-dialog').open,false);assert.equal($('attack-dialog').open,true);
  $('attack-close').handlers.click();assert.equal($('attack-dialog').open,false);
  await vm.runInContext('showRaw("e")',ctx);
  assert.equal($('raw-dialog').open,true);
  $('raw-close').handlers.click();assert.equal($('raw-dialog').open,false);
 }
});
test('backdrop closes inspector without treating content clicks or drags as dismissal',()=>{
 const {$,ctx}=setup();const d=$('attack-dialog');
 const outside={target:d,clientX:10,clientY:10};const inside={target:d,clientX:200,clientY:200};
 vm.runInContext('openInspection("attack-dialog")',ctx);
 d.handlers.pointerdown(inside);d.handlers.click(outside);assert.equal(d.open,true);
 d.handlers.pointerdown(inside);d.handlers.click(inside);assert.equal(d.open,true);
 d.handlers.pointerdown(outside);d.handlers.click(outside);assert.equal(d.open,false);
});

test('saved cross-host chain renders in the rule inspector and opens its source',async()=>{
 const {$,ctx,errors}=setup();
 const chain={version:1,hosts:2,limitations:'Source identifiers; not proof of causation',steps:[{event_id:'first',agent_id:'node-a',asset_id:'asset-a',at:'2026-10-29',user:'lab\\alice',action:'logon',identity:{account_sid:'S-1-5-21-1-2-3-1000'}},{event_id:'second',agent_id:'node-b',asset_id:'asset-b',at:'2026-10-29',user:'lab\\alice',action:'logon',identity:{account_sid:'S-1-5-21-1-2-3-1000'}}],links:[{from:'first',to:'second',kind:'domain_sid',basis:'same SID'}]};
 ctx.fixtureChain=chain;
 await vm.runInContext('showRule({rule:"chain.domain_account_hosts",version:1,agent_id:"node-b",evidence:["first","second"],chain:fixtureChain})',ctx);
 assert.equal($('rule-dialog').open,true);assert.deepEqual(errors,[]);
 // The first paragraph is followed by the saved chain details and its timeline.
 const detail=$('rule-description').children[1],timeline=detail.children[2];
 assert.equal(timeline.children.length,2);
 await timeline.children[0].children.at(-1).handlers.click();
 assert.equal($('raw-dialog').open,true);assert.equal($('rule-dialog').open,false);assert.deepEqual(errors,[]);
 $('raw-close').handlers.click();assert.equal($('raw-dialog').open,false);
});
