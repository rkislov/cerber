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
 for(const name of ['dialogs.js','attack.js','events.js'])vm.runInContext(fs.readFileSync(path.join(__dirname,'../static',name),'utf8'),ctx);
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
