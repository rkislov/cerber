const {test}=require('node:test');const assert=require('node:assert/strict');const vm=require('node:vm');const fs=require('node:fs');const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../static/chain-graph.js'),'utf8');
const id=n=>n.toString(16).padStart(64,'0');
function step(n,host='a'){return {event_id:id(n),agent_id:'agent-'+host,asset_id:'asset-'+host,at:new Date(1700000000000+n*1000).toISOString(),user:'lab\\alice',action:'logon',identity:{computer:'host-'+host,account_sid:'S-1-5-21-1-2-3-1001',local_session:'0x123'}}}
function detection(steps,links=[]){return {id:id(999),rule:'chain.domain_account_hosts',policy:{revision:2},chain:{version:1,steps,links,truncated:false}}}
function model(anchors,extra={}){const ctx=vm.createContext({});vm.runInContext(source,ctx);return ctx.chainGraphModel({anchors,...extra});}
test('graph merges shared source events, keeps explicit typed links and scopes local sessions to hosts',()=>{
 const a=step(1),b=step(2,'b'),link={from:a.event_id,to:b.event_id,kind:'domain_sid',basis:'same SID'};
 const reordered={...a,identity:{local_session:'0x123',account_sid:a.identity.account_sid,computer:'host-a'}};
 const m=model([detection([a,b],[link]),detection([reordered,b],[link])]);
 assert.equal(m.events.length,2);assert.equal(m.links.length,1);assert.equal(m.hosts.length,2);assert.equal(m.accounts,1);assert.equal(m.sessions,2);assert.equal(m.conflicts,0);
 assert.equal(model([detection([a,b])]).links.length,0,'shared SID must not fabricate an edge');
});
test('SSH credential does not merge local user accounts; absent session is not inferred',()=>{
 const a=step(1),b=step(2,'b');for(const n of [a,b]){n.user='root';n.identity={ssh_key:'SHA256:shared',computer:n.agent_id}}
 const m=model([detection([a,b])]);assert.equal(m.accounts,2);assert.equal(m.sessions,0);assert.equal(m.links.length,0);
});
test('conflicting snapshots and orphan endpoints never produce misleading edges',()=>{
 const a=step(1),b=step(2,'b');const conflicting={...a,asset_id:'foreign-asset'};
 const m=model([detection([a,b],[{from:a.event_id,to:b.event_id,kind:'domain_sid',basis:'saved'}]),detection([conflicting])]);
 assert.equal(m.conflicts,1);assert.equal(m.events.length,1);assert.equal(m.links.length,0);assert.equal(m.truncated,true);
 const cross=model([detection([a],[{from:a.event_id,to:b.event_id,kind:'ssh_key',basis:'orphan'}]),detection([b])]);assert.equal(cross.links.length,0);
});
test('graph enforces host/event bounds and preserves source truncation and empty cases',()=>{
 const many=[];for(let d=0;d<20;d++){const steps=[];for(let n=0;n<21;n++)steps.push(step(d*21+n+1,'host-'+d));many.push(detection(steps))}
 const m=model(many);assert.equal(m.events.length,80);assert.ok(m.hosts.length<=20);assert.equal(m.truncated,true);
 const hosts=model([detection(Array.from({length:21},(_,n)=>step(n+1,String(n))))]);assert.equal(hosts.hosts.length,20);assert.equal(hosts.truncated,true);
 assert.equal(model([],{truncated:true}).truncated,true);assert.equal(model([{id:id(1)}]).events.length,0);
});
function renderSetup(){
 class Node {constructor(tag='div',cls='',text=''){this.tag=tag;this.children=[];this.handlers={};this.attrs={};this.dataset={};this.style={};this.textContent=text;this.clientWidth=900;this.clientHeight=540;const classes=new Set(cls.split(' ').filter(Boolean));this.classList={toggle:(k,value)=>{const on=value===undefined?!classes.has(k):value;on?classes.add(k):classes.delete(k);return on},contains:k=>classes.has(k)}}setAttribute(k,v){this.attrs[k]=String(v);if(k==='id')this.id=v}append(...nodes){this.children.push(...nodes)}replaceChildren(...nodes){this.children=nodes}addEventListener(k,f){this.handlers[k]=f}}
 const opened=[];const ctx=vm.createContext({document:{createElementNS:(_,tag)=>new Node(tag)},el:(tag,cls,text)=>new Node(tag,cls,text),date:String,short:s=>String(s).slice(0,12),showRaw:id=>opened.push(id)});vm.runInContext(source,ctx);
 return {ctx,opened,root:new Node(),all(root){return [root,...root.children.flatMap(n=>typeof n==='object'?this.all(n):[])]}};
}
test('SVG and list controls select event/session details and open the correct source',()=>{
 const s=renderSetup(),a=step(1),b=step(2,'b');s.ctx.renderChainGraph(s.root,model([detection([a,b],[{from:a.event_id,to:b.event_id,kind:'domain_sid',basis:'explicit SID'}])]));
 let nodes=s.all(s.root),event=nodes.find(n=>n.attrs.role==='button'&&n.attrs['aria-label']?.startsWith('2.'));
 assert.ok(event);event.handlers.keydown({key:'Enter',preventDefault(){}});
 nodes=s.all(s.root);const open=nodes.find(n=>n.tag==='button'&&n.textContent==='Открыть исходное событие →');open.handlers.click();assert.deepEqual(s.opened,[b.event_id]);
 const edge=nodes.find(n=>n.attrs.role==='button'&&n.attrs['aria-label']?.startsWith('Общий SID:'));edge.handlers.click();assert.ok(s.all(s.root).some(n=>n.textContent==='explicit SID'));
 const zoom=nodes.find(n=>n.attrs['aria-label']==='Увеличить масштаб графа');zoom.handlers.click();
 const list=nodes.find(n=>n.textContent==='Список событий');list.handlers.click();assert.equal(list.attrs['aria-expanded'],'true');
});

test('closing during graph load does not render a hidden zero-width graph; reopening retries',async()=>{
 const s=renderSetup();s.ctx.state={csrf:'session'};s.ctx.URLSearchParams=URLSearchParams;
 let finish;let requests=0;s.ctx.api=()=>{requests++;return new Promise(resolve=>{finish=resolve})};
 s.ctx.chainGraphLauncher(s.root,{incident:id(7)});
 const detail=s.root.children[0];detail.isConnected=true;detail.open=true;detail.handlers.toggle();detail.open=false;finish({context:{anchors:[]}});
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(detail.children[1].children[0].textContent,'Загрузка сохранённых цепочек инцидента…');
 detail.open=true;detail.handlers.toggle();assert.equal(requests,2);finish({context:{anchors:[],at:'2026-10-29',incident_version:1}});
 await new Promise(resolve=>setImmediate(resolve));
 assert.ok(s.all(s.root).some(n=>n.textContent.includes('пока нет сохранённой межузловой цепочки')));
});
