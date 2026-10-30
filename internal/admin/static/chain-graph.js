"use strict";
function chainStepTitle(step){return {process_created:"Запуск процесса",service_installed:"Установка службы",task_created:"Создание задания",explicit_credentials:"Попытка использования реквизитов",kerberos_service_ticket:step.outcome==="failure"?"Kerberos: отказ":step.outcome==="success"?"Kerberos: запрос успешен":"Запрос Kerberos-билета",log_cleared:"Очистка аудита",logon:"Успешный вход"}[step.action]||"Событие";}
function chainWindowsSourceFacts(step){const w=step.windows_auth||{};return [["Целевые реквизиты / пользователь билета",w.target_account],["TargetLogonGuid реквизитов",w.target_guid],["Запрошенная служба",w.service],["SID службы (не пользователя)",w.service_sid],["Статус Kerberos",w.status],["Тип шифрования билета",w.encryption],["Сервер из 4648",w.target_server],["Процесс инициатора",w.process],["PID процесса",w.process_id]].filter(([,v])=>v);}
function chainWindowsFacts(step){
 const states={verified:"Подтверждена",pending:"Ожидает проверки",unavailable:"Каталог недоступен",unresolved:"Не подтверждена",unsupported:"Неподдерживаемая запись",foreign_domain:"Другой домен",not_found:"Не найдена",ambiguous:"Неоднозначное имя",mismatch:"Конфликт атрибутов",sid_mismatch:"SID не совпадает",disabled:"Отключена",locked:"Заблокирована",expired:"Срок действия истёк"};
 const observations=step.directory_observations||[{role:"Учётная запись / инициатор",proof:step.identity?.directory},{role:"Целевые реквизиты / билет",proof:step.windows_auth?.directory}];
 const w=step.windows_activity||{};const out=chainWindowsSourceFacts(step);for(const [k,v]of [["Процесс",w.process],["PID",w.process_id],["Родитель",w.parent],["PID родителя",w.parent_id],["Командная строка",w.command_line],["Служба / задание",w.name],["Исполняемый файл службы",w.image],["Учётка запуска (не инициатор)",w.run_as],["Целевой SID процесса",w.target_sid]])if(v)out.push([k,v]);for(const {role,proof:p}of observations){if(!p)continue;out.push(["AD · "+role,states[p.state]||p.state]);if(p.checked_at&&Date.parse(p.checked_at)>0)out.push(["Проверено в каталоге",p.checked_at]);if(p.dns)out.push(["DNS / NetBIOS",p.dns+" / "+p.netbios]);if(p.sid)out.push(["SID из AD",p.sid]);if(p.object_guid)out.push(["objectGUID из AD",p.object_guid]);if(p.sam)out.push(["sAMAccountName / UPN",p.sam+" / "+(p.upn||"—")]);}
 return out;
}
function chainEdgeTitle(kind){return {service_confirmation:"Запись установки службы",session_activity:"Действие в сеансе",domain_sid:"Общий SID",logon_guid:"SID + Logon GUID",ssh_key:"Общий SSH-ключ",local_session:"Один локальный сеанс",actor_local_session:"Сеанс инициатора",kerberos_guid:"Kerberos GUID + учётка",explicit_target_guid:"Target GUID + учётка",credential_ticket_guid:"Реквизиты → билет"}[kind]||"Сохранённая связь";}


// Display only immutable links saved by the correlator. Shared names, IPs or
// local session numbers never manufacture new cross-host edges in the browser.
function chainGraphModel(context) {
  const events = new Map(), links = new Map(), conflicts = new Set();
  const limits = {events:80, links:200, hosts:20};
  let truncated = !!context.truncated, savedChains = 0;
  const hostKey = step => JSON.stringify([step.agent_id,step.asset_id]);
  const facts = step => JSON.stringify([step.agent_id,step.asset_id,step.at,step.user,step.action,step.source_ip||"",JSON.stringify(chainWindowsSourceFacts(step)),...["account_key","account_sid","realm","session_guid","local_session","ssh_key","computer","logon_type"].map(k=>step.identity?.[k]||"")]);
  for (const detection of context.anchors || []) {
    const chain = detection.chain;
    if (!chain || ![1,2].includes(chain.version)) continue;
    savedChains++;
    truncated = truncated || !!chain.truncated;
    const membership = new Set();
    for (const step of (chain.steps || []).slice(0,21)) {
      if (!/^[a-f0-9]{64}$/.test(step.event_id) || !step.agent_id || !step.asset_id || !Number.isFinite(Date.parse(step.at))) continue;
      membership.add(step.event_id);
      const previous = events.get(step.event_id);
      if (previous && (previous.facts !== facts(step)||previous.code&&step.code&&previous.code!==step.code||previous.outcome&&step.outcome&&previous.outcome!==step.outcome)) {conflicts.add(step.event_id);continue;}
      if (!previous) events.set(step.event_id,{...step,hostKey:hostKey(step),facts:facts(step),detections:[],directory_observations:[]});
      const observations=events.get(step.event_id).directory_observations;for(const [role,proof]of [["Учётная запись / инициатор",step.identity?.directory],["Целевые реквизиты / билет",step.windows_auth?.directory]]){if(proof&&!observations.some(o=>JSON.stringify(o)===JSON.stringify({role,proof})))observations.push({role,proof});}
      events.get(step.event_id).code ||= step.code;events.get(step.event_id).outcome ||= step.outcome;
      events.get(step.event_id).detections.push({id:detection.id,rule:detection.rule,revision:detection.policy?.revision||0});
    }
    for (const link of (chain.links || []).slice(0,20)) {
      if (!membership.has(link.from) || !membership.has(link.to) || link.from === link.to) continue;
      const key = JSON.stringify([link.from,link.to,link.kind]);
      if (!links.has(key)) links.set(key,{...link,key,bases:[],detections:[]});
      const item = links.get(key);
      if (!item.bases.includes(link.basis)) item.bases.push(link.basis);
      if (!item.detections.includes(detection.id)) item.detections.push(detection.id);
    }
  }
  const hosts = new Map(), included = [];
  // Deterministic chronological order; the latest omitted events remain explicit.
  for (const event of [...events.values()].sort((a,b)=>Date.parse(a.at)-Date.parse(b.at)||a.event_id.localeCompare(b.event_id))) {
    if (conflicts.has(event.event_id)) continue;
    if (included.length >= limits.events || !hosts.has(event.hostKey) && hosts.size >= limits.hosts) {truncated=true;continue;}
    if (!hosts.has(event.hostKey)) hosts.set(event.hostKey,{key:event.hostKey,agent_id:event.agent_id,asset_id:event.asset_id,name:event.identity?.computer||event.agent_id});
    included.push(event);
  }
  const ids = new Set(included.map(e=>e.event_id));
  const edges = [...links.values()].filter(l=>ids.has(l.from)&&ids.has(l.to)).sort((a,b)=>a.key.localeCompare(b.key));
  if (edges.length > limits.links || conflicts.size || events.size !== included.length) truncated=true;
  const accounts = new Set(), sessions = new Set(),sidAccounts=new Set(),nameAccounts=new Set();
  for (const step of included) {
    const i=step.identity||{};
    // A key is a credential, not a globally unique local account identity.
    if(i.account_sid)sidAccounts.add(i.account_sid);else nameAccounts.add(JSON.stringify([step.hostKey,step.user||"unknown"]));
    accounts.add(i.account_sid ? "sid:"+i.account_sid : JSON.stringify([step.hostKey,step.user||"unknown"]));
    if (i.local_session) sessions.add(JSON.stringify([step.hostKey,i.local_session]));
    else if (i.session_guid && i.account_sid) sessions.add(JSON.stringify([step.hostKey,i.account_sid,i.session_guid]));
  }
  return {events:included,hosts:[...hosts.values()],links:edges.slice(0,limits.links),savedChains,truncated,conflicts:conflicts.size,accounts:accounts.size,accountsWithSID:sidAccounts.size,accountsWithoutSID:nameAccounts.size,sessions:sessions.size};
}

function chainGraphLauncher(root, scope) {
  const detail=el("details","incident-graph"), summary=el("summary","","Открыть граф цепочки между узлами"), body=el("div","chain-graph-content");
  detail.dataset.investigation="1";
  detail.append(summary,body);root.append(detail);
  let loaded=false,busy=false;
  async function load() {
    if(busy)return;busy=true;loaded=false;const session=state.csrf;
    body.replaceChildren(el("p","muted","Загрузка сохранённых цепочек инцидента…"));
    try {
      const response=await api("api/incident-graph?"+new URLSearchParams({id:scope.incident}));
      if(session!==state.csrf||!detail.isConnected||!detail.open)return;
      body.replaceChildren();
      const c=response.context;
      body.append(el("p","muted","Снимок: "+date(c.at)+(c.incident_id?" · версия карточки "+c.incident_version:"")+". Показаны только цепочки связанных срабатываний; предположительные соседние события не добавляются."));
      const reload=el("button","text-button","Обновить граф →");reload.type="button";reload.addEventListener("click",load);body.append(reload);
      renderChainGraph(body,chainGraphModel(c));loaded=true;
    } catch(e) {
      if(session!==state.csrf||!detail.isConnected||!detail.open)return;
      body.replaceChildren(el("p","error",e.message));
      const retry=el("button","button","Повторить загрузку графа");retry.type="button";retry.addEventListener("click",load);body.append(retry);
    } finally {busy=false;}
  }
  detail.addEventListener("toggle",()=>{if(detail.open&&!loaded)load();});
}

function renderChainGraph(root,model) {
  root.append(el("p","graph-note","Стрелки показывают порядок наблюдений и сохранённый признак связи (SID, GUID, SSH-ключ или локальный сеанс). Они не подтверждают прямое сетевое перемещение или успешную атаку."));
  if(model.truncated) root.append(el("p","error","Граф ограничен: до 20 опорных срабатываний, 80 событий, 20 узлов и 200 связей. Пропущенные данные не считаются отсутствующими."));
  if(model.conflicts) root.append(el("p","error","Есть несовпадающие снимки одного события: такие события и их связи исключены из графа. Проверьте исходники срабатываний."));
  if(!model.events.length) {root.append(el("p","empty","В связанных срабатываниях пока нет сохранённой межузловой цепочки. Свяжите с инцидентом срабатывание межузлового правила; совпадения имён и IP граф не объединяет автоматически."));return;}
  root.append(el("p","graph-counts","Узлы: "+model.hosts.length+" · учётки с SID: "+model.accountsWithSID+" · имена без SID: "+model.accountsWithoutSID+" · локальные сеансы с идентификатором: "+model.sessions+" · события: "+model.events.length+" · связи: "+model.links.length));
  const tools=el("div","graph-tools"), minus=el("button","button","−"),plus=el("button","button","+"),fit=el("button","button","По ширине"),fitAll=el("button","button","Весь граф"),scaleLabel=el("span","muted","100%"),listToggle=el("button","text-button","Список событий");
  minus.setAttribute("aria-label","Уменьшить масштаб графа");plus.setAttribute("aria-label","Увеличить масштаб графа");
  for(const b of [minus,plus,fit,fitAll,listToggle])b.type="button";
  tools.append(minus,scaleLabel,plus,fit,fitAll,listToggle);root.append(tools);
  const layout=el("div","graph-layout"),viewport=el("div","graph-viewport"),canvas=el("div","graph-canvas"),inspector=el("div","graph-inspector");
  viewport.tabIndex=0;viewport.setAttribute("aria-label","Граф событий: прокрутка, масштабирование и выбор события");
  inspector.setAttribute("aria-live","polite");layout.append(viewport,inspector);viewport.append(canvas);root.append(layout);
  const svgNS="http://www.w3.org/2000/svg";
  function svgEl(tag,attrs={},text){const n=document.createElementNS(svgNS,tag);for(const [k,v]of Object.entries(attrs))n.setAttribute(k,String(v));if(text!==undefined)n.textContent=text;return n;}
  const lane=286, cardWidth=250, rowHeight=142, width=Math.max(340,model.hosts.length*lane+40),height=130+model.events.length*rowHeight;
  const svg=svgEl("svg",{width,height,viewBox:`0 0 ${width} ${height}`,role:"group","aria-label":"Узлы и последовательность событий сохранённой цепочки"});canvas.append(svg);
  const defs=svgEl("defs"),marker=svgEl("marker",{id:"graph-arrow-"+Math.random().toString(36).slice(2),viewBox:"0 0 10 10",refX:9,refY:5,markerWidth:7,markerHeight:7,orient:"auto-start-reverse"});marker.append(svgEl("path",{d:"M 0 0 L 10 5 L 0 10 z",fill:"#638f89"}));defs.append(marker);svg.append(defs);
  const hostPositions=new Map();
  model.hosts.forEach((host,index)=>{const x=20+index*lane;hostPositions.set(host.key,x);svg.append(svgEl("rect",{x,y:10,width:lane-12,height:height-20,rx:12,class:"graph-lane"}),svgEl("text",{x:x+14,y:36,class:"graph-host-label"},clip(host.name,29)),svgEl("text",{x:x+14,y:57,class:"graph-small"},"Агент "+short(host.agent_id)),svgEl("text",{x:x+14,y:75,class:"graph-small"},"Актив "+short(host.asset_id)));});
  const positions=new Map();model.events.forEach((event,index)=>positions.set(event.event_id,{x:hostPositions.get(event.hostKey)+12,y:100+index*rowHeight}));
  const edgeLayer=svgEl("g"),nodeLayer=svgEl("g");svg.append(edgeLayer,nodeLayer);
  const edgeElements=new Map(),nodeElements=new Map();
  function clip(s,max){s=String(s||"");return s.length>max?s.slice(0,max-1)+"…":s;}
  function button(text,handler){const b=el("button","text-button",text);b.type="button";b.addEventListener("click",handler);return b;}
  function sourceButton(event){return button("Открыть исходное событие →",()=>showRaw(event.event_id));}
  function fact(label,value){if(value)inspector.append(el("p","graph-fact",label+": "+value));}
  function highlight(eventID,edgeKey){for(const [id,n]of nodeElements)n.classList.toggle("selected",id===eventID);for(const [key,n]of edgeElements)n.classList.toggle("selected",key===edgeKey||!!eventID&&(n.dataset.from===eventID||n.dataset.to===eventID));}
  function selectEvent(event) {
    highlight(event.event_id,"");const i=event.identity||{};
    inspector.replaceChildren(el("h3","","Событие и сеанс"),el("p","",date(event.at)),el("p","graph-node-name",i.computer||event.agent_id));
    fact("Действие",chainStepTitle(event));fact("Код события",event.code);for(const [k,v]of chainWindowsFacts(event))fact(k,v);fact("Учётная запись",event.user||"Не указана");fact("Агент",event.agent_id);fact("Актив",event.asset_id);fact("SID",i.account_sid);fact("Домен источника",i.realm);fact("Logon GUID",i.session_guid);fact("Локальный сеанс",i.local_session);fact("SSH-ключ",i.ssh_key);fact("IP источника",event.source_ip);
    if(!i.local_session&&!i.session_guid)inspector.append(el("p","muted","Идентификатор сеанса не передан; сеанс по имени пользователя не достраивается."));
    inspector.append(sourceButton(event),el("h4","","Сохранённые срабатывания"));
    const seen=new Set();for(const d of event.detections){const key=d.id+":"+d.revision;if(seen.has(key))continue;seen.add(key);inspector.append(el("p","graph-fact",d.rule+" · параметры v"+d.revision+" · "+d.id));}
  }
  function selectEdge(edge) {
    highlight("",edge.key);inspector.replaceChildren(el("h3","","Основание связи"),el("p","",edgeName(edge.kind)));
    for(const basis of edge.bases)inspector.append(el("p","graph-fact",basis));
    for(const [label,id]of [["Откуда",edge.from],["Куда",edge.to]]){const event=model.events.find(e=>e.event_id===id);inspector.append(el("h4","",label+": "+(event.identity?.computer||short(event.agent_id))),button("Показать событие и сеанс",()=>selectEvent(event)),sourceButton(event));}
    inspector.append(el("p","muted","Это признак сопоставления из срабатывания, а не доказательство сетевого соединения между соседними узлами."));
  }
  function activate(n,handler){n.setAttribute("role","button");n.setAttribute("tabindex","0");n.addEventListener("click",handler);n.addEventListener("keydown",event=>{if(event.key==="Enter"||event.key===" "){event.preventDefault();handler();}});}
  function edgeName(kind){return chainEdgeTitle(kind);}
  for(const edge of model.links) {
    const a=positions.get(edge.from),b=positions.get(edge.to),same=a.x===b.x;
    const fromX=a.x+(same?cardWidth:cardWidth/2),fromY=a.y+116,toX=b.x+(same?cardWidth:cardWidth/2),toY=b.y;
    const d=same?`M ${fromX} ${fromY-20} C ${fromX+22} ${fromY}, ${toX+22} ${toY}, ${toX} ${toY+20}`:`M ${fromX} ${fromY} C ${fromX} ${fromY+30}, ${toX} ${toY-30}, ${toX} ${toY}`;
    const g=svgEl("g",{class:"graph-edge","aria-label":edgeName(edge.kind)+": "+edge.bases.join("; ")});g.dataset.from=edge.from;g.dataset.to=edge.to;
    g.append(svgEl("title",{},edgeName(edge.kind)+" — "+edge.bases.join("; ")),svgEl("path",{d,class:"graph-edge-hit"}),svgEl("path",{d,class:"graph-edge-line","marker-end":"url(#"+marker.id+")"}));
    const tx=same?fromX+3:(fromX+toX)/2,ty=same?(fromY+toY)/2:(fromY+toY)/2-5;
    g.append(svgEl("text",{x:tx,y:ty,class:"graph-edge-label","text-anchor":same?"end":"middle"},edgeName(edge.kind)));activate(g,()=>selectEdge(edge));edgeLayer.append(g);edgeElements.set(edge.key,g);
  }
  model.events.forEach((event,index)=>{
    const p=positions.get(event.event_id),i=event.identity||{},session=i.local_session||i.session_guid||"не передан";
    const g=svgEl("g",{class:"graph-event","aria-label":`${index+1}. ${i.computer||event.agent_id}; ${event.user||"пользователь не указан"}; ${date(event.at)}; сеанс ${session}`});
    g.append(svgEl("title",{},chainStepTitle(event)),svgEl("rect",{x:p.x,y:p.y,width:cardWidth,height:116,rx:9}),svgEl("text",{x:p.x+12,y:p.y+23,class:"graph-event-title"},clip((index+1)+". "+chainStepTitle(event),31)),svgEl("text",{x:p.x+12,y:p.y+45,class:"graph-small"},date(event.at)),svgEl("text",{x:p.x+12,y:p.y+68,class:"graph-account"},clip((event.action==="explicit_credentials"?"Инициатор: ":"Учётка: ")+(event.user||"не указана"),31)),svgEl("text",{x:p.x+12,y:p.y+89,class:"graph-small"},clip((i.local_session?"Сеанс узла: ":i.session_guid?"Logon GUID: ":"Сеанс: ")+session,33)),svgEl("text",{x:p.x+12,y:p.y+106,class:"graph-hint"},clip(event.windows_auth?.service?"Служба: "+event.windows_auth.service:event.action==="explicit_credentials"?"Реквизиты: "+event.windows_auth.target_account:"Выбрать событие →",34)));
    activate(g,()=>selectEvent(event));nodeLayer.append(g);nodeElements.set(event.event_id,g);
  });
  let scale=1;
  function zoom(value){scale=Math.max(.04,Math.min(1.75,value));svg.style.width=width*scale+"px";svg.style.height=height*scale+"px";canvas.style.width=width*scale+"px";canvas.style.height=height*scale+"px";scaleLabel.textContent=Math.round(scale*100)+"%";minus.disabled=scale<=.04;plus.disabled=scale>=1.75;}
  minus.addEventListener("click",()=>zoom(scale-.15));plus.addEventListener("click",()=>zoom(scale+.15));fit.addEventListener("click",()=>zoom(Math.min(1,(viewport.clientWidth-20)/width)));
  function overview(){zoom(Math.min(1,(viewport.clientWidth-20)/width,(viewport.clientHeight-20)/height));viewport.scrollTop=0;viewport.scrollLeft=0;}
  fitAll.addEventListener("click",overview);
  const list=el("div","graph-event-list hidden");for(const event of model.events){const row=el("div","graph-list-row");row.append(button(date(event.at)+" · "+(event.identity?.computer||short(event.agent_id))+" · "+(event.user||"—"),()=>selectEvent(event)),sourceButton(event));list.append(row);}listToggle.setAttribute("aria-expanded","false");listToggle.addEventListener("click",()=>{const shown=list.classList.toggle("hidden");listToggle.setAttribute("aria-expanded",String(!shown));});root.append(list);
  overview();selectEvent(model.events[0]);
}
