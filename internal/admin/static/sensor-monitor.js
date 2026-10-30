// SPDX-License-Identifier: Apache-2.0
"use strict";
const sensorMonitorUI={selected:"",draft:null,epoch:0,request:0,key:"",last:0,loading:false};
const sensorMonitorFields={offline:["offline_seconds",60],pending:["pending_seconds",60],window:["window_seconds",60],min:["min_messages",1],percent:["error_percent",1],unknown:["unknown_sets",1],batches:["queue_batches",1],bytes:["queue_bytes",1048576]};
function renderSensorMonitoring(item){
 const a=item.agent,s=a.health.sensor,m=item.monitor;
 if(sensorMonitorUI.selected!==a.agent_id){resetSensorMonitoring();sensorMonitorUI.selected=a.agent_id;$("sensor-history-input").replaceChildren(el("option","","Весь сенсор"));$("sensor-history-input").firstChild.value=""}
 if(!sensorCanEdit())cancelSensorMonitor();
 $("sensor-monitor-edit").classList.toggle("hidden",!sensorCanEdit()||a.revoked||s.monitoring_version!==1);
 $("sensor-monitor-summary").textContent=m?(m.enabled?"Оповещения включены":"Оповещения отключены")+" · ожидаемых источников: "+(m.watches||[]).length+" · нет связи: "+m.offline_seconds/60+" мин":"Для настройки оповещений обновите сервер и сенсор.";
 loadSensorHistory();
}
function resetSensorMonitoring(){sensorMonitorUI.epoch++;sensorMonitorUI.request++;sensorMonitorUI.selected="";sensorMonitorUI.key="";sensorMonitorUI.last=0;sensorMonitorUI.loading=false;cancelSensorMonitor();$("sensor-history-charts").replaceChildren();$("sensor-history-status").textContent=""}
function cancelSensorMonitor(){sensorMonitorUI.draft=null;$("sensor-monitor-form").classList.add("hidden");$("sensor-watch-rows").replaceChildren();$("sensor-monitor-error").textContent=""}
function editSensorMonitor(){
 const item=sensorUI.items.find(i=>i.agent.agent_id===sensorMonitorUI.selected);if(!item?.monitor||!sensorCanEdit()||item.agent.revoked)return;
 const c=structuredClone(item.monitor);sensorMonitorUI.draft={agent:item.agent.agent_id,revision:item.policy.revision,inputs:item.agent.health.sensor.inputs.filter(i=>i.protocol!=="file").map(i=>i.id)};
 $("sensor-monitor-enabled").checked=c.enabled;for(const [id,[key,factor]]of Object.entries(sensorMonitorFields))$("sensor-monitor-"+id).value=c[key]/factor;
 $("sensor-watch-add").disabled=false;$("sensor-watch-rows").replaceChildren();for(const w of c.watches||[])addSensorWatch(w);
 $("sensor-monitor-error").textContent="";$("sensor-monitor-form").classList.remove("hidden");$("sensor-monitor-form").scrollIntoView?.({behavior:"smooth",block:"start"});$("sensor-monitor-enabled").focus();
}
function addSensorWatch(w={input:"",peer:"",silence_seconds:600}){
 const draft=sensorMonitorUI.draft,root=$("sensor-watch-rows");if(!draft||root.children.length>=32)return;
 const row=el("div","sensor-watch-row"),input=el("select"),peer=el("input"),minutes=el("input"),remove=el("button","text-button","Удалить");
 for(const id of [...new Set([...draft.inputs,...(w.input?[w.input]:[])])]){const option=el("option","",id+(draft.inputs.includes(id)?"":" · вход удалён"));option.value=id;input.append(option)}
 if(w.input)input.value=w.input;peer.value=w.peer||"";peer.placeholder="Любой разрешённый IP";peer.maxLength=45;minutes.type="number";minutes.min="3";minutes.max="10080";minutes.required=true;minutes.value=w.silence_seconds/60;
 for(const [title,node]of [["Вход",input],["IP экспортёра",peer],["Тишина, минут",minutes]]){const label=el("label","",title);label.append(node);row.append(label)}
 remove.type="button";remove.addEventListener("click",()=>{row.remove();$("sensor-watch-add").disabled=false});row.append(remove);root.append(row);$("sensor-watch-add").disabled=root.children.length>=32;
}
async function saveSensorMonitor(event){
 event.preventDefault();const draft=sensorMonitorUI.draft;if(!draft||!sensorCanEdit())return;$("sensor-monitor-save").disabled=true;$("sensor-monitor-error").textContent="";
 try{
  const c={enabled:$("sensor-monitor-enabled").checked,watches:[]};for(const [id,[key,factor]]of Object.entries(sensorMonitorFields))c[key]=Number($("sensor-monitor-"+id).value)*factor;
  for(const row of $("sensor-watch-rows").children){const [input,peer,minutes]=row.querySelectorAll("select,input");c.watches.push({input:input.value,peer:peer.value.trim(),silence_seconds:Number(minutes.value)*60})}
  await api("api/sensors",{method:"POST",body:JSON.stringify({agent_id:draft.agent,expected_revision:draft.revision,monitor:c})});
  if(sensorMonitorUI.draft===draft){cancelSensorMonitor();await loadSensors()}
 }catch(e){if(sensorMonitorUI.draft===draft)$("sensor-monitor-error").textContent=e.message}finally{$("sensor-monitor-save").disabled=false}
}
async function loadSensorHistory(force=false){
 const agent=sensorMonitorUI.selected;if(!agent||state.view!=="sensors"||!state.csrf)return;
 const period=$("sensor-history-period").value,input=$("sensor-history-input").value,key=agent+"/"+period+"/"+input;
 if(!force&&sensorMonitorUI.key===key&&(sensorMonitorUI.loading||Date.now()-sensorMonitorUI.last<30000))return;
 sensorMonitorUI.key=key;sensorMonitorUI.loading=true;const request=++sensorMonitorUI.request,epoch=sensorMonitorUI.epoch;
 $("sensor-history-status").textContent="Загрузка истории…";
 try{
  const h=await api("api/sensors/history?agent="+encodeURIComponent(agent)+"&input="+encodeURIComponent(input)+"&period="+encodeURIComponent(period));
  if(request!==sensorMonitorUI.request||epoch!==sensorMonitorUI.epoch||state.view!=="sensors"||!state.csrf)return;
  const select=$("sensor-history-input"),current=sensorUI.items.find(i=>i.agent.agent_id===agent)?.agent.health.sensor.inputs||[];
  const options=[...new Set([...current.map(i=>i.id),...(h.inputs||[]),...(input?[input]:[])])].sort();select.replaceChildren();const all=el("option","","Весь сенсор");all.value="";select.append(all);for(const id of options){const option=el("option","",id);option.value=id;select.append(option)}select.value=input;
  sensorMonitorUI.last=Date.now();renderSensorHistory(h,period);
 }catch(e){if(request===sensorMonitorUI.request&&epoch===sensorMonitorUI.epoch){$("sensor-history-charts").replaceChildren();$("sensor-history-status").textContent="История недоступна. "+e.message}}
 finally{if(request===sensorMonitorUI.request)sensorMonitorUI.loading=false}
}
function renderSensorHistory(h,period){
 const root=$("sensor-history-charts");root.replaceChildren();const points=h.points||[];
 $("sensor-history-status").textContent=points.length?"Замер: "+date(h.as_of)+" · интервал "+h.step_seconds/60+" мин · агрегатов: "+points.length:"История пока накапливается. Первый достоверный замер скорости появится после двух heartbeat.";
 if(!points.length)return;
 const hours=({"24h":24,"7d":168,"30d":720})[period]||24,end=Date.parse(h.as_of),start=end-hours*3600000;
 const specs=[
  {title:"Приём сообщений",unit:"сообщ./с",values:p=>[p.seconds>0?p.messages/p.seconds:null],labels:["Приём"],format:n=>n.toFixed(2)},
  {title:"Полученные данные",unit:"КиБ/с",values:p=>[p.seconds>0?p.bytes/p.seconds/1024:null],labels:["Приём"],format:n=>n.toFixed(2)},
  {title:"Ошибки за интервал",unit:"количество",values:p=>[p.seconds>0?p.rejected:null,p.seconds>0?p.unknown_sets:null],labels:["Сообщения с отказом/потерями","Наборы без шаблона"],format:n=>Math.round(n).toString()},
  {title:"Очередь сенсора",unit:"пакетов · максимум",values:p=>[p.queue_reports>0?p.queue_batches:null],labels:["Очередь"],format:n=>Math.round(n).toString()}
 ];
 if($("sensor-history-input").value)specs.pop();
 for(const spec of specs){
  const card=el("article","sensor-chart"),heading=el("div","sensor-card-heading"),title=el("h4","",spec.title),unit=el("span","muted",spec.unit);heading.append(title,unit);card.append(heading);
  const ns="http://www.w3.org/2000/svg",svg=document.createElementNS(ns,"svg");svg.setAttribute("viewBox","0 0 600 160");svg.setAttribute("role","img");svg.setAttribute("aria-label",spec.title+". Стрелки влево и вправо переключают интервалы.");svg.setAttribute("tabindex","0");
  const values=points.map(spec.values),max=Math.max(1,...values.flat().filter(v=>v!=null)),x=p=>8+Math.max(0,Math.min(1,(Date.parse(p.at)-start)/(end-start)))*584,y=v=>145-v/max*125;
  const grid=document.createElementNS(ns,"path");grid.setAttribute("d","M8 20H592 M8 82H592 M8 145H592");grid.setAttribute("class","sensor-chart-grid");svg.append(grid);
  const top=document.createElementNS(ns,"text");top.setAttribute("x","10");top.setAttribute("y","14");top.textContent=spec.format(max);svg.append(top);
  for(let line=0;line<spec.labels.length;line++){let d="",previous=null;for(let k=0;k<points.length;k++){const v=values[k][line];if(v==null){previous=null;continue}const at=Date.parse(points[k].at),join=previous!=null&&at-previous<=h.step_seconds*1000*1.1;d+=(join?"L":"M")+x(points[k]).toFixed(1)+" "+y(v).toFixed(1);if(!join)d+="l.1 0";previous=at}
   const path=document.createElementNS(ns,"path");path.setAttribute("d",d);path.setAttribute("class","sensor-chart-line line-"+line);svg.append(path)
  }
  const marker=document.createElementNS(ns,"path");marker.setAttribute("class","sensor-chart-marker");svg.append(marker);const detail=el("p","sensor-chart-detail"),range=el("div","sensor-chart-range");range.append(el("span","",date(new Date(start).toISOString())),el("span","",date(h.as_of)));let selected=points.length-1;
  function show(index){selected=Math.max(0,Math.min(points.length-1,index));const p=points[selected],v=values[selected],pos=x(p);marker.setAttribute("d","M"+pos+" 20V145");detail.textContent=date(p.at)+" · "+spec.labels.map((label,k)=>label+": "+(v[k]==null?"нет замера":spec.format(v[k]))).join(" · ")+(spec.title==="Очередь сенсора"&&p.queue_reports>0?" · "+sensorBytes(p.queue_bytes):"")}
  svg.addEventListener("pointermove",event=>{const rect=svg.getBoundingClientRect(),target=start+((event.clientX-rect.left)/rect.width*600-8)/584*(end-start);let best=0;for(let k=1;k<points.length;k++)if(Math.abs(Date.parse(points[k].at)-target)<Math.abs(Date.parse(points[best].at)-target))best=k;show(best)});
  svg.addEventListener("keydown",event=>{if(event.key==="ArrowLeft"||event.key==="ArrowRight"){event.preventDefault();show(selected+(event.key==="ArrowRight"?1:-1))}});svg.addEventListener("focus",()=>show(selected));show(selected);card.append(svg,range,detail);root.append(card)
 }
}
$("sensor-monitor-edit").addEventListener("click",editSensorMonitor);$("sensor-monitor-form").addEventListener("submit",saveSensorMonitor);$("sensor-monitor-cancel").addEventListener("click",cancelSensorMonitor);$("sensor-watch-add").addEventListener("click",()=>addSensorWatch());
for(const id of ["sensor-history-period","sensor-history-input"])$(id).addEventListener("change",()=>loadSensorHistory(true));
