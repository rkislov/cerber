"use strict";
$("windows-tab").addEventListener("click",()=>{state.inventorySection="windows";state.inventoryOffset=0;loadInventory()});
async function loadWindowsVulnerabilities(){
 const agent=state.currentAgent,offset=state.inventoryOffset,id=agent?.latest_inventory_id,root=$("windows-vulnerabilities");
 $("components-tab").classList.remove("selected");$("updates-tab").classList.remove("selected");$("inventory-error").textContent="";$("inventory-retry").classList.add("hidden");
 if(!id){root.replaceChildren(el("p","muted","Для проверки нужен снимок инвентаря Windows"));return}
 root.replaceChildren(el("p","muted","Проверка сборки Windows по центральному каталогу Microsoft…"));
 try{
  const r=await api("api/windows-vulnerabilities?id="+encodeURIComponent(id)+"&offset="+offset);
  if(state.currentAgent!==agent||state.inventorySection!=="windows"||state.inventoryOffset!==offset)return;
  root.replaceChildren();$("inventory-note").textContent=r.reason;
  const source=r.source,counts=r.counts;root.append(el("h3","","Microsoft MSRC · Windows"),el("p","muted","Документов: "+source.documents+" / "+source.expected+" · записей: "+source.records+" · "+(source.initial_complete?"Первичный импорт завершён":"Первичный импорт ещё не завершён")+(source.busy?" · идёт загрузка":"")),el("p","muted","Индекс проверен: "+date(source.at)+" · "+source.scope));
  if(source.error||source.errors)root.append(el("p","error",source.error||"Ошибок загрузки документов: "+source.errors));
  root.append(el("p","","Уязвимая сборка: "+counts.affected+" · требуется проверка: "+counts.unknown+" · исправлено / не затронуто: "+counts.fixed));
  root.append(el("p","muted","Перезагрузка: "+(r.os.reboot_required===true?"требуется":r.os.reboot_required===false?"не требуется по данным агента":"статус не получен; обновите агент и инвентарь")));
  const refresh=el("button","text-button","Обновить результат →");refresh.addEventListener("click",loadInventory);root.append(refresh);
  if(state.role==="administrator"&&state.username){const sync=el("button","text-button","Запросить синхронизацию Microsoft →");sync.addEventListener("click",async()=>{sync.disabled=true;try{await api("api/microsoft-catalog",{method:"POST",body:JSON.stringify({action:"refresh"})});sync.textContent="Проверка источника запрошена; обновите результат через минуту"}catch(e){$("inventory-error").textContent=e.message;sync.disabled=false}});root.append(sync)}
  for(const f of r.items){const d=el("details","network-vulnerability"),a=f.assessment,w=f.windows;d.append(el("summary","",f.id+" · "+({affected:"Уязвимая сборка",fixed:"Исправлено / не затронуто",unknown:"Требует проверки"}[a.status]||a.status)+" · "+(f.score?"CVSS "+f.score:"CVSS неизвестен")),el("p","",f.title),el("p",a.status==="affected"?"error":"",a.reason),el("p","muted",w.product+" · Product ID "+w.product_id),el("p","","Сборка: "+w.installed_build+" · исправление: "+(w.fixed_build||"не опубликовано")));
   if(w.kb){const link=el("a","text-button","Исправляющее обновление "+w.kb+" →");if(/^KB[0-9]{6,8}$/.test(w.kb)){link.href="https://support.microsoft.com/help/"+w.kb.slice(2);link.target="_blank";link.rel="noopener noreferrer";d.append(link)}}
   if(w.installed_kb)d.append(el("p","muted","Установлен: "+w.installed_kb+" · цепочка замены: "+(w.supersedence||[]).join(" → ")));
   const link=el("a","text-button","Карточка Microsoft MSRC →");link.href="https://msrc.microsoft.com/update-guide/vulnerability/"+encodeURIComponent(f.id);link.target="_blank";link.rel="noopener noreferrer";d.append(link,el("p","network-evidence","Источник: "+a.source_url+" · загружен "+date(a.source_fetched)+" · SHA-256 "+a.source_sha256));root.append(d)
  }
  if(!r.items.length)root.append(el("p","empty","Записей на этой странице нет. Это не подтверждает отсутствие уязвимостей."));
  $("inventory-page").textContent=r.total?"Записи "+(offset+1)+"–"+(offset+r.items.length)+" из "+r.total:"Записей нет";$("inventory-prev").disabled=offset===0;$("inventory-next").disabled=offset+50>=r.total;
 }catch(e){if(state.currentAgent!==agent||state.inventorySection!=="windows")return;root.replaceChildren(el("p","error",e.message));$("inventory-retry").classList.remove("hidden")}
}
