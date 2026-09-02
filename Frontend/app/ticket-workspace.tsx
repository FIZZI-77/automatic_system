"use client";
/* eslint-disable react-hooks/set-state-in-effect */

import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, config, type Role, type Session, type Ticket } from "./api";
import { loadBrigades } from "./brigade-store";
import { TicketAssetPicker } from "./ticket-asset-picker";

const statusNames: Record<string, string> = { NEW: "Новая", ASSIGNED: "Назначена", IN_PROGRESS: "В работе", DONE: "Завершена", CANCELED: "Отменена" };

type WorkReport = { id:string; ticket_id:string; author_user_id:string; description:string; file_ids:string[]; created_at:string|number };
type StoredFile = { id:string; name:string; content_type:string; size:number; status:string };
type DispatchCandidate = { brigade_id:string; rank:number; distance_meters:number; eta_seconds:number; reachable:boolean };
type TicketHistory = { id:string; old_status?:string; new_status:string; changed_by?:string; comment?:string; created_at:number };

export function TicketWorkspace({tickets,session,role,onUpdate,onMap,onNotice}:{tickets:Ticket[];session:Session;role:Role;onUpdate:(ticket:Ticket)=>void;onMap:(id:string)=>void;onNotice:(text:string)=>void}) {
  const [selected,setSelected]=useState<Ticket>();
  const [files,setFiles]=useState<File[]>([]);
  const [reports,setReports]=useState<WorkReport[]>([]);
  const [reportFiles,setReportFiles]=useState<Record<string,StoredFile[]>>({});
  const [busy,setBusy]=useState(false);
  const [candidates,setCandidates]=useState<DispatchCandidate[]>([]);
  const [history,setHistory]=useState<TicketHistory[]>([]);
  const [editing,setEditing]=useState(false);
  const [filters,setFilters]=useState({query:"",status:"",priority:"",assignment:"",createdFrom:"",createdTo:"",sort:"created_desc"});
  const demo=session.accessToken==="demo";
  const brigades=loadBrigades().filter(item=>!["INACTIVE","OFFLINE","ARCHIVED"].includes(item.status));

  const visibleTickets=useMemo(()=>{
    const query=filters.query.trim().toLocaleLowerCase("ru-RU");
    const from=filters.createdFrom?new Date(`${filters.createdFrom}T00:00:00`).getTime()/1000:0;
    const to=filters.createdTo?new Date(`${filters.createdTo}T23:59:59`).getTime()/1000:Number.POSITIVE_INFINITY;
    const result=tickets.filter(ticket=>{
      if(query&&![ticket.id,ticket.title,ticket.address,ticket.description].some(value=>String(value||"").toLocaleLowerCase("ru-RU").includes(query)))return false;
      if(filters.status&&ticket.status!==filters.status)return false;
      if(filters.priority&&ticket.priority!==filters.priority)return false;
      if(filters.assignment==="assigned"&&!ticket.brigade_id)return false;
      if(filters.assignment==="unassigned"&&ticket.brigade_id)return false;
      return Number(ticket.created_at)>=from&&Number(ticket.created_at)<=to;
    });
    return result.sort((left,right)=>{
      if(filters.sort==="created_asc")return Number(left.created_at)-Number(right.created_at);
      if(filters.sort==="updated_desc")return Number(right.updated_at)-Number(left.updated_at);
      if(filters.sort==="priority_desc")return ({EMERGENCY:4,HIGH:3,MEDIUM:2,LOW:1}[right.priority]||0)-({EMERGENCY:4,HIGH:3,MEDIUM:2,LOW:1}[left.priority]||0);
      if(filters.sort==="status")return (statusNames[left.status]||left.status).localeCompare(statusNames[right.status]||right.status,"ru");
      return Number(right.created_at)-Number(left.created_at);
    });
  },[filters,tickets]);

  useEffect(()=>{
    if(!selected){setReports([]);setReportFiles({});setHistory([]);return;}
    if(demo){setReports(selected.status==="DONE"?[{id:"demo-report",ticket_id:selected.id,author_user_id:"demo-worker",description:"Работы выполнены, объект проверен и передан диспетчеру.",file_ids:[],created_at:Date.now()/1000}]:[]);setHistory([{id:"demo-history",new_status:selected.status,comment:"Текущее состояние",created_at:selected.updated_at}]);return;}
    let active=true;
    (async()=>{
      try{
        const [result,historyResult]=await Promise.all([api<{reports:WorkReport[]}>(config.endpoints.ticketReportsList,{ticket_id:selected.id},"POST",session.accessToken),api<{history:TicketHistory[]}>(config.endpoints.ticketsHistory,{ticket_id:selected.id,limit:100,offset:0},"POST",session.accessToken)]);
        if(!active)return;
        const items=result.reports||[];
        setReports(items);
        setHistory(historyResult.history||[]);
        const entries=await Promise.all(items.map(async report=>{
          const response=await api<{files:StoredFile[]}>(config.endpoints.filesList,{resource_type:"work_report",resource_id:report.id},"POST",session.accessToken);
          return [report.id,response.files||[]] as const;
        }));
        if(active)setReportFiles(Object.fromEntries(entries));
      }catch(error){if(active)onNotice(error instanceof Error?error.message:"Не удалось загрузить отчёты")}
    })();
    return()=>{active=false};
  },[demo,onNotice,selected,session.accessToken]);

  useEffect(()=>{
    if(!selected||selected.status!=="NEW"||!["admin","dispatcher"].includes(role)||demo){setCandidates([]);return}
    let active=true;
    api<{candidates:DispatchCandidate[]}>(config.endpoints.dispatchPreview,{ticket_id:selected.id,limit:100},"POST",session.accessToken)
      .then(result=>{if(active)setCandidates((result.candidates||[]).filter(item=>item.reachable).sort((a,b)=>a.rank-b.rank))})
      .catch(error=>{if(active)onNotice(error instanceof Error?error.message:"Не удалось подобрать бригады")});
    return()=>{active=false};
  },[demo,onNotice,role,selected,session.accessToken]);

  async function status(next:string){
    if(!selected)return;
    setBusy(true);
    try{
      let updated={...selected,status:next.toUpperCase()};
      if(!demo){
        const result=await api<{ticket:Ticket}>(config.endpoints.ticketsStatus,{ticket_id:selected.id,new_status:next,changed_by:session.user?.user_id,comment:"Изменено из рабочего окна"},"POST",session.accessToken);
        updated=result.ticket;
      }
      setSelected(updated);onUpdate(updated);onNotice(`Статус заявки изменён: ${statusNames[updated.status]||updated.status}`);
      if(updated.status==="IN_PROGRESS")onMap(updated.id);
    }catch(error){onNotice(error instanceof Error?error.message:"Не удалось изменить статус")}finally{setBusy(false)}
  }

  async function assign(brigadeId:string){
    if(!selected||!brigadeId)return;
    setBusy(true);
    try{
      const updated:Ticket={...selected,brigade_id:brigadeId,status:"ASSIGNED"};
      if(!demo){
        const reserved=await api<{operation:{id:string;version:number}}>(config.endpoints.dispatchReserve,{ticket_id:selected.id,brigade_id:brigadeId,requested_by:session.user?.user_id,reservation_ttl_seconds:120},"POST",session.accessToken);
        await api(config.endpoints.dispatchConfirm,{id:reserved.operation.id,confirmed_by:session.user?.user_id,expected_version:reserved.operation.version},"POST",session.accessToken);
      }
      setSelected(updated);onUpdate(updated);onNotice("Бригада назначена");onMap(updated.id);
    }catch(error){onNotice(error instanceof Error?error.message:"Не удалось назначить бригаду")}finally{setBusy(false)}
  }

  async function autoAssign(){
    if(!selected||demo)return;
    setBusy(true);
    try{
      const result=await api<{operation:{brigade_id:string}}>(config.endpoints.dispatchAuto,{ticket_id:selected.id,requested_by:session.user?.user_id,candidate_limit:100},"POST",session.accessToken);
      const updated:Ticket={...selected,brigade_id:result.operation.brigade_id,status:"ASSIGNED"};
      setSelected(updated);onUpdate(updated);onNotice("Dispatch Service автоматически назначил бригаду");onMap(updated.id);
    }catch(error){onNotice(error instanceof Error?error.message:"Не удалось выполнить автоназначение")}finally{setBusy(false)}
  }

  async function complete(event:FormEvent<HTMLFormElement>){
    event.preventDefault();if(!selected)return;
    const description=String(new FormData(event.currentTarget).get("description")||"").trim();
    setBusy(true);
    try{
      const fileIds:string[]=[];
      if(!demo)for(const file of files){
        const created=await api<{file:{id:string};upload_url:string}>(config.endpoints.filesUploadCreate,{name:file.name,content_type:file.type||"application/octet-stream",size:file.size},"POST",session.accessToken);
        const uploaded=await fetch(created.upload_url,{method:"PUT",headers:{"Content-Type":file.type||"application/octet-stream"},body:file});
        if(!uploaded.ok)throw new Error(`Не удалось загрузить ${file.name}`);
        await api(config.endpoints.filesUploadConfirm,{file_id:created.file.id},"POST",session.accessToken);
        fileIds.push(created.file.id);
      }
      let generatedName="";
      if(!demo){
        const generated=await api<{work_report:WorkReport;pdf_file_id:string;pdf_name:string}>(config.endpoints.completionReportsCreate,{ticket_id:selected.id,description,file_ids:fileIds},"POST",session.accessToken);
        generatedName=generated.pdf_name;
        setReports(current=>[generated.work_report,...current]);
        setReportFiles(current=>({...current,[generated.work_report.id]:[{id:generated.pdf_file_id,name:generated.pdf_name,content_type:"application/pdf",size:0,status:"LINKED"}]}));
        const result=await api<{ticket:Ticket}>(config.endpoints.ticketsComplete,{ticket_id:selected.id,completed_by:session.user?.user_id,comment:description},"POST",session.accessToken);
        setSelected(result.ticket);onUpdate(result.ticket);
      }else{
        const updated={...selected,status:"DONE"};setSelected(updated);onUpdate(updated);
      }
      setFiles([]);onNotice(`Отчёт сформирован${generatedName?`: ${generatedName}`:""}. Заявка завершена`);
    }catch(error){onNotice(error instanceof Error?error.message:"Не удалось завершить заявку")}finally{setBusy(false)}
  }

  async function cancel(event:FormEvent<HTMLFormElement>){
    event.preventDefault();if(!selected)return;const reason=String(new FormData(event.currentTarget).get("reason")||"").trim();setBusy(true);
    try{let updated={...selected,status:"CANCELED"};if(!demo){const result=await api<{ticket:Ticket}>(config.endpoints.ticketsCancel,{ticket_id:selected.id,canceled_by:session.user?.user_id,reason},"POST",session.accessToken);updated=result.ticket}setSelected(updated);onUpdate(updated);setHistory(items=>[{id:`local-${Date.now()}`,old_status:selected.status,new_status:"CANCELED",changed_by:session.user?.user_id,comment:reason,created_at:Date.now()/1000},...items]);onNotice("Заявка отменена")}catch(error){onNotice(error instanceof Error?error.message:"Не удалось отменить заявку")}finally{setBusy(false)}
  }
  async function updateTicket(event:FormEvent<HTMLFormElement>){event.preventDefault();if(!selected)return;const d=new FormData(event.currentTarget),payload={ticket_id:selected.id,title:String(d.get("title")),description:String(d.get("description")),priority:String(d.get("priority")),address:String(d.get("address")),asset_id:String(d.get("asset_id")||"")||undefined,updated_by:session.user?.user_id};setBusy(true);try{let updated:Ticket={...selected,title:payload.title,description:payload.description,priority:payload.priority,address:payload.address,asset_id:payload.asset_id};if(!demo){const result=await api<{ticket:Ticket}>(config.endpoints.ticketsUpdate,payload,"POST",session.accessToken);updated=result.ticket}setSelected(updated);onUpdate(updated);setEditing(false);onNotice("Данные заявки обновлены")}catch(error){onNotice(error instanceof Error?error.message:"Не удалось обновить заявку")}finally{setBusy(false)}}

  async function download(file:StoredFile){
    if(demo){onNotice("В демо файл не загружается");return;}
    try{
      const result=await api<{download_url:string}>(config.endpoints.filesDownload,{file_id:file.id},"POST",session.accessToken);
      window.open(result.download_url,"_blank","noopener,noreferrer");
    }catch(error){onNotice(error instanceof Error?error.message:"Не удалось открыть файл")}
  }

  async function removeStoredFile(reportId:string,file:StoredFile){
    if(demo)return;
    try{
      await api(config.endpoints.filesDelete,{file_id:file.id},"POST",session.accessToken);
      setReportFiles(current=>({...current,[reportId]:(current[reportId]||[]).filter(item=>item.id!==file.id)}));
      onNotice(`Файл «${file.name}» удалён`);
    }catch(error){onNotice(error instanceof Error?error.message:"Не удалось удалить файл")}
  }

  return <section className="content-page ticket-workspace">
    {selected && role === "worker" && selected.status === "IN_PROGRESS" && <TicketAssetPicker ticket={selected} session={session} demo={demo} onUpdate={ticket=>{setSelected(ticket);onUpdate(ticket)}} onNotice={onNotice}/>} 
    <div className="page-toolbar"><div><h2>Работа с заявками</h2><p>Назначение, исполнение и подтверждённые отчёты</p></div></div>
    <div className="service-filters ticket-filters">
      <label className="filter-search">Поиск<input type="search" value={filters.query} onChange={event=>setFilters(current=>({...current,query:event.target.value}))} placeholder="Номер, название или адрес"/></label>
      <label>Статус<select value={filters.status} onChange={event=>setFilters(current=>({...current,status:event.target.value}))}><option value="">Все статусы</option><option value="NEW">Новая</option><option value="ASSIGNED">Назначена</option><option value="IN_PROGRESS">В работе</option><option value="DONE">Завершена</option><option value="CANCELED">Отменена</option></select></label>
      <label>Приоритет<select value={filters.priority} onChange={event=>setFilters(current=>({...current,priority:event.target.value}))}><option value="">Все приоритеты</option><option value="EMERGENCY">Экстренный</option><option value="HIGH">Высокий</option><option value="MEDIUM">Средний</option><option value="LOW">Низкий</option></select></label>
      <label>Назначение<select value={filters.assignment} onChange={event=>setFilters(current=>({...current,assignment:event.target.value}))}><option value="">Все заявки</option><option value="assigned">Бригада назначена</option><option value="unassigned">Без бригады</option></select></label>
      <label>Создана с<input type="date" value={filters.createdFrom} onChange={event=>setFilters(current=>({...current,createdFrom:event.target.value}))}/></label>
      <label>Создана до<input type="date" value={filters.createdTo} onChange={event=>setFilters(current=>({...current,createdTo:event.target.value}))}/></label>
      <label>Сортировка<select value={filters.sort} onChange={event=>setFilters(current=>({...current,sort:event.target.value}))}><option value="created_desc">Сначала новые</option><option value="created_asc">Сначала старые</option><option value="updated_desc">Недавно изменённые</option><option value="priority_desc">По приоритету</option><option value="status">По статусу</option></select></label>
      <button type="button" onClick={()=>setFilters({query:"",status:"",priority:"",assignment:"",createdFrom:"",createdTo:"",sort:"created_desc"})}>Сбросить</button>
      <span className="filter-result-count">Найдено: <b>{visibleTickets.length}</b></span>
    </div>
    <div className="work-ticket-list">{visibleTickets.map(ticket=><button key={ticket.id} className={selected?.id===ticket.id?"selected":""} onClick={()=>setSelected(ticket)}><span className={`priority ${ticket.priority.toLowerCase()}`}/><div><b>{ticket.title}</b><small>{ticket.address}</small></div><em className={`status ${ticket.status.toLowerCase()}`}>{statusNames[ticket.status]||ticket.status}</em></button>)}{!visibleTickets.length&&<p className="ticket-filter-empty">По выбранным фильтрам заявок нет.</p>}</div>
    {selected&&<div className="ticket-modal-backdrop" role="presentation" onMouseDown={event=>{if(event.currentTarget===event.target)setSelected(undefined)}}>
      <article className="ticket-modal" role="dialog" aria-modal="true" aria-label={`Заявка ${selected.id}`}>
        <button className="detail-close" onClick={()=>setSelected(undefined)} aria-label="Закрыть">×</button>
        <span className="eyebrow">Заявка {selected.id}</span>{editing?<form className="ticket-edit-form" onSubmit={updateTicket}><label>Заголовок<input name="title" defaultValue={selected.title} required/></label><label>Описание<textarea name="description" rows={4} defaultValue={selected.description} required/></label><label>Адрес<input name="address" defaultValue={selected.address} required/></label><label>Приоритет<select name="priority" defaultValue={selected.priority}><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>EMERGENCY</option></select></label><div><button type="button" onClick={()=>setEditing(false)}>Отмена</button><button className="primary" disabled={busy}>Сохранить</button></div></form>:<><h2>{selected.title}</h2><p className="ticket-description">{selected.description}</p>{["admin","dispatcher","user"].includes(role)&&<button className="link ticket-edit-link" onClick={()=>setEditing(true)}>Изменить данные заявки</button>}</>}
        <dl className="ticket-facts"><div><dt>Адрес</dt><dd>{selected.address}</dd></div><div><dt>Статус</dt><dd>{statusNames[selected.status]||selected.status}</dd></div><div><dt>Создал</dt><dd>{selected.created_by_name||selected.user_id||"Не указан"}</dd></div><div><dt>Принял</dt><dd>{selected.brigade_id?(selected.accepted_by_name||`Бригада ${selected.brigade_id}`):"Ожидает назначения"}</dd></div></dl>
        <div className="ticket-modal-actions"><button className="ghost" onClick={()=>onMap(selected.id)}>Показать на карте</button>{["admin","dispatcher"].includes(role)&&<label>Назначить бригаду<select value={selected.brigade_id||""} onChange={event=>assign(event.target.value)} disabled={busy||selected.status!=="NEW"}><option value="">Выберите бригаду</option>{(candidates.length?candidates.map(candidate=>brigades.find(item=>item.id===candidate.brigade_id)).filter((item):item is NonNullable<typeof item>=>Boolean(item)):brigades).map(brigade=><option key={brigade.id} value={brigade.id}>{brigade.name}</option>)}</select>{selected.status==="NEW"&&candidates.length>0&&<small>Доступные бригады отсортированы Dispatch Service</small>}{selected.status==="NEW"&&<button type="button" className="link" disabled={busy} onClick={autoAssign}>Назначить автоматически</button>}</label>}</div>
        {selected.status==="ASSIGNED"&&["admin","dispatcher","worker"].includes(role)&&<button className="primary full-action" disabled={busy} onClick={()=>status("in_progress")}>Начать выполнение</button>}
        {!['DONE','CANCELED'].includes(selected.status)&&["admin","dispatcher","user"].includes(role)&&<form className="ticket-cancel-form" onSubmit={cancel}><label>Причина отмены<input name="reason" required minLength={3} placeholder="Укажите причину"/></label><button className="danger-action" disabled={busy}>Отменить заявку</button></form>}
        {selected.status==="IN_PROGRESS"&&["admin","dispatcher","worker"].includes(role)&&<form className="completion-form" onSubmit={complete}><h3>Отчёт о выполнении</h3><label>Что выполнено<textarea name="description" required rows={4} placeholder="Опишите выполненные работы и результат"/></label><label className="file-drop">Фото и документы<input type="file" multiple accept="image/*,.pdf,.doc,.docx" onChange={event=>setFiles(Array.from(event.target.files||[]))}/><span>Выбрать файлы</span><small>Фотографии будут встроены в итоговый PDF</small></label>{files.length>0&&<ul className="report-files">{files.map(file=><li key={`${file.name}-${file.size}`}><div><b>{file.name}</b><small>{(file.size/1024/1024).toFixed(2)} МБ</small></div><button type="button" onClick={()=>setFiles(value=>value.filter(item=>item!==file))}>×</button></li>)}</ul>}<button className="primary" disabled={busy} type="submit">{busy?"Формируем отчёт…":"Сформировать PDF и завершить"}</button></form>}
        {reports.length>0&&<section className="saved-reports"><h3>Сохранённые отчёты</h3>{reports.map(report=><article key={report.id}><div><b>{report.description}</b><small>Автор: {report.author_user_id}</small></div><div className="saved-report-files">{(reportFiles[report.id]||[]).map(file=><span key={file.id}><button onClick={()=>download(file)}>{file.content_type==="application/pdf"?"PDF":"Файл"} · {file.name}</button>{["admin","dispatcher"].includes(role)&&<button className="file-delete" onClick={()=>removeStoredFile(report.id,file)} aria-label={`Удалить ${file.name}`}>×</button>}</span>)}</div></article>)}</section>}
        {history.length>0&&<section className="ticket-history"><h3>История статусов</h3>{history.map(item=><div key={item.id}><i>●</i><span><b>{item.old_status?`${statusNames[item.old_status]||item.old_status} → `:""}{statusNames[item.new_status]||item.new_status}</b><small>{item.comment||"Без комментария"} · {item.changed_by||"Система"}</small></span><time>{new Date(item.created_at*1000).toLocaleString("ru-RU")}</time></div>)}</section>}
      </article>
    </div>}
  </section>;
}
