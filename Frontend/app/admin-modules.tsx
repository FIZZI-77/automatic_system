"use client";
/* eslint-disable react-hooks/set-state-in-effect */

import { FormEvent, ReactNode, useCallback, useEffect, useState } from "react";
import { api, config, Role, Session, type Ticket } from "./api";
import { loadBrigades, type BrigadeRecord } from "./brigade-store";
import { ReadableDetails } from "./readable-details";
import { qualificationLabel, qualificationStateClass } from "./qualification-labels";

type Notice = (message: string) => void;
type Dict = Record<string, unknown>;

function text(value: unknown, fallback: unknown = "—") {
  if (value === null || value === undefined || value === "") return String(fallback);
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function timestamp(value: unknown) {
  const source = typeof value === "object" && value !== null && "seconds" in value
    ? (value as { seconds?: unknown }).seconds
    : value;
  const number = Number(source);
  if (!Number.isFinite(number) || number <= 0) return "—";
  return new Date(number > 10_000_000_000 ? number : number * 1000).toLocaleString("ru-RU");
}

function enumLabel(value: unknown, labels: string[]) {
  return typeof value === "number" ? (labels[value] || "UNKNOWN") : text(value, "UNKNOWN");
}

const predictionRiskNames:Record<string,string>={UNKNOWN:"Не определён",LOW:"Низкий",MEDIUM:"Средний",HIGH:"Высокий",CRITICAL:"Критический"};
const predictionActions:Record<string,string>={
  "normal scheduled maintenance":"Продолжать плановое обслуживание",
  "shorten inspection interval":"Сократить интервал между осмотрами",
  "priority inspection and preventive repair":"Провести приоритетный осмотр и профилактический ремонт",
  "immediate inspection and replacement planning":"Немедленно осмотреть объект и запланировать замену",
};
const predictionFactors:Record<string,string>={
  "service life is nearly exhausted":"Срок службы близок к окончанию",
  "repeated failures within 90 days":"За последние 90 дней были повторные неисправности",
  "inspection is overdue":"Плановый осмотр просрочен",
  "poor latest inspection condition":"Последний осмотр показал неудовлетворительное состояние",
};

function predictionValue(source:Dict,key:string){const prediction=(source.prediction&&typeof source.prediction==="object"?source.prediction:source) as Dict;return prediction[key]}
function AssetPredictionCard({data}:{data:Dict}){
  const rawLevel=predictionValue(data,"risk_level"),level=typeof rawLevel==="number"?riskLevels[rawLevel]||"UNKNOWN":text(rawLevel,"UNKNOWN").replace("RISK_LEVEL_","");
  const score=Math.max(0,Math.min(100,Number(predictionValue(data,"risk_score")||0))),probability=Math.max(0,Math.min(100,Number(predictionValue(data,"failure_probability_90d")||0)));
  const factors=Array.isArray(predictionValue(data,"factors"))?predictionValue(data,"factors") as unknown[]:[];
  const calculated=predictionValue(data,"calculated_at"),calculatedText=calculated?timestamp(typeof calculated==="object"&&calculated!==null&&"seconds" in calculated?(calculated as {seconds:unknown}).seconds:calculated):"—";
  return <section className={`asset-prediction ${level.toLowerCase()}`}><div className="prediction-heading"><div><span>Прогноз состояния</span><h3>{predictionRiskNames[level]||level} риск</h3></div><strong>{Math.round(probability)}<small>%</small></strong></div><p>Вероятность неисправности в течение ближайших 90 дней</p><div className="prediction-meter"><i style={{width:`${probability}%`}}/></div><div className="prediction-facts"><div><span>Оценка риска</span><b>{score.toFixed(1)} из 100</b></div><div><span>Рассчитано</span><b>{calculatedText}</b></div></div><div className="prediction-recommendation"><span>Что рекомендуется сделать</span><b>{predictionActions[text(predictionValue(data,"recommended_action"))]||text(predictionValue(data,"recommended_action"),"Продолжать наблюдение")}</b></div><div className="prediction-factors"><span>Что повлияло на прогноз</span>{factors.length?<ul>{factors.map((factor,index)=><li key={index}>{predictionFactors[text(factor)]||text(factor)}</li>)}</ul>:<p>Существенных факторов риска не обнаружено.</p>}</div></section>
}

const assetStatuses = ["UNKNOWN", "PLANNED", "INSTALLED", "ACTIVE", "DAMAGED", "UNDER_REPAIR", "NEEDS_REPLACEMENT", "REPLACED", "DECOMMISSIONED"];
const riskLevels = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const dispatchStatuses = ["UNKNOWN", "PENDING", "RESERVED", "CONFIRMING", "ASSIGNED", "FAILED", "CANCELLED", "EXPIRED"];
const dispatchModes = ["UNKNOWN", "MANUAL", "AUTOMATIC"];
const routeStatuses = ["UNKNOWN", "PLANNED", "ACTIVE", "COMPLETED", "CANCELLED"];

function Modal({ title, children, onClose, className="" }: { title: string; children: ReactNode; onClose: () => void; className?: string }) {
  return <div className="ops-modal" role="presentation" onMouseDown={event=>{if(event.target===event.currentTarget)onClose()}}><div className={`ops-modal-card ${className}`} role="dialog" aria-modal="true"><button className="modal-close" onClick={onClose}>×</button><span className="eyebrow">Рабочая форма</span><h2>{title}</h2>{children}</div></div>;
}

function Empty({ children }: { children: ReactNode }) { return <div className="ops-empty">{children}</div>; }

type Asset = { id: string; department_id: string; type: string; name: string; address?: string; district?: string; status?: string; risk_level?: string; criticality?: number; geometry_geo_json?: string };

export function AssetsPage({ session, onNotice }: { session: Session; onNotice: Notice }) {
  const demo = session.accessToken === "demo";
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selected, setSelected] = useState<Asset>();
  const [modal, setModal] = useState<string>();
  const [details, setDetails] = useState<Dict>();
  const [detailsKind,setDetailsKind]=useState<"prediction"|"other">("other");
  const [filter, setFilter] = useState("");
  const [assetFilters,setAssetFilters]=useState({department_id:"",type:"",district:"",status:"",risk_level:""});
  const load = useCallback(async () => {
    if (demo) { setAssets([
      {id:"asset-demo-1",department_id:"dep-roads",type:"STREET_LIGHT",name:"Опора освещения №124",address:"Тверская улица, 12",district:"Тверской",status:"ACTIVE",risk_level:"LOW",criticality:.35},
      {id:"asset-demo-2",department_id:"dep-utilities",type:"FIRE_HYDRANT",name:"Пожарный гидрант №77",address:"Большая Дмитровка, 18",district:"Тверской",status:"DEGRADED",risk_level:"HIGH",criticality:.9},
      {id:"asset-demo-3",department_id:"dep-roads",type:"ROAD_SIGN",name:"Дорожный знак 3.27",address:"Страстной бульвар, 6",district:"Тверской",status:"UNDER_REPAIR",risk_level:"MEDIUM",criticality:.55},
    ]); return; }
    try { const result = await api<{assets: (Asset & {status?:unknown;risk_level?:unknown})[]}>(config.endpoints.assetsList, {limit:200,offset:0,...Object.fromEntries(Object.entries(assetFilters).filter(([,value])=>value))}, "POST", session.accessToken); setAssets((result.assets || []).map(item=>({...item,status:enumLabel(item.status,assetStatuses),risk_level:enumLabel(item.risk_level,riskLevels)}))); }
    catch (error) { onNotice(error instanceof Error ? error.message : "Не удалось загрузить реестр инфраструктуры"); }
  }, [assetFilters, demo, onNotice, session.accessToken]);
  useEffect(() => { void load(); }, [load]);

  async function create(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); const d = new FormData(e.currentTarget);
    const payload = {department_id:String(d.get("department_id")),type:String(d.get("type")),name:String(d.get("name")),address:String(d.get("address")),district:String(d.get("district")),geometry_geo_json:JSON.stringify({type:"Point",coordinates:[Number(d.get("longitude")),Number(d.get("latitude"))]}),criticality:Number(d.get("criticality")),inspection_interval_days:Number(d.get("inspection_interval_days"))};
    if (!demo) await api(config.endpoints.assetsCreate, payload, "POST", session.accessToken);
    setModal(undefined); await load(); onNotice("Объект инфраструктуры сохранён");
  }
  async function updateAsset(e:FormEvent<HTMLFormElement>){e.preventDefault();if(!selected)return;const d=new FormData(e.currentTarget),payload={asset_id:selected.id,name:String(d.get("name")),address:String(d.get("address")),contractor:String(d.get("contractor")),criticality:Number(d.get("criticality"))};if(!demo)await api(config.endpoints.assetsUpdate,payload,"POST",session.accessToken);const next={...selected,name:payload.name,address:payload.address,criticality:payload.criticality};setSelected(next);setAssets(items=>items.map(item=>item.id===next.id?next:item));setModal(undefined);onNotice("Паспорт объекта обновлён")}
  async function changeStatus(status: string) {
    if (!selected) return; if (!demo) await api(config.endpoints.assetsStatus,{asset_id:selected.id,status,reason:"Изменено из реестра"},"POST",session.accessToken);
    setAssets(items=>items.map(item=>item.id===selected.id?{...item,status}:item)); setSelected({...selected,status}); onNotice("Статус объекта обновлён");
  }
  async function operation(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); if (!selected || !modal) return; const d=new FormData(e.currentTarget); let endpoint="", payload:Dict={asset_id:selected.id};
    if(modal==="incident"){endpoint=config.endpoints.assetsIncident;payload={...payload,failure_type:String(d.get("kind")),description:String(d.get("description")),source:"WEB",priority:String(d.get("priority"))}}
    if(modal==="inspection"){endpoint=config.endpoints.assetsInspection;payload={...payload,kind:String(d.get("kind")),result:String(d.get("description")),recommendation:String(d.get("recommendation")),defect_found:d.get("defect")!==null,condition_score:Number(d.get("score"))}}
    if(modal==="repair"){endpoint=config.endpoints.assetsRepair;payload={...payload,description:String(d.get("description")),replaced_components:String(d.get("recommendation")),duration_minutes:Number(d.get("duration"))}}
    if(modal==="maintenance"){endpoint=config.endpoints.assetsMaintenanceCreate;payload={...payload,kind:String(d.get("kind")),interval_days:Number(d.get("duration")),next_due_at:new Date(String(d.get("date"))).toISOString()}}
    setDetailsKind("other");if(!demo) setDetails(await api<Dict>(endpoint,payload,"POST",session.accessToken)); setModal(undefined); onNotice("Операция по объекту зарегистрирована");
  }
  async function predict(){if(!selected)return;setDetailsKind("prediction");setDetails(demo?{prediction:{asset_id:selected.id,risk_score:28.4,risk_level:"LOW",failure_probability_90d:18.7,factors:["inspection is overdue"],recommended_action:"normal scheduled maintenance",calculated_at:{seconds:Math.floor(Date.now()/1000)}}}:await api<Dict>(config.endpoints.assetsPrediction,{asset_id:selected.id},"POST",session.accessToken))}
  async function recalculate(){const result=demo?{updated:1}:await api<Dict>(config.endpoints.assetsRisksRecalculate,{},"POST",session.accessToken);setDetailsKind("other");setDetails(result);onNotice("Риски пересчитаны")}
  async function nearby(){const result=demo?{assets}:await api<Dict>(config.endpoints.assetsNearby,{latitude:55.751244,longitude:37.618423,radius_meters:5000,limit:100},"POST",session.accessToken);setDetailsKind("other");setDetails(result);onNotice("Найдены объекты в радиусе 5 км от центра Москвы")}
  async function due(){const result=demo?{plans:[]}:await api<Dict>(config.endpoints.assetsMaintenanceDue,{due_before:new Date(Date.now()+30*86400000).toISOString(),limit:100,offset:0},"POST",session.accessToken);setDetailsKind("other");setDetails(result);onNotice("Загружен план обслуживания на 30 дней")}
  async function summary(){const result=demo?{total:assets.length}:await api<Dict>(config.endpoints.analyticsAssetsSummary,{filter:{}},"POST",session.accessToken);setDetailsKind("other");setDetails(result);onNotice("Сводка Asset Analytics загружена")}
  const visible=assets.filter(item=>`${item.name} ${item.type} ${item.address}`.toLowerCase().includes(filter.toLowerCase()));
  return <section className="ops-page asset-page"><div className="ops-head"><div><span className="eyebrow">Asset Service</span><h2>Реестр городской инфраструктуры</h2><p>Паспорта объектов, состояние, осмотры, ремонты и обслуживание.</p></div><div><button className="ghost" onClick={()=>void nearby()}>Рядом</button><button className="ghost" onClick={()=>void due()}>План ТО</button><button className="ghost" onClick={()=>void summary()}>Сводка</button><button className="ghost" onClick={recalculate}>Риски</button><button className="primary" onClick={()=>setModal("create")}>+ Объект</button></div></div>
    <div className="service-filters"><label>Департамент<input value={assetFilters.department_id} onChange={e=>setAssetFilters(v=>({...v,department_id:e.target.value}))} placeholder="UUID департамента"/></label><label>Тип<input value={assetFilters.type} onChange={e=>setAssetFilters(v=>({...v,type:e.target.value}))} placeholder="STREET_LIGHT"/></label><label>Район<input value={assetFilters.district} onChange={e=>setAssetFilters(v=>({...v,district:e.target.value}))} placeholder="Тверской"/></label><label>Состояние<select value={assetFilters.status} onChange={e=>setAssetFilters(v=>({...v,status:e.target.value}))}><option value="">Все</option>{assetStatuses.slice(1).map(value=><option key={value}>{value}</option>)}</select></label><label>Риск<select value={assetFilters.risk_level} onChange={e=>setAssetFilters(v=>({...v,risk_level:e.target.value}))}><option value="">Все</option>{riskLevels.slice(1).map(value=><option key={value}>{value}</option>)}</select></label><button onClick={()=>setAssetFilters({department_id:"",type:"",district:"",status:"",risk_level:""})}>Сбросить</button></div>
    <div className="ops-toolbar"><input placeholder="Поиск по названию, типу или адресу" value={filter} onChange={e=>setFilter(e.target.value)}/><b>{visible.length} объектов</b></div>
    <div className={`ops-layout ${selected?"selected":""}`}><div className="ops-grid">{visible.map(item=><button key={item.id} className={selected?.id===item.id?"selected":""} onClick={()=>{setSelected(item);setDetails(undefined)}}><span className={`ops-state ${(item.status||"unknown").toLowerCase()}`}>● {item.status||"UNKNOWN"}</span><h3>{item.name}</h3><p>{item.type} · {item.district||"округ не задан"}</p><small>{item.address||"Адрес не задан"}</small><div><b>Риск: {item.risk_level||"—"}</b><span>Критичность {Math.round((item.criticality||0)*100)}%</span></div></button>)}</div>{!visible.length&&<Empty>В реестре пока нет объектов.</Empty>}
      {selected&&<aside className="ops-detail asset-detail"><button className="detail-close" onClick={()=>setSelected(undefined)}>×</button><span className="eyebrow">Паспорт объекта</span><h2>{selected.name}</h2><p>{selected.address}</p><dl><div><dt>ID</dt><dd>{selected.id}</dd></div><div><dt>Тип</dt><dd>{selected.type}</dd></div><div><dt>Район</dt><dd>{selected.district||"—"}</dd></div><div><dt>Риск</dt><dd>{predictionRiskNames[selected.risk_level||""]||selected.risk_level||"—"}</dd></div></dl><label>Состояние<select value={selected.status||"ACTIVE"} onChange={e=>void changeStatus(e.target.value)}><option value="ACTIVE">Активен</option><option value="DEGRADED">Ухудшено</option><option value="FAILED">Неисправен</option><option value="UNDER_REPAIR">На ремонте</option><option value="DECOMMISSIONED">Выведен</option></select></label><div className="ops-actions"><button onClick={()=>setModal("edit")}>Изменить</button><button onClick={()=>setModal("incident")}>Инцидент</button><button onClick={()=>setModal("inspection")}>Осмотр</button><button onClick={()=>setModal("repair")}>Ремонт</button><button onClick={()=>setModal("maintenance")}>ТО</button><button onClick={()=>void predict()}>Прогноз</button></div>{details&&(detailsKind==="prediction"?<AssetPredictionCard data={details}/>:<ReadableDetails data={details}/>)}</aside>}</div>
    {modal==="create"&&<Modal title="Новый объект инфраструктуры" onClose={()=>setModal(undefined)}><form onSubmit={create} className="ops-form"><label>Название<input name="name" required/></label><div><label>Департамент ID<input name="department_id" required/></label><label>Тип<input name="type" defaultValue="STREET_LIGHT" required/></label></div><label>Адрес<input name="address"/></label><label>Район<input name="district"/></label><div><label>Широта<input name="latitude" type="number" step="any" defaultValue="55.751244" required/></label><label>Долгота<input name="longitude" type="number" step="any" defaultValue="37.618423" required/></label></div><div><label>Критичность<input name="criticality" type="number" min="0" max="1" step="0.05" defaultValue="0.5"/></label><label>Осмотр, дней<input name="inspection_interval_days" type="number" defaultValue="30"/></label></div><button className="primary">Сохранить объект</button></form></Modal>}
    {selected&&modal==="edit"&&<Modal title="Изменить паспорт объекта" onClose={()=>setModal(undefined)}><form onSubmit={updateAsset} className="ops-form"><label>Название<input name="name" defaultValue={selected.name} required/></label><label>Адрес<input name="address" defaultValue={selected.address}/></label><label>Подрядчик<input name="contractor"/></label><label>Критичность<input name="criticality" type="number" min="0" max="1" step="0.05" defaultValue={selected.criticality}/></label><button className="primary">Сохранить</button></form></Modal>}
    {selected&&modal&&!["create","edit"].includes(modal)&&<Modal title={{incident:"Зарегистрировать инцидент",inspection:"Результат осмотра",repair:"Завершить ремонт",maintenance:"План обслуживания"}[modal]||"Операция"} onClose={()=>setModal(undefined)}><form onSubmit={operation} className="ops-form"><label>Вид работ / события<input name="kind" required/></label>{modal!=="maintenance"&&<label>Описание<textarea name="description" required rows={4}/></label>}{modal==="incident"&&<label>Приоритет<select name="priority"><option>MEDIUM</option><option>HIGH</option><option>EMERGENCY</option></select></label>}{modal==="inspection"&&<><label>Рекомендация<textarea name="recommendation"/></label><label>Оценка состояния<input name="score" type="number" min="0" max="1" step="0.05" defaultValue="0.8"/></label><label className="check"><input name="defect" type="checkbox"/> Обнаружен дефект</label></>}{modal==="repair"&&<><label>Заменённые компоненты<input name="recommendation"/></label><label>Длительность, минут<input name="duration" type="number" defaultValue="60"/></label></>}{modal==="maintenance"&&<><label>Интервал, дней<input name="duration" type="number" defaultValue="30"/></label><label>Следующая дата<input name="date" type="datetime-local" required/></label></>}<button className="primary">Сохранить</button></form></Modal>}
  </section>;
}

type SLARule={id:string;name:string;department_id?:string;category_id?:string;priority?:string|number;response_time_seconds:number;resolution_time_seconds:number;warning_percent:number;active:boolean;is_active?:boolean};
type Category={id:string;code:string;name:string;description?:string;is_active:boolean};
type CatalogDepartment={id:string;name:string};
function slaPriorityName(value:unknown){if(typeof value==="number")return ["","LOW","MEDIUM","HIGH","EMERGENCY"][value]||"";const source=text(value,"").toUpperCase();return source.replace("TICKET_PRIORITY_","").replace("PRIORITY_","")}

export function ServiceCatalogPage({session,onNotice}:{session:Session;onNotice:Notice}){
  const demo=session.accessToken==="demo",[tab,setTab]=useState<"sla"|"categories">("sla"),[rules,setRules]=useState<SLARule[]>([]),[categories,setCategories]=useState<Category[]>([]),[departments,setDepartments]=useState<CatalogDepartment[]>([]),[editing,setEditing]=useState<SLARule|Category>(),[modal,setModal]=useState(false),[formActive,setFormActive]=useState(true);
  const [catalogFilters,setCatalogFilters]=useState({department_id:"",category_id:"",priority:"",active:""});
  const load=useCallback(async()=>{if(demo){setRules([
    {id:"sla-demo-1",name:"Экстренное водоснабжение",priority:"EMERGENCY",response_time_seconds:600,resolution_time_seconds:7200,warning_percent:70,active:true},
    {id:"sla-demo-2",name:"Дорожные повреждения",priority:"HIGH",response_time_seconds:1800,resolution_time_seconds:14400,warning_percent:80,active:true},
    {id:"sla-demo-3",name:"Городское освещение",priority:"HIGH",response_time_seconds:1200,resolution_time_seconds:10800,warning_percent:75,active:true},
  ]);setCategories([
    {id:"cat-demo-1",code:"ROAD_DAMAGE",name:"Дорожное покрытие",description:"Ямы и повреждения полотна",is_active:true},
    {id:"cat-demo-2",code:"STREET_LIGHT",name:"Уличное освещение",description:"Фонари, опоры и электропитание",is_active:true},
    {id:"cat-demo-3",code:"WATER",name:"Водоснабжение",description:"Протечки и аварийные работы",is_active:true},
  ]);setDepartments([{id:"dep-roads",name:"Дорожное хозяйство"},{id:"dep-utilities",name:"Городское хозяйство"}]);return}try{const rulePayload={limit:100,offset:0,...(catalogFilters.department_id?{department_id:catalogFilters.department_id}:{}),...(catalogFilters.category_id?{category_id:catalogFilters.category_id}:{}),...(catalogFilters.priority?{priority:catalogFilters.priority}:{}),...(catalogFilters.active?{active:catalogFilters.active==="true"}:{})},categoryPayload={only_active:catalogFilters.active==="true",limit:100,offset:0};const [r,c,d]=await Promise.all([api<{rules:SLARule[]}>(config.endpoints.slaRulesList,rulePayload,"POST",session.accessToken),api<{categories:Category[]}>(config.endpoints.ticketCategoriesList,categoryPayload,"POST",session.accessToken),api<{departments:CatalogDepartment[]}>(config.endpoints.departmentsList,{limit:100,offset:0},"POST",session.accessToken)]);setRules((r.rules||[]).map(rule=>({...rule,priority:slaPriorityName(rule.priority),active:typeof rule.active==="boolean"?rule.active:Boolean(rule.is_active)})));setCategories(c.categories||[]);setDepartments(d.departments||[])}catch(error){onNotice(error instanceof Error?error.message:"Не удалось загрузить справочники")}},[catalogFilters,demo,onNotice,session.accessToken]);
  useEffect(()=>{void load()},[load]);
  async function save(e:FormEvent<HTMLFormElement>){e.preventDefault();const d=new FormData(e.currentTarget);if(tab==="sla"){const old=editing as SLARule|undefined,departmentId=String(d.get("department_id")||""),categoryId=String(d.get("category_id")||""),priority=String(d.get("priority")||""),base={name:String(d.get("name")),department_id:departmentId,category_id:categoryId,response_time_seconds:Number(d.get("response"))*60,resolution_time_seconds:Number(d.get("resolution"))*60,warning_percent:Number(d.get("warning")),...(priority?{priority}:{})},payload=old?{id:old.id,...base,active:formActive}:base;if(!demo)await api(old?config.endpoints.slaRulesUpdate:config.endpoints.slaRulesCreate,payload,"POST",session.accessToken)}else{const old=editing as Category|undefined,payload=old?{category_id:old.id,name:String(d.get("name")),description:String(d.get("description")),is_active:formActive}:{code:String(d.get("code")),name:String(d.get("name")),description:String(d.get("description"))};if(!demo)await api(old?config.endpoints.ticketCategoriesUpdate:config.endpoints.ticketCategoriesCreate,payload,"POST",session.accessToken)}setModal(false);setEditing(undefined);await load();onNotice("Справочник обновлён")}
  async function remove(){if(!editing)return;if(!demo)await api(tab==="sla"?config.endpoints.slaRulesDelete:config.endpoints.ticketCategoriesDelete,tab==="sla"?{id:editing.id}:{category_id:editing.id},"POST",session.accessToken);setModal(false);setEditing(undefined);await load();onNotice("Запись удалена")}
  const visibleRules=demo?rules.filter(rule=>(!catalogFilters.department_id||rule.department_id===catalogFilters.department_id)&&(!catalogFilters.category_id||rule.category_id===catalogFilters.category_id)&&(!catalogFilters.priority||rule.priority===catalogFilters.priority)&&(!catalogFilters.active||rule.active===(catalogFilters.active==="true"))):rules,visibleCategories=categories.filter(category=>!catalogFilters.active||category.is_active===(catalogFilters.active==="true"));
  return <section className="ops-page"><div className="ops-head"><div><span className="eyebrow">Настройки процессов</span><h2>Регламенты и категории</h2><p>Правила SLA и классификатор городских обращений.</p></div><button className="primary" onClick={()=>{setEditing(undefined);setFormActive(true);setModal(true)}}>+ Новая запись</button></div><div className="ops-tabs"><button className={tab==="sla"?"active":""} onClick={()=>setTab("sla")}>Правила SLA <b>{visibleRules.length}</b></button><button className={tab==="categories"?"active":""} onClick={()=>setTab("categories")}>Категории заявок <b>{visibleCategories.length}</b></button></div><div className="service-filters">{tab==="sla"&&<><label>Департамент<select value={catalogFilters.department_id} onChange={e=>setCatalogFilters(v=>({...v,department_id:e.target.value}))}><option value="">Все департаменты</option>{departments.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}</select></label><label>Категория<select value={catalogFilters.category_id} onChange={e=>setCatalogFilters(v=>({...v,category_id:e.target.value}))}><option value="">Все категории</option>{categories.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}</select></label><label>Приоритет<select value={catalogFilters.priority} onChange={e=>setCatalogFilters(v=>({...v,priority:e.target.value}))}><option value="">Все</option><option value="LOW">Низкий</option><option value="MEDIUM">Средний</option><option value="HIGH">Высокий</option><option value="EMERGENCY">Экстренный</option></select></label></>}<label>Активность<select value={catalogFilters.active} onChange={e=>setCatalogFilters(v=>({...v,active:e.target.value}))}><option value="">Все</option><option value="true">Активные</option><option value="false">Неактивные</option></select></label><button onClick={()=>setCatalogFilters({department_id:"",category_id:"",priority:"",active:""})}>Сбросить</button></div><div className="catalog-list">{tab==="sla"?visibleRules.map(rule=><button key={rule.id} onClick={()=>{setEditing(rule);setFormActive(Boolean(rule.active));setModal(true)}}><span className={`ops-state ${rule.active?"active":"inactive"}`}>● {rule.active?"Активен":"Выключен"}</span><h3>{rule.name}</h3><p>{{LOW:"Низкий",MEDIUM:"Средний",HIGH:"Высокий",EMERGENCY:"Экстренный"}[slaPriorityName(rule.priority)]||"Все приоритеты"}</p><small>{departments.find(item=>item.id===rule.department_id)?.name||"Все департаменты"} · {categories.find(item=>item.id===rule.category_id)?.name||"Все категории"}</small><div><b>Реакция {Math.round(rule.response_time_seconds/60)} мин</b><b>Решение {Math.round(rule.resolution_time_seconds/60)} мин</b><span>Предупреждение {rule.warning_percent}%</span></div></button>):visibleCategories.map(category=><button key={category.id} onClick={()=>{setEditing(category);setFormActive(Boolean(category.is_active));setModal(true)}}><span className={`ops-state ${category.is_active?"active":"inactive"}`}>● {category.is_active?"Активна":"Выключена"}</span><h3>{category.name}</h3><p>{category.code}</p><small>{category.description||"Без описания"}</small></button>)}</div>
    {modal&&<Modal className="catalog-rule-modal" title={editing?"Изменить запись":"Создать запись"} onClose={()=>{setModal(false);setEditing(undefined)}}><form key={`${tab}-${editing?.id||"new"}`} className="ops-form" onSubmit={save}>{tab==="sla"?<><label>Название<input name="name" defaultValue={(editing as SLARule)?.name} required/></label><div><label>Департамент<select name="department_id" defaultValue={(editing as SLARule)?.department_id||""}><option value="">Все департаменты</option>{departments.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}</select></label><label>Категория заявки<select name="category_id" defaultValue={(editing as SLARule)?.category_id||""}><option value="">Все категории</option>{categories.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}</select></label></div><label>Приоритет<select name="priority" defaultValue={slaPriorityName((editing as SLARule)?.priority)||""}><option value="">Любой приоритет</option><option value="LOW">Низкий</option><option value="MEDIUM">Средний</option><option value="HIGH">Высокий</option><option value="EMERGENCY">Экстренный</option></select></label><div><label>Срок реакции, мин<input name="response" type="number" min="1" defaultValue={Math.max(1,Math.round(((editing as SLARule)?.response_time_seconds||1800)/60))} required/></label><label>Срок выполнения, мин<input name="resolution" type="number" min="1" defaultValue={Math.max(1,Math.round(((editing as SLARule)?.resolution_time_seconds||14400)/60))} required/></label></div><label>Когда предупредить, % срока<input name="warning" type="number" min="1" max="99" defaultValue={(editing as SLARule)?.warning_percent||80}/></label>{editing&&<label className="check regulation-active"><input name="active" type="checkbox" checked={formActive} onChange={event=>setFormActive(event.target.checked)}/><span><b>{formActive?"Регламент активен":"Регламент выключен"}</b><small>{formActive?"Применяется к новым заявкам":"Не используется при расчёте SLA"}</small></span></label>}</>:<><label>Код<input name="code" defaultValue={(editing as Category)?.code} disabled={Boolean(editing)} required/></label><label>Название<input name="name" defaultValue={(editing as Category)?.name} required/></label><label>Описание<textarea name="description" rows={4} defaultValue={(editing as Category)?.description}/></label>{editing&&<label className="check regulation-active"><input name="active" type="checkbox" checked={formActive} onChange={event=>setFormActive(event.target.checked)}/><span><b>{formActive?"Категория активна":"Категория выключена"}</b><small>{formActive?"Доступна при создании заявок":"Скрыта из списка новых заявок"}</small></span></label>}</>}<div className="modal-buttons">{editing&&<button type="button" className="danger-action" onClick={()=>void remove()}>Удалить</button>}<button className="primary">Сохранить</button></div></form></Modal>}
  </section>
}

type Skill={id:string;code:string;name:string;description?:string;active:boolean};
type CertType={id:string;code:string;name:string;description?:string;default_validity_days?:number;requires_file:boolean;active:boolean};
type WorkProfile={work_profile:{id:string;position:string;status:string};user_profile:{full_name:string}};

function QualificationsPageLegacy({session,onNotice}:{session:Session;onNotice:Notice}){
 const demo=session.accessToken==="demo",[tab,setTab]=useState<"skills"|"certs"|"brigades"|"people">("skills"),[skills,setSkills]=useState<Skill[]>([]),[certs,setCerts]=useState<CertType[]>([]),[people,setPeople]=useState<WorkProfile[]>([]),[selectedProfile,setSelectedProfile]=useState<WorkProfile>(),[grants,setGrants]=useState<Dict[]>([]),[certifications,setCertifications]=useState<Dict[]>([]),[modal,setModal]=useState(false),[editing,setEditing]=useState<Skill|CertType>(),[brigades]=useState<BrigadeRecord[]>(loadBrigades),[selectedBrigade,setSelectedBrigade]=useState<BrigadeRecord>(),[brigadeSkills,setBrigadeSkills]=useState<Dict[]>([]);
 const load=useCallback(async()=>{if(demo){setSkills([{id:"skill-demo-1",code:"ROAD_REPAIR",name:"Ремонт дорожного покрытия",description:"Локальное восстановление асфальта",active:true},{id:"skill-demo-2",code:"ELECTRIC",name:"Электробезопасность",description:"Работы с сетями освещения",active:true},{id:"skill-demo-3",code:"WATER",name:"Аварийный ремонт водопровода",description:"Локализация и устранение течей",active:true}]);setCerts([{id:"cert-demo-1",code:"ROAD_CERT",name:"Безопасность дорожных работ",description:"Работы в зоне движения",default_validity_days:730,requires_file:true,active:true},{id:"cert-demo-2",code:"ELECTRIC_CERT",name:"Допуск к электроустановкам",description:"Группа электробезопасности",default_validity_days:365,requires_file:true,active:true}]);setPeople([{work_profile:{id:"work-demo-1",position:"Мастер дорожных работ",status:"ACTIVE"},user_profile:{full_name:"Алексей Смирнов"}},{work_profile:{id:"work-demo-2",position:"Аварийный техник",status:"ACTIVE"},user_profile:{full_name:"Ирина Волкова"}}]);return}try{const [s,c,p]=await Promise.all([api<{skills:Skill[]}>(config.endpoints.skillsList,{limit:100,offset:0},"POST",session.accessToken),api<{certification_types:CertType[]}>(config.endpoints.certificationTypesList,{limit:100,offset:0},"POST",session.accessToken),api<{work_profiles:WorkProfile[]}>(config.endpoints.workProfilesList,{limit:100,offset:0},"POST",session.accessToken)]);setSkills(s.skills||[]);setCerts(c.certification_types||[]);setPeople(p.work_profiles||[])}catch(error){onNotice(error instanceof Error?error.message:"Не удалось загрузить квалификации")}},[demo,onNotice,session.accessToken]);useEffect(()=>{void load()},[load]);
 async function loadPerson(person:WorkProfile){setSelectedProfile(person);if(demo){setGrants([{id:"grant-demo-1",skill_id:person.work_profile.id==="work-demo-1"?"skill-demo-1":"skill-demo-3",proficiency_level:"Эксперт",active:true}]);setCertifications([{id:"worker-cert-demo",certification_type_id:person.work_profile.id==="work-demo-1"?"cert-demo-1":"cert-demo-2",status:person.work_profile.id==="work-demo-1"?"VERIFIED":"PENDING"}]);return}const [g,c]=await Promise.all([api<{skill_grants:Dict[]}>(config.endpoints.workProfileSkillsList,{work_profile_id:person.work_profile.id},"POST",session.accessToken),api<{certifications:Dict[]}>(config.endpoints.workProfileCertificationsList,{work_profile_id:person.work_profile.id,limit:100,offset:0},"POST",session.accessToken)]);setGrants(g.skill_grants||[]);setCertifications(c.certifications||[])}
 async function loadBrigadeSkills(brigade:BrigadeRecord){setSelectedBrigade(brigade);if(demo){setBrigadeSkills([{id:`brigade-skill-${brigade.id}`,skill_id:brigade.id.includes("14")?"skill-demo-1":"skill-demo-3",skill:{id:brigade.id.includes("14")?"skill-demo-1":"skill-demo-3",name:brigade.id.includes("14")?"Ремонт дорожного покрытия":"Аварийный ремонт водопровода"}}]);return}const result=await api<{skills:Dict[]}>(config.endpoints.brigadeSkillsList,{brigade_id:brigade.id,active:true},"POST",session.accessToken);setBrigadeSkills(result.skills||[])}
 async function save(e:FormEvent<HTMLFormElement>){e.preventDefault();const d=new FormData(e.currentTarget);if(tab==="skills"){const payload={code:String(d.get("code")),name:String(d.get("name")),description:String(d.get("description"))};if(!demo)await api(editing?config.endpoints.skillsUpdate:config.endpoints.skillsCreate,editing?{id:editing.id,...payload}:payload,"POST",session.accessToken)}else if(tab==="certs"){const payload={code:String(d.get("code")),name:String(d.get("name")),description:String(d.get("description")),default_validity_days:Number(d.get("days")),requires_file:d.get("file")!==null};if(!demo)await api(editing?config.endpoints.certificationTypesUpdate:config.endpoints.certificationTypesCreate,editing?{id:editing.id,...payload}:payload,"POST",session.accessToken)}else if(tab==="brigades"&&selectedBrigade){if(!demo)await api(config.endpoints.brigadeSkillsAdd,{brigade_id:selectedBrigade.id,skill_id:String(d.get("skill_id"))},"POST",session.accessToken);await loadBrigadeSkills(selectedBrigade)}else if(selectedProfile){if(!demo)await api(config.endpoints.workProfileSkillsGrant,{work_profile_id:selectedProfile.work_profile.id,skill_id:String(d.get("skill_id")),proficiency_level:String(d.get("level")),reason:String(d.get("description"))},"POST",session.accessToken);await loadPerson(selectedProfile)}setModal(false);setEditing(undefined);await load();onNotice("Квалификация сохранена")}
 async function deactivate(){if(!editing||tab!=="skills")return;if(!demo)await api(config.endpoints.skillsDeactivate,{id:editing.id},"POST",session.accessToken);setModal(false);setEditing(undefined);await load();onNotice("Навык деактивирован")}
  async function removeBrigadeSkill(item:Dict){if(!selectedBrigade)return;const skill=item.skill as Dict|undefined,skillId=text(skill?.id,item.skill_id);if(!demo)await api(config.endpoints.brigadeSkillsRemove,{brigade_id:selectedBrigade.id,skill_id:skillId},"POST",session.accessToken);await loadBrigadeSkills(selectedBrigade);onNotice("Навык удалён у бригады")}
 async function removePersonGrant(item:Dict){if(!selectedProfile)return;if(!demo){await api(config.endpoints.workProfileSkillsRevoke,{id:text(item.id),reason:"Удалено администратором"},"POST",session.accessToken);await loadPerson(selectedProfile)}else setGrants(current=>current.filter(grant=>grant.id!==item.id));onNotice("Навык удалён у сотрудника")}
 async function removePersonCertification(item:Dict){if(!selectedProfile)return;if(!demo){await api(config.endpoints.workProfileCertificationsRevoke,{id:text(item.id),reason:"Удалено администратором"},"POST",session.accessToken);await loadPerson(selectedProfile)}else setCertifications(current=>current.filter(cert=>cert.id!==item.id));onNotice("Удостоверение удалено у сотрудника")}
 return <section className="ops-page"><div className="ops-head"><div><span className="eyebrow">Квалификации</span><h2>Навыки и допуски сотрудников</h2><p>Навыки служб, типы удостоверений и фактические допуски работников.</p></div><button className="primary" onClick={()=>{setEditing(undefined);setModal(true)}}>+ {tab==="skills"?"Навык":tab==="certs"?"Тип допуска":tab==="brigades"?"Навык бригаде":"Выдать навык"}</button></div><div className="ops-tabs"><button className={tab==="skills"?"active":""} onClick={()=>setTab("skills")}>Навыки <b>{skills.length}</b></button><button className={tab==="certs"?"active":""} onClick={()=>setTab("certs")}>Типы удостоверений <b>{certs.length}</b></button><button className={tab==="brigades"?"active":""} onClick={()=>setTab("brigades")}>Навыки бригад <b>{brigades.length}</b></button><button className={tab==="people"?"active":""} onClick={()=>setTab("people")}>Сотрудники <b>{people.length}</b></button></div>{["skills","certs"].includes(tab)?<div className="catalog-list">{(tab==="skills"?skills:certs).map(item=><button key={item.id} onClick={()=>{setEditing(item);setModal(true)}}><span className={`ops-state ${item.active?"active":"inactive"}`}>● {item.active?"ACTIVE":"INACTIVE"}</span><h3>{item.name}</h3><p>{item.code}</p><small>{item.description||"Без описания"}</small></button>)}</div>:tab==="brigades"?<div className={`ops-layout ${selectedBrigade?"selected":""}`}><div className="people-qualification-list">{brigades.map(brigade=><button key={brigade.id} onClick={()=>void loadBrigadeSkills(brigade)}><b>{brigade.name}</b><span>{brigade.specialization}</span><em>{brigade.status}</em></button>)}</div>{selectedBrigade&&<aside className="ops-detail"><button className="detail-close" onClick={()=>setSelectedBrigade(undefined)}>×</button><span className="eyebrow">Навыки бригады</span><h2>{selectedBrigade.name}</h2>{brigadeSkills.length?brigadeSkills.map((item,index)=><div className="data-row action-row" key={text(item.id,index)}><span><b>{text((item.skill as Dict)?.name,item.skill_id)}</b></span><button className="danger-action" onClick={()=>void removeBrigadeSkill(item)}>Удалить</button></div>):<Empty>Навыки не назначены</Empty>}</aside>}</div>:<div className={`ops-layout ${selectedProfile?"selected":""}`}><div className="people-qualification-list">{people.map(person=><button key={person.work_profile.id} onClick={()=>void loadPerson(person)} className={selectedProfile?.work_profile.id===person.work_profile.id?"selected":""}><b>{person.user_profile.full_name}</b><span>{person.work_profile.position}</span><em>{person.work_profile.status}</em></button>)}</div>{selectedProfile&&<aside className="ops-detail"><button className="detail-close" onClick={()=>setSelectedProfile(undefined)}>×</button><span className="eyebrow">Квалификация сотрудника</span><h2>{selectedProfile.user_profile.full_name}</h2><h3>Действующие навыки</h3>{grants.length?grants.map((grant,index)=><div className="data-row" key={text(grant.id,index)}><b>{skills.find(s=>s.id===grant.skill_id)?.name||text(grant.skill_id)}</b><span>{text(grant.proficiency_level,"Уровень не задан")}</span></div>):<Empty>Навыки не назначены</Empty>}<h3>Удостоверения</h3>{certifications.length?certifications.map((cert,index)=><div className="data-row" key={text(cert.id,index)}><b>{certs.find(c=>c.id===cert.certification_type_id)?.name||text(cert.certification_type_id)}</b><span>{text(cert.status)}</span></div>):<Empty>Удостоверений нет</Empty>}</aside>}</div>}{modal&&<Modal title={tab==="skills"?(editing?"Изменить навык":"Новый навык"):tab==="certs"?(editing?"Изменить тип удостоверения":"Новый тип удостоверения"):tab==="brigades"?"Назначить навык бригаде":"Выдать навык сотруднику"} onClose={()=>{setModal(false);setEditing(undefined)}}><form className="ops-form" onSubmit={save}>{["people","brigades"].includes(tab)?<><label>Навык<select name="skill_id">{skills.filter(s=>s.active).map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</select></label>{tab==="people"&&<><label>Уровень<input name="level" placeholder="например, эксперт"/></label><label>Основание<textarea name="description" required/></label></>}</>:<><label>Код<input name="code" defaultValue={editing?.code} required/></label><label>Название<input name="name" defaultValue={editing?.name} required/></label><label>Описание<textarea name="description" defaultValue={editing?.description}/></label>{tab==="certs"&&<><label>Срок действия, дней<input name="days" type="number" defaultValue={(editing as CertType)?.default_validity_days||365}/></label><label className="check"><input name="file" type="checkbox" defaultChecked={(editing as CertType)?.requires_file}/> Требуется файл удостоверения</label></>}</>}<div className="modal-buttons">{editing&&tab==="skills"&&<button type="button" className="danger-action" onClick={()=>void deactivate()}>Деактивировать</button>}<button className="primary">Сохранить</button></div></form></Modal>}</section>
}

export function QualificationsPage({session,onNotice}:{session:Session;onNotice:Notice}){
  const demo=session.accessToken==="demo";
  const [tab,setTab]=useState<"skills"|"certs"|"brigades"|"people">("skills");
  const [skills,setSkills]=useState<Skill[]>([]);
  const [certs,setCerts]=useState<CertType[]>([]);
  const [people,setPeople]=useState<WorkProfile[]>([]);
  const [selectedProfile,setSelectedProfile]=useState<WorkProfile>();
  const [grants,setGrants]=useState<Dict[]>([]);
  const [certifications,setCertifications]=useState<Dict[]>([]);
  const [modal,setModal]=useState(false);
  const [editing,setEditing]=useState<Skill|CertType>();
  const [brigades,setBrigades]=useState<BrigadeRecord[]>(()=>demo?loadBrigades():[]);
  const [selectedBrigade,setSelectedBrigade]=useState<BrigadeRecord>();
  const [brigadeSkills,setBrigadeSkills]=useState<Dict[]>([]);

  const load=useCallback(async()=>{
    if(demo){
      setSkills([
        {id:"skill-demo-1",code:"ROAD_REPAIR",name:"Ремонт дорожного покрытия",description:"Локальное восстановление асфальта",active:true},
        {id:"skill-demo-2",code:"ELECTRIC",name:"Электробезопасность",description:"Работы с сетями освещения",active:true},
        {id:"skill-demo-3",code:"WATER",name:"Аварийный ремонт водопровода",description:"Локализация и устранение течей",active:true},
      ]);
      setCerts([
        {id:"cert-demo-1",code:"ROAD_CERT",name:"Безопасность дорожных работ",description:"Работы в зоне движения",default_validity_days:730,requires_file:true,active:true},
        {id:"cert-demo-2",code:"ELECTRIC_CERT",name:"Допуск к электроустановкам",description:"Группа электробезопасности",default_validity_days:365,requires_file:true,active:true},
      ]);
      setPeople([
        {work_profile:{id:"work-demo-1",position:"Мастер дорожных работ",status:"ACTIVE"},user_profile:{full_name:"Алексей Смирнов"}},
        {work_profile:{id:"work-demo-2",position:"Аварийный техник",status:"ON_SHIFT"},user_profile:{full_name:"Ирина Волкова"}},
      ]);
      return;
    }
    try{
      const [skillResult,certResult,profileResult,brigadeResult]=await Promise.all([
        api<{skills:Skill[]}>(config.endpoints.skillsList,{limit:100,offset:0},"POST",session.accessToken),
        api<{certification_types:CertType[]}>(config.endpoints.certificationTypesList,{limit:100,offset:0},"POST",session.accessToken),
        api<{work_profiles:WorkProfile[]}>(config.endpoints.workProfilesList,{limit:100,offset:0},"POST",session.accessToken),
        api<{brigades:BrigadeRecord[]}>(config.endpoints.brigadesList,{limit:100,offset:0},"POST",session.accessToken),
      ]);
      setSkills(skillResult.skills||[]);
      setCerts(certResult.certification_types||[]);
      setPeople(profileResult.work_profiles||[]);
      setBrigades(brigadeResult.brigades||[]);
    }catch(error){onNotice(error instanceof Error?error.message:"Не удалось загрузить квалификации")}
  },[demo,onNotice,session.accessToken]);
  useEffect(()=>{void load()},[load]);

  async function loadPerson(person:WorkProfile){
    setSelectedProfile(person);
    if(demo){
      const road=person.work_profile.id==="work-demo-1";
      setGrants([{id:`grant-${person.work_profile.id}`,skill_id:road?"skill-demo-1":"skill-demo-3",proficiency_level:road?"Эксперт":"Специалист",source_type:"MANUAL",active:true}]);
      setCertifications([{id:`certificate-${person.work_profile.id}`,certification_type_id:road?"cert-demo-1":"cert-demo-2",status:road?"VERIFIED":"PENDING"}]);
      return;
    }
    const [grantResult,certResult]=await Promise.all([
      api<{skill_grants:Dict[]}>(config.endpoints.workProfileSkillsList,{work_profile_id:person.work_profile.id},"POST",session.accessToken),
      api<{certifications:Dict[]}>(config.endpoints.workProfileCertificationsList,{work_profile_id:person.work_profile.id,limit:100,offset:0},"POST",session.accessToken),
    ]);
    setGrants(grantResult.skill_grants||[]);
    setCertifications(certResult.certifications||[]);
  }

  async function loadBrigadeSkills(brigade:BrigadeRecord){
    setSelectedBrigade(brigade);
    if(demo){
      const road=brigade.id.includes("14");
      setBrigadeSkills([{id:`brigade-skill-${brigade.id}`,skill_id:road?"skill-demo-1":"skill-demo-3",skill:{id:road?"skill-demo-1":"skill-demo-3",name:road?"Ремонт дорожного покрытия":"Аварийный ремонт водопровода"}}]);
      return;
    }
    try{
      const result=await api<{skills:Dict[]}>(config.endpoints.brigadeSkillsList,{brigade_id:brigade.id,active:true},"POST",session.accessToken);
      setBrigadeSkills(result.skills||[]);
    }catch(error){
      setSelectedBrigade(undefined);
      setBrigadeSkills([]);
      onNotice(error instanceof Error?error.message:"Не удалось загрузить навыки бригады");
    }
  }

  async function save(event:FormEvent<HTMLFormElement>){
    event.preventDefault();
    const data=new FormData(event.currentTarget);
    if(tab==="skills"){
      const payload={code:String(data.get("code")),name:String(data.get("name")),description:String(data.get("description"))};
      if(!demo)await api(editing?config.endpoints.skillsUpdate:config.endpoints.skillsCreate,editing?{id:editing.id,...payload}:payload,"POST",session.accessToken);
    }else if(tab==="certs"){
      const payload={code:String(data.get("code")),name:String(data.get("name")),description:String(data.get("description")),default_validity_days:Number(data.get("days")),requires_file:data.get("file")!==null};
      if(!demo)await api(editing?config.endpoints.certificationTypesUpdate:config.endpoints.certificationTypesCreate,editing?{id:editing.id,...payload}:payload,"POST",session.accessToken);
    }else if(tab==="brigades"&&selectedBrigade){
      const skillId=String(data.get("skill_id"));
      if(demo){
        const skill=skills.find(item=>item.id===skillId);
        setBrigadeSkills(current=>[...current,{id:`brigade-skill-${Date.now()}`,skill_id:skillId,skill}]);
      }else{
        await api(config.endpoints.brigadeSkillsAdd,{brigade_id:selectedBrigade.id,skill_id:skillId},"POST",session.accessToken);
        await loadBrigadeSkills(selectedBrigade);
      }
    }else if(selectedProfile){
      const skillId=String(data.get("skill_id"));
      if(demo){
        setGrants(current=>[...current,{id:`grant-demo-${Date.now()}`,skill_id:skillId,proficiency_level:String(data.get("level"))||"Уровень не задан",source_type:"MANUAL",active:true}]);
      }else{
        await api(config.endpoints.workProfileSkillsGrant,{work_profile_id:selectedProfile.work_profile.id,skill_id:skillId,proficiency_level:String(data.get("level")),reason:String(data.get("description"))},"POST",session.accessToken);
        await loadPerson(selectedProfile);
      }
    }
    setModal(false);
    setEditing(undefined);
    if(tab==="skills"||tab==="certs")await load();
    onNotice("Квалификация сохранена");
  }

  async function deactivate(){
    if(!editing||tab!=="skills")return;
    if(!demo)await api(config.endpoints.skillsDeactivate,{id:editing.id},"POST",session.accessToken);
    setModal(false);setEditing(undefined);await load();onNotice("Навык деактивирован");
  }
  async function removeBrigadeSkill(item:Dict){
    if(!selectedBrigade)return;
    const skill=item.skill as Dict|undefined,skillId=text(skill?.id,item.skill_id);
    if(demo)setBrigadeSkills(current=>current.filter(value=>value.id!==item.id));
    else{await api(config.endpoints.brigadeSkillsRemove,{brigade_id:selectedBrigade.id,skill_id:skillId},"POST",session.accessToken);await loadBrigadeSkills(selectedBrigade)}
    onNotice("Навык удалён у бригады");
  }
  async function removePersonGrant(item:Dict){
    if(!selectedProfile)return;
    if(demo)setGrants(current=>current.filter(value=>value.id!==item.id));
    else{await api(config.endpoints.workProfileSkillsRevoke,{id:text(item.id),reason:"Удалено администратором"},"POST",session.accessToken);await loadPerson(selectedProfile)}
    onNotice("Навык удалён у сотрудника");
  }
  async function removePersonCertification(item:Dict){
    if(!selectedProfile)return;
    if(demo)setCertifications(current=>current.filter(value=>value.id!==item.id));
    else{await api(config.endpoints.workProfileCertificationsRevoke,{id:text(item.id),reason:"Удалено администратором"},"POST",session.accessToken);await loadPerson(selectedProfile)}
    onNotice("Удостоверение удалено у сотрудника");
  }

  const openCreate=()=>{setEditing(undefined);setModal(true)};
  const changeTab=(value:typeof tab)=>{setTab(value);setSelectedProfile(undefined);setSelectedBrigade(undefined)};
  return <section className="ops-page qualification-page">
    <div className="ops-head"><div><span className="eyebrow">Квалификации</span><h2>Навыки и допуски сотрудников</h2><p>Навыки служб, типы удостоверений и фактические допуски работников.</p></div><button className="primary" disabled={(tab==="people"&&!selectedProfile)||(tab==="brigades"&&!selectedBrigade)} onClick={openCreate}>+ {tab==="skills"?"Навык":tab==="certs"?"Тип удостоверения":tab==="brigades"?"Навык бригаде":"Навык сотруднику"}</button></div>
    <div className="ops-tabs">
      <button className={tab==="skills"?"active":""} onClick={()=>changeTab("skills")}>Навыки <b>{skills.length}</b></button>
      <button className={tab==="certs"?"active":""} onClick={()=>changeTab("certs")}>Типы удостоверений <b>{certs.length}</b></button>
      <button className={tab==="brigades"?"active":""} onClick={()=>changeTab("brigades")}>Навыки бригад <b>{brigades.length}</b></button>
      <button className={tab==="people"?"active":""} onClick={()=>changeTab("people")}>Сотрудники <b>{people.length}</b></button>
    </div>
    {(tab==="skills"||tab==="certs")&&<div className="catalog-list">{(tab==="skills"?skills:certs).map(item=><button key={item.id} onClick={()=>{setEditing(item);setModal(true)}}><span className={`ops-state ${qualificationStateClass(item.active?"ACTIVE":"INACTIVE")}`}>● {qualificationLabel(item.active?"ACTIVE":"INACTIVE")}</span><h3>{item.name}</h3><p>{item.code}</p><small>{item.description||"Без описания"}</small></button>)}</div>}
    {tab==="brigades"&&<div className={`ops-layout ${selectedBrigade?"selected":""}`}><div className="people-qualification-list">{brigades.map(brigade=><button key={brigade.id} className={selectedBrigade?.id===brigade.id?"selected":""} onClick={()=>void loadBrigadeSkills(brigade)}><b>{brigade.name}</b><span>{brigade.specialization}</span><em className={`ops-state ${qualificationStateClass(brigade.status)}`}>{qualificationLabel(brigade.status)}</em></button>)}</div>{selectedBrigade&&<aside className="ops-detail qualification-person-detail"><button className="detail-close" onClick={()=>setSelectedBrigade(undefined)}>×</button><span className="eyebrow">Навыки бригады</span><h2>{selectedBrigade.name}</h2><div className="qualification-subhead"><h3>Назначенные навыки</h3><button className="ghost small" onClick={openCreate}>+ Добавить</button></div>{brigadeSkills.length?brigadeSkills.map((item,index)=><div className="data-row action-row" key={text(item.id,index)}><span><b>{text((item.skill as Dict)?.name ?? skills.find(skill=>skill.id===item.skill_id)?.name,item.skill_id)}</b></span><button className="danger-action" onClick={()=>void removeBrigadeSkill(item)}>Удалить</button></div>):<Empty>Навыки не назначены</Empty>}</aside>}</div>}
    {tab==="people"&&<div className={`ops-layout ${selectedProfile?"selected":""}`}><div className="people-qualification-list">{people.map(person=><button key={person.work_profile.id} className={selectedProfile?.work_profile.id===person.work_profile.id?"selected":""} onClick={()=>void loadPerson(person)}><b>{person.user_profile.full_name}</b><span>{person.work_profile.position}</span><em className={`ops-state ${qualificationStateClass(person.work_profile.status)}`}>{qualificationLabel(person.work_profile.status)}</em></button>)}</div>{selectedProfile&&<aside className="ops-detail qualification-person-detail"><button className="detail-close" onClick={()=>setSelectedProfile(undefined)}>×</button><span className="eyebrow">Квалификация сотрудника</span><h2>{selectedProfile.user_profile.full_name}</h2><div className="qualification-subhead"><h3>Действующие навыки</h3><button className="ghost small" onClick={openCreate}>+ Добавить</button></div>{grants.filter(item=>item.active!==false).length?grants.filter(item=>item.active!==false).map((grant,index)=><div className="data-row action-row" key={text(grant.id,index)}><span><b>{skills.find(skill=>skill.id===grant.skill_id)?.name||text(grant.skill_id)}</b><small>{text(grant.proficiency_level,"Уровень не задан")} · {qualificationLabel(grant.source_type)}</small></span><button className="danger-action" onClick={()=>void removePersonGrant(grant)}>Удалить</button></div>):<Empty>Навыки не назначены</Empty>}<div className="qualification-subhead"><h3>Удостоверения</h3></div>{certifications.length?certifications.map((cert,index)=><div className="data-row action-row" key={text(cert.id,index)}><span><b>{certs.find(item=>item.id===cert.certification_type_id)?.name||text(cert.certification_type_id)}</b><small className={`ops-state ${qualificationStateClass(cert.status)}`}>{qualificationLabel(cert.status)}</small></span>{["PENDING","VERIFIED"].includes(String(cert.status))&&<button className="danger-action" onClick={()=>void removePersonCertification(cert)}>Удалить</button>}</div>):<Empty>Удостоверений нет</Empty>}</aside>}</div>}
    {modal&&<Modal title={tab==="skills"?(editing?"Изменить навык":"Новый навык"):tab==="certs"?(editing?"Изменить тип удостоверения":"Новый тип удостоверения"):tab==="brigades"?"Назначить навык бригаде":"Выдать навык сотруднику"} onClose={()=>{setModal(false);setEditing(undefined)}}><form className="ops-form" onSubmit={save}>{(tab==="people"||tab==="brigades")?<><label>Навык<select name="skill_id" required>{skills.filter(item=>item.active).map(item=><option key={item.id} value={item.id}>{item.name}</option>)}</select></label>{tab==="people"&&<><label>Уровень<input name="level" placeholder="Например: эксперт" required/></label><label>Основание<textarea name="description" rows={3} required/></label></>}</>:<><label>Код<input name="code" defaultValue={editing?.code} required/></label><label>Название<input name="name" defaultValue={editing?.name} required/></label><label>Описание<textarea name="description" defaultValue={editing?.description}/></label>{tab==="certs"&&<><label>Срок действия, дней<input name="days" type="number" min="1" defaultValue={(editing as CertType)?.default_validity_days||365}/></label><label className="check"><input name="file" type="checkbox" defaultChecked={(editing as CertType)?.requires_file}/> Требуется файл удостоверения</label></>}</>}<div className="modal-buttons">{editing&&tab==="skills"&&<button type="button" className="danger-action" onClick={()=>void deactivate()}>Деактивировать</button>}<button className="primary">Сохранить</button></div></form></Modal>}
  </section>;
}

export function OperationsPage({session,role,tickets,onNotice}:{session:Session;role:Role;tickets:Ticket[];onNotice:Notice}){
 const demo=session.accessToken==="demo",[tab,setTab]=useState<"dispatch"|"routes"|"templates"|"deliveries">("dispatch"),[items,setItems]=useState<Dict[]>([]),[selected,setSelected]=useState<Dict>(),[modal,setModal]=useState(false);
 const [operationFilters,setOperationFilters]=useState({ticket_id:"",brigade_id:"",status:"",event_type:"",channel:""});
 const load=useCallback(async()=>{if(demo){const now=Math.floor(Date.now()/1000),fixtures:Record<typeof tab,Dict[]>={dispatch:[{id:"dispatch-demo-1",ticket_id:"INC-1042",brigade_id:"Бригада №7",route_id:"route-demo-2",mode:"AUTO",status:"ASSIGNED",version:3,created_at:now-2700},{id:"dispatch-demo-2",ticket_id:"INC-1038",brigade_id:"Бригада №14",route_id:"route-demo-1",mode:"MANUAL",status:"ASSIGNED",version:2,created_at:now-1500},{id:"dispatch-demo-3",ticket_id:"INC-1017",mode:"AUTO",status:"FAILED",failure_reason:"Нет подходящей свободной бригады",version:1,created_at:now-7200}],routes:[{id:"route-demo-1",ticket_id:"INC-1038",brigade_id:"Бригада №14",status:"PLANNED",calculation:{distance_meters:2400,duration_seconds:540},created_at:now-1500},{id:"route-demo-2",ticket_id:"INC-1042",brigade_id:"Бригада №7",status:"ACTIVE",calculation:{distance_meters:1800,duration_seconds:420},created_at:now-2700}],templates:[{id:"template-demo-1",event_type:"ticket.assigned",channel:"IN_APP",status:"ACTIVE",subject:"Бригада назначена",body:"По заявке назначена городская бригада",created_at:now-86400},{id:"template-demo-2",event_type:"sla.warning",channel:"EMAIL",status:"ACTIVE",subject:"Риск нарушения SLA",body:"Приближается контрольный срок",created_at:now-86400}],deliveries:[{id:"delivery-demo-1",event_type:"ticket.assigned",channel:"IN_APP",status:"SENT",subject:"demo.user@city.local",attempts:1,created_at:now-1500},{id:"delivery-demo-2",event_type:"sla.warning",channel:"PUSH",status:"FAILED",subject:"demo-dispatcher-device",attempts:3,created_at:now-600}]};setItems(fixtures[tab]);setSelected(undefined);return}try{let endpoint=config.endpoints.dispatchList,key="operations";const body:Dict={limit:100,offset:0};if(tab==="dispatch"||tab==="routes"){if(operationFilters.ticket_id)body.ticket_id=operationFilters.ticket_id;if(operationFilters.brigade_id)body.brigade_id=operationFilters.brigade_id;if(operationFilters.status)body.status=operationFilters.status}if(tab==="routes"){endpoint=config.endpoints.routesList;key="routes"}if(tab==="templates"){endpoint=config.endpoints.notificationTemplatesList;key="templates";if(operationFilters.event_type)body.event_type=operationFilters.event_type;if(operationFilters.channel)body.channel=operationFilters.channel}if(tab==="deliveries"){endpoint=config.endpoints.notificationDeliveriesList;key="deliveries";if(operationFilters.status)body.status=operationFilters.status;if(operationFilters.channel)body.channel=operationFilters.channel}const result=await api<Record<string,Dict[]>>(endpoint,body,"POST",session.accessToken);const normalized=(result[key]||[]).map(item=>tab==="dispatch"?{...item,status:enumLabel(item.status,dispatchStatuses),mode:enumLabel(item.mode,dispatchModes),created_at:item.created_at??item.created_at_unix_ms}:tab==="routes"?{...item,status:enumLabel(item.status,routeStatuses),created_at:item.created_at??item.created_at_unix_ms}:item);setItems(normalized);setSelected(undefined)}catch(error){onNotice(error instanceof Error?error.message:"Не удалось загрузить операционный журнал")}},[demo,onNotice,operationFilters,session.accessToken,tab]);useEffect(()=>{void load()},[load]);
 async function routeStatus(status:string){if(!selected)return;if(!demo)await api(config.endpoints.routesStatus,{id:selected.id,status},"POST",session.accessToken);await load();onNotice("Статус маршрута обновлён")}
 async function cancelDispatch(){if(!selected)return;if(!demo)await api(config.endpoints.dispatchCancel,{id:selected.id,cancelled_by:session.user?.user_id,expected_version:Number(selected.version||1),reason:"Отменено диспетчером"},"POST",session.accessToken);await load();onNotice("Назначение отменено")}
 async function saveTemplate(e:FormEvent<HTMLFormElement>){e.preventDefault();const d=new FormData(e.currentTarget);if(!demo)await api(config.endpoints.notificationTemplatesUpsert,{event_type:String(d.get("event_type")),channel:String(d.get("channel")),subject:String(d.get("subject")),body:String(d.get("body")),active:true},"POST",session.accessToken);setModal(false);await load();onNotice("Шаблон уведомления сохранён")}
 function applyFilters(e:FormEvent<HTMLFormElement>){e.preventDefault();const d=new FormData(e.currentTarget);setOperationFilters({ticket_id:String(d.get("ticket_id")||""),brigade_id:String(d.get("brigade_id")||""),status:String(d.get("status")||""),event_type:String(d.get("event_type")||""),channel:String(d.get("channel")||"")})}
 const tabs:[typeof tab,string][]=[["dispatch","Назначения"],["routes","Маршруты"],["templates","Шаблоны"],["deliveries","Доставка"]];
 const allowedTicketIds=new Set(tickets.map(item=>item.id.toLowerCase()));
 const departmentItems=role==="dispatcher"&&(tab==="dispatch"||tab==="routes")?items.filter(item=>!item.ticket_id||allowedTicketIds.has(text(item.ticket_id).toLowerCase())):items;
 const visibleItems=demo?departmentItems.filter(item=>(!operationFilters.ticket_id||text(item.ticket_id).toLowerCase().includes(operationFilters.ticket_id.toLowerCase()))&&(!operationFilters.brigade_id||text(item.brigade_id).toLowerCase().includes(operationFilters.brigade_id.toLowerCase()))&&(!operationFilters.status||text(item.status).toUpperCase()===operationFilters.status)&&(!operationFilters.event_type||text(item.event_type).toLowerCase().includes(operationFilters.event_type.toLowerCase()))&&(!operationFilters.channel||text(item.channel).toUpperCase()===operationFilters.channel)):departmentItems;
 return <section className="ops-page"><div className="ops-head"><div><span className="eyebrow">Операционный контроль</span><h2>Маршруты, назначения и доставка</h2><p>Состояние серверных процессов и детальная информация по каждой операции.</p></div>{tab==="templates"&&role==="admin"&&<button className="primary" onClick={()=>setModal(true)}>+ Шаблон</button>}</div><div className="ops-tabs">{tabs.filter(([id])=>role==="admin"||!(["templates","deliveries"] as string[]).includes(id)).map(([id,label])=><button key={id} className={tab===id?"active":""} onClick={()=>setTab(id)}>{label}</button>)}</div><form className="service-filters" onSubmit={applyFilters}>{(tab==="dispatch"||tab==="routes")&&<><label>Заявка<input name="ticket_id" defaultValue={operationFilters.ticket_id} placeholder="UUID или номер"/></label><label>Бригада<input name="brigade_id" defaultValue={operationFilters.brigade_id} placeholder="UUID"/></label><label>Статус<select name="status" defaultValue={operationFilters.status}><option value="">Все</option>{(tab==="dispatch"?dispatchStatuses:routeStatuses).slice(1).map(value=><option key={value}>{value}</option>)}</select></label></>}{tab==="templates"&&<><label className="filter-search">Тип события<input name="event_type" defaultValue={operationFilters.event_type} placeholder="ticket.assigned"/></label><label>Канал<select name="channel" defaultValue={operationFilters.channel}><option value="">Все</option><option>IN_APP</option><option>EMAIL</option><option>PUSH</option><option>SMS</option></select></label></>}{tab==="deliveries"&&<><label>Статус<select name="status" defaultValue={operationFilters.status}><option value="">Все</option><option>PENDING</option><option>PROCESSING</option><option>SENT</option><option>FAILED</option><option>DEAD</option><option>SKIPPED</option></select></label><label>Канал<select name="channel" defaultValue={operationFilters.channel}><option value="">Все</option><option>IN_APP</option><option>EMAIL</option><option>PUSH</option><option>SMS</option></select></label></>}<button type="submit">Применить</button><button type="button" onClick={()=>setOperationFilters({ticket_id:"",brigade_id:"",status:"",event_type:"",channel:""})}>Сбросить</button></form><div className={`ops-layout ${selected?"selected":""}`}><div className="operation-list">{visibleItems.map((item,index)=><button key={text(item.id,index)} className={selected?.id===item.id?"selected":""} onClick={()=>setSelected(item)}><span className={`ops-state ${text(item.status,"active").toLowerCase()}`}>● {text(item.status,item.channel)}</span><h3>{text(item.event_type,item.ticket_id?`Заявка ${item.ticket_id}`:`Операция ${index+1}`)}</h3><p>{text(item.brigade_id,item.subject)}</p><small>{timestamp(item.created_at)}</small></button>)}</div>{!visibleItems.length&&<Empty>По выбранным фильтрам записей нет.</Empty>}{selected&&<aside className="ops-detail"><button className="detail-close" onClick={()=>setSelected(undefined)}>×</button><span className="eyebrow">Детали операции</span><h2>{text(selected.event_type,selected.id)}</h2><ReadableDetails data={selected}/>{tab==="dispatch"&&!["ASSIGNED","CANCELLED","FAILED","EXPIRED"].includes(text(selected.status))&&<button className="danger-action" onClick={()=>void cancelDispatch()}>Отменить назначение</button>}{tab==="routes"&&<div className="ops-actions"><button onClick={()=>void routeStatus("ACTIVE")}>Активировать</button><button onClick={()=>void routeStatus("COMPLETED")}>Завершить</button><button className="danger-action" onClick={()=>void routeStatus("CANCELLED")}>Отменить</button></div>}</aside>}</div>{modal&&<Modal title="Шаблон уведомления" onClose={()=>setModal(false)}><form className="ops-form" onSubmit={saveTemplate}><label>Событие<input name="event_type" placeholder="ticket.assigned" required/></label><label>Канал<select name="channel"><option>IN_APP</option><option>EMAIL</option><option>PUSH</option><option>SMS</option></select></label><label>Тема<input name="subject"/></label><label>Текст<textarea name="body" rows={5} required/></label><button className="primary">Сохранить</button></form></Modal>}</section>
}
