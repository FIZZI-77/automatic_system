"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import "leaflet/dist/leaflet.css";
import { ApiError, api, config, type Position, type Session, type Ticket } from "./api";
import { brigadeDisplayName, vehicleDisplayName, type BrigadeRecord } from "./brigade-store";

type RoutePoint = [number, number];
type LayerId = "districts" | "roads" | "stops" | "lighting" | "traffic" | "emergency" | "utilities" | "social" | "energy";
type BaseId = "standard" | "humanitarian" | "topographic";
type InfraFeature = { id: string; latitude?: number; longitude?: number; coordinates?: [number, number][]; category: LayerId; name: string; kind: string; address?:string; operator?:string; network?:string; ref?:string };
type AssetPassport = { id:string; external_id?:string; department_id:string; type:string; name:string; address?:string; district?:string; municipality?:string; status?:string|number; risk_level?:string|number; risk_score?:number; criticality?:number; geometry_geo_json?:string; next_inspection_at?:string|number };
type Department = { id:string; name:string };
type Props = { tickets: Ticket[]; vehicles: Position[]; brigades?:BrigadeRecord[]; selected?: string; session?:Session; onSelect: (id: string) => void; onNotice?:(message:string)=>void };

const demoDepartments:Department[]=[
  {id:"dep-roads",name:"Дорожное хозяйство"},
  {id:"dep-utilities",name:"Городские коммуникации"},
];

const layerMeta: Record<LayerId, { label: string; icon: string; color: string }> = {
  districts: { label: "Границы округов", icon: "О", color: "#8b78a8" },
  roads: { label: "Основные дороги", icon: "Д", color: "#cf8c68" },
  stops: { label: "Остановки", icon: "А", color: "#668db0" },
  lighting: { label: "Уличные фонари", icon: "Ф", color: "#d4a64f" },
  traffic: { label: "Светофоры", icon: "С", color: "#638c75" },
  emergency: { label: "Экстренные службы", icon: "+", color: "#d4776c" },
  utilities: { label: "ЖКХ и гидранты", icon: "В", color: "#5e9e9a" },
  social: { label: "Социальные объекты", icon: "У", color: "#9a83aa" },
  energy: { label: "Энергетика", icon: "Э", color: "#b99042" },
};

const bases: Record<BaseId, { label: string; url: string; attribution: string; maxZoom: number }> = {
  standard: { label: "Городская", url: config.openMapTileUrl, attribution: config.openMapAttribution, maxZoom: 19 },
  humanitarian: { label: "Контрастная", url: config.hotMapTileUrl, attribution: "© OpenStreetMap · HOT", maxZoom: 19 },
  topographic: { label: "Топографическая", url: config.topographicMapTileUrl, attribution: "© OpenStreetMap · OpenTopoMap", maxZoom: 17 },
};

const assetTypes:Record<LayerId,string>={districts:"ADMINISTRATIVE_AREA",roads:"ROAD",stops:"BUS_STOP",lighting:"STREET_LIGHT",traffic:"TRAFFIC_SIGNAL",emergency:"EMERGENCY_FACILITY",utilities:"UTILITY_OBJECT",social:"SOCIAL_FACILITY",energy:"ENERGY_OBJECT"};
const assetStatusLabels=["Неизвестно","Запланирован","Установлен","Активен","Повреждён","На ремонте","Требует замены","Заменён","Выведен из эксплуатации"];
const riskLabels=["Неизвестно","Низкий","Средний","Высокий","Критический"];
function enumText(value:string|number|undefined,labels:string[]){return typeof value==="number"?labels[value]||String(value):value||"Не указано"}
function hasFreshPosition(position:Position){return Number(position.recorded_at)>=Date.now()/1000-120}
function positionTitle(position:Position){const recordedAt=new Date(Number(position.recorded_at)*1000);return hasFreshPosition(position)?"Передаёт координаты":`Последняя позиция: ${recordedAt.toLocaleString("ru-RU")}`}

function decodePolyline6(encoded: string): RoutePoint[] {
  const points: RoutePoint[] = []; let index = 0; let latitude = 0; let longitude = 0;
  while (index < encoded.length) {
    const values: number[] = [];
    for (let coordinate = 0; coordinate < 2; coordinate++) {
      let result = 0; let shift = 0; let byte: number;
      do { byte = encoded.charCodeAt(index++) - 63; result |= (byte & 0x1f) << shift; shift += 5; } while (byte >= 0x20 && index <= encoded.length);
      values.push((result & 1) ? ~(result >> 1) : result >> 1);
    }
    latitude += values[0]; longitude += values[1]; points.push([latitude / 1e6, longitude / 1e6]);
  }
  return points;
}

export function CityMap({ tickets, vehicles, brigades = [], selected, session, onSelect, onNotice }: Props) {
  const root = useRef<HTMLDivElement>(null);
  const [route, setRoute] = useState<RoutePoint[]>([]);
  const [departments,setDepartments]=useState<Department[]>(demoDepartments);
  const [departmentFilter,setDepartmentFilter]=useState("");
  const [ticketFilter,setTicketFilter]=useState("");
  const [brigadeFilter,setBrigadeFilter]=useState("");
  const [infrastructure, setInfrastructure] = useState<InfraFeature[]>([]);
  const [base, setBase] = useState<BaseId>("standard");
  const [layers, setLayers] = useState<LayerId[]>(["districts", "roads"]);
  const [panelOpen, setPanelOpen] = useState(false);
  const [error, setError] = useState("");
  const [selectedInfrastructure,setSelectedInfrastructure]=useState<InfraFeature>();
  const [passport,setPassport]=useState<AssetPassport>();
  const [passportBusy,setPassportBusy]=useState(false);
  const [passportError,setPassportError]=useState("");

  const knownBrigades=useMemo(()=>{
    const byId=new Map(brigades.map(brigade=>[brigade.id,brigade]));
    tickets.forEach(ticket=>{if(ticket.brigade_id&&!byId.has(ticket.brigade_id))byId.set(ticket.brigade_id,{id:ticket.brigade_id,department_id:ticket.department_id,name:brigadeDisplayName(ticket.brigade_id),description:"",specialization:"",status:""})});
    vehicles.forEach(vehicle=>{if(!byId.has(vehicle.brigade_id))byId.set(vehicle.brigade_id,{id:vehicle.brigade_id,department_id:vehicle.department_id||tickets.find(ticket=>ticket.brigade_id===vehicle.brigade_id)?.department_id||"",name:brigadeDisplayName(vehicle.brigade_id),description:"",specialization:"",status:""})});
    return Array.from(byId.values());
  },[brigades,tickets,vehicles]);
  const departmentOptions=useMemo(()=>{
    const byId=new Map(departments.map(department=>[department.id,department]));
    tickets.forEach(ticket=>{if(!byId.has(ticket.department_id))byId.set(ticket.department_id,{id:ticket.department_id,name:`Департамент ${ticket.department_id.slice(0,8)}`})});
    knownBrigades.forEach(brigade=>{if(brigade.department_id&&!byId.has(brigade.department_id))byId.set(brigade.department_id,{id:brigade.department_id,name:`Департамент ${brigade.department_id.slice(0,8)}`})});
    return Array.from(byId.values()).sort((left,right)=>left.name.localeCompare(right.name,"ru"));
  },[departments,knownBrigades,tickets]);
  const departmentTickets=useMemo(()=>departmentFilter?tickets.filter(ticket=>ticket.department_id===departmentFilter):tickets,[departmentFilter,tickets]);
  const departmentBrigades=useMemo(()=>departmentFilter?knownBrigades.filter(brigade=>brigade.department_id===departmentFilter):knownBrigades,[departmentFilter,knownBrigades]);
  const filteredTickets=useMemo(()=>departmentTickets.filter(ticket=>(!ticketFilter||ticket.id===ticketFilter)&&(!brigadeFilter||ticket.brigade_id===brigadeFilter)),[brigadeFilter,departmentTickets,ticketFilter]);
  const filteredVehicles=useMemo(()=>vehicles.filter(vehicle=>{
    const departmentId=vehicle.department_id||knownBrigades.find(brigade=>brigade.id===vehicle.brigade_id)?.department_id;
    if(departmentFilter&&departmentId!==departmentFilter)return false;
    if(brigadeFilter&&vehicle.brigade_id!==brigadeFilter)return false;
    if(ticketFilter&&vehicle.brigade_id!==tickets.find(ticket=>ticket.id===ticketFilter)?.brigade_id)return false;
    return true;
  }),[brigadeFilter,departmentFilter,knownBrigades,ticketFilter,tickets,vehicles]);

  const routePair = useMemo(() => {
    const assigned = tickets.filter(ticket => ["ASSIGNED", "IN_PROGRESS"].includes(ticket.status) && ticket.brigade_id);
    const selectedTicket = assigned.find(ticket => ticket.id === (ticketFilter||selected));
    if (selectedTicket) return { destination: selectedTicket, origin: vehicles.find(vehicle => vehicle.brigade_id === selectedTicket.brigade_id) };
    const selectedVehicle = vehicles.find(vehicle => vehicle.vehicle_id === selected || vehicle.brigade_id === (brigadeFilter||selected));
    if (selectedVehicle) return { origin: selectedVehicle, destination: assigned.find(ticket => ticket.brigade_id === selectedVehicle.brigade_id) };
    return {};
  }, [brigadeFilter,selected,ticketFilter,tickets,vehicles]);
  const routeHint=useMemo(()=>{
    if(!ticketFilter&&!brigadeFilter&&!selected)return "Выберите заявку или бригаду, чтобы показать маршрут";
    const selectedTicket=tickets.find(ticket=>ticket.id===(ticketFilter||selected));
    if(selectedTicket&&!selectedTicket.brigade_id)return "У выбранной заявки пока нет назначенной бригады";
    if(selectedTicket&&!routePair.origin)return "У назначенной бригады пока нет позиции машины";
    if((brigadeFilter||selected)&&!routePair.destination)return "У выбранной бригады нет активной заявки с маршрутом";
    return "";
  },[brigadeFilter,routePair,selected,ticketFilter,tickets]);

  useEffect(()=>{
    if(!session||session.accessToken==="demo"){setDepartments(demoDepartments);return}
    let active=true;
    api<{departments:Department[]}>(config.endpoints.departmentsList,{limit:100,offset:0},"POST",session.accessToken)
      .then(payload=>{if(active)setDepartments(payload.departments||[])})
      .catch(()=>undefined);
    return()=>{active=false};
  },[session]);

  useEffect(()=>{
    if(!selected)return;
    const ticket=tickets.find(item=>item.id===selected);
    if(ticket){setDepartmentFilter(ticket.department_id);setTicketFilter(ticket.id);setBrigadeFilter("");return}
    const vehicle=vehicles.find(item=>item.vehicle_id===selected||item.brigade_id===selected);
    const brigadeId=vehicle?.brigade_id||knownBrigades.find(item=>item.id===selected)?.id;
    if(!brigadeId)return;
    const brigade=knownBrigades.find(item=>item.id===brigadeId);
    if(brigade?.department_id)setDepartmentFilter(brigade.department_id);
    setBrigadeFilter(brigadeId);
    setTicketFilter("");
  },[knownBrigades,selected,tickets,vehicles]);

  function selectTicket(ticketId:string){
    setTicketFilter(ticketId);
    setBrigadeFilter("");
    const ticket=tickets.find(item=>item.id===ticketId);
    if(ticket)setDepartmentFilter(ticket.department_id);
    onSelect(ticketId);
  }

  function selectBrigade(brigadeId:string){
    setBrigadeFilter(brigadeId);
    setTicketFilter("");
    const brigade=knownBrigades.find(item=>item.id===brigadeId);
    if(brigade?.department_id)setDepartmentFilter(brigade.department_id);
    onSelect(brigadeId);
  }

  function resetFilters(){
    setDepartmentFilter("");
    setTicketFilter("");
    setBrigadeFilter("");
    onSelect("");
  }

  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/moscow-infrastructure", { signal: controller.signal }).then(response => response.json()).then(payload => setInfrastructure(payload.features || [])).catch(() => undefined);
    return () => controller.abort();
  }, []);

  useEffect(()=>{
    let active=true;
    if(!selectedInfrastructure||selectedInfrastructure.latitude==null||selectedInfrastructure.longitude==null||!session||session.accessToken==="demo")return()=>{active=false};
    api<{assets:AssetPassport[]}>(config.endpoints.assetsNearby,{latitude:selectedInfrastructure.latitude,longitude:selectedInfrastructure.longitude,radius_meters:8,type:assetTypes[selectedInfrastructure.category],limit:20},"POST",session.accessToken)
      .then(result=>{if(active)setPassport((result.assets||[]).find(asset=>asset.external_id===selectedInfrastructure.id))})
      .catch(reason => {
        if (!active || (reason instanceof ApiError && reason.status === 404)) {
          return;
        }
        setPassportError(
          reason instanceof Error
            ? reason.message
            : "Не удалось проверить паспорт объекта",
        );
      })
      .finally(()=>{if(active)setPassportBusy(false)});
    return()=>{active=false};
  },[selectedInfrastructure,session]);

  async function createPassport(){
    if(!selectedInfrastructure||selectedInfrastructure.latitude==null||selectedInfrastructure.longitude==null||!session)return;
    setPassportBusy(true);setPassportError("");
    try{
      if(session.accessToken==="demo"){
        setPassport({id:`demo-${selectedInfrastructure.id}`,external_id:selectedInfrastructure.id,department_id:"dep-roads",type:assetTypes[selectedInfrastructure.category],name:selectedInfrastructure.name,status:"ACTIVE",risk_level:"LOW",criticality:.4,address:selectedInfrastructure.address});
        return;
      }
      let departmentId=session.user?.department_id;
      if(!departmentId){const resolved=await api<{department_id:string;can_operate:boolean}>(config.endpoints.workingDepartment,{user_id:session.user?.user_id},"POST",session.accessToken);if(resolved.can_operate)departmentId=resolved.department_id}
      if(!departmentId)throw new Error("Для пользователя не определён рабочий департамент");
      const result=await api<{asset:AssetPassport}>(config.endpoints.assetsCreate,{external_id:selectedInfrastructure.id,department_id:departmentId,type:assetTypes[selectedInfrastructure.category],name:selectedInfrastructure.name,address:selectedInfrastructure.address||"",geometry_geo_json:JSON.stringify({type:"Point",coordinates:[selectedInfrastructure.longitude,selectedInfrastructure.latitude]}),owner:"Город Москва",inspection_interval_days:90,response_norm_minutes:60,repair_norm_minutes:1440,criticality:.4},"POST",session.accessToken);
      setPassport(result.asset);onNotice?.(`Паспорт «${result.asset.name}» создан`);
    }catch(reason){setPassportError(reason instanceof Error?reason.message:"Не удалось создать паспорт объекта")}
    finally{setPassportBusy(false)}
  }

  useEffect(() => {
    if (!routePair.origin || !routePair.destination) { queueMicrotask(() => setRoute([])); return; }
    const controller = new AbortController();
    const request=session&&session.accessToken!=="demo"
      ?api<{routes:Array<{encoded_polyline:string}>}>(config.endpoints.routesList,{ticket_id:routePair.destination.id,limit:10,offset:0},"POST",session.accessToken)
        .then(payload=>payload.routes?.find(item=>item.encoded_polyline)?.encoded_polyline)
        .then(async storedShape=>storedShape?[storedShape]:api<{route:{encoded_polyline:string}}>(config.endpoints.routesBuild,{origin:{latitude:routePair.origin!.latitude,longitude:routePair.origin!.longitude},destination:{latitude:routePair.destination!.latitude,longitude:routePair.destination!.longitude},options:{travel_mode:"auto"}},"POST",session.accessToken).then(payload=>[payload.route.encoded_polyline]))
      :fetch("/api/valhalla-route", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ origin: routePair.origin, destination: routePair.destination }), signal: controller.signal }).then(async response => { const payload = await response.json(); if (!response.ok) throw new Error(payload.error || "Не удалось построить маршрут"); return payload.encoded_polylines as string[]; });
    request
      .then(shapes => shapes.flatMap((shape, index) => { const leg = decodePolyline6(shape); return index ? leg.slice(1) : leg; }))
      .then(points => { setRoute(points); setError(""); })
      .catch(reason => { if (reason instanceof Error && reason.name === "AbortError") return; setRoute([]); setError(reason instanceof Error ? reason.message : "Ошибка маршрута"); });
    return () => controller.abort();
  }, [routePair,session]);

  useEffect(() => {
    if (!root.current) return;
    let disposed = false;
    let invalidateTimer: number | undefined;
    let mapInstance: import("leaflet").Map | undefined;
    const target = filteredTickets.find(ticket => ticket.id === selected) || filteredVehicles.find(vehicle => vehicle.vehicle_id === selected || vehicle.brigade_id === selected);
    import("leaflet").then(L => {
      if (disposed || !root.current) return;
      root.current.innerHTML = "";
      const map = L.map(root.current, { zoomControl: true, zoomAnimation:false, fadeAnimation:false, markerZoomAnimation:false }).setView(target ? [target.latitude, target.longitude] : [55.751244, 37.618423], target ? 16 : 12);
      mapInstance = map;
      map.on("click", () => {
        setSelectedInfrastructure(undefined);
        setPassport(undefined);
        setPassportError("");
        setPassportBusy(false);
      });
      const baseLayer = bases[base];
      L.tileLayer(baseLayer.url, { attribution: baseLayer.attribution, maxZoom: baseLayer.maxZoom }).addTo(map);
      infrastructure.filter(item => layers.includes(item.category)).forEach(item => {
        const meta = layerMeta[item.category];
        if (item.coordinates?.length) {
          L.polyline(item.coordinates, { color: meta.color, weight: item.category === "roads" ? 3 : 2, opacity: item.category === "districts" ? .75 : .65, dashArray: item.category === "districts" ? "8 7" : undefined }).bindTooltip(item.name).addTo(map);
        } else if (item.latitude != null && item.longitude != null) {
          const icon = L.divIcon({ className: "leaflet-div-icon-clean", html: `<span class="infra-marker small" style="--infra:${meta.color}">${meta.icon}</span>`, iconSize: [20, 20], iconAnchor: [10, 10] });
          L.marker([item.latitude, item.longitude], { icon, title: item.name, zIndexOffset: 150 }).bindTooltip(`<b>${item.name}</b><br>${meta.label}`).on("click", () => {
            setPassport(undefined);
            setPassportError("");
            setPassportBusy(Boolean(session && session.accessToken !== "demo"));
            setSelectedInfrastructure(item);
          }).addTo(map);
        }
      });
      if (route.length > 1) {
        const routeLayer=L.polyline(route, { className: "assigned-route", color: "#547b68", weight: 5, opacity: .95 }).addTo(map);
        map.fitBounds(routeLayer.getBounds(),{padding:[42,42],maxZoom:16,animate:false});
      }
      filteredTickets.forEach(ticket => { const icon = L.divIcon({ className: "leaflet-div-icon-clean", html: `<span class="leaflet-incident ${selected === ticket.id ? "selected" : ""} ${ticket.priority.toLowerCase()}">!</span>`, iconSize: [34, 34], iconAnchor: [17, 17] }); L.marker([ticket.latitude, ticket.longitude], { icon, title: `${ticket.title} — ${ticket.address}`, zIndexOffset: selected === ticket.id ? 1000 : 0 }).on("click", () => selectTicket(ticket.id)).addTo(map); });
      filteredVehicles.forEach(vehicle => { const active = selected === vehicle.vehicle_id || selected === vehicle.brigade_id; const stale = !hasFreshPosition(vehicle); const icon = L.divIcon({ className: "leaflet-div-icon-clean", html: `<span class="leaflet-vehicle ${active ? "selected" : ""} ${stale ? "stale" : ""}" style="transform:rotate(${vehicle.heading}deg)">▲</span>`, iconSize: [38, 30], iconAnchor: [19, 15] }); L.marker([vehicle.latitude, vehicle.longitude], { icon, title: `${vehicleDisplayName(vehicle.vehicle_id)} · ${brigadeDisplayName(vehicle.brigade_id)} · ${positionTitle(vehicle)}`, zIndexOffset: active ? 1200 : 500 }).on("click", () => selectBrigade(vehicle.brigade_id)).addTo(map); });
      invalidateTimer = window.setTimeout(() => {
        if (!disposed) map.invalidateSize();
      }, 50);
    });
    return () => {
      disposed = true;
      if (invalidateTimer !== undefined) window.clearTimeout(invalidateTimer);
      mapInstance?.stop();
      mapInstance?.off();
      mapInstance?.remove();
    };
  }, [filteredTickets, filteredVehicles, selected, session, route, infrastructure, layers, base]);

  const toggleLayer = (layer: LayerId) => setLayers(current => current.includes(layer) ? current.filter(item => item !== layer) : [...current, layer]);
  const canCreatePassport=Boolean(session&&session.user?.roles.some(role=>["admin","dispatcher","worker"].includes(role.toLowerCase())));
  return <div className="map-shell yandex-map"><div ref={root} className="map-root"/><div className="map-route-filters" aria-label="Фильтры карты"><label><span>Департамент</span><select aria-label="Фильтр по департаменту" value={departmentFilter} onChange={event=>{setDepartmentFilter(event.target.value);setTicketFilter("");setBrigadeFilter("");onSelect("")}}><option value="">Все департаменты</option>{departmentOptions.map(department=><option value={department.id} key={department.id}>{department.name}</option>)}</select></label><label><span>Заявка</span><select aria-label="Фильтр по заявке" value={ticketFilter} onChange={event=>event.target.value?selectTicket(event.target.value):(setTicketFilter(""),onSelect(""))}><option value="">Все заявки</option>{departmentTickets.map(ticket=><option value={ticket.id} key={ticket.id}>{ticket.id} · {ticket.title}</option>)}</select></label><label><span>Бригада</span><select aria-label="Фильтр по бригаде" value={brigadeFilter} onChange={event=>event.target.value?selectBrigade(event.target.value):(setBrigadeFilter(""),onSelect(""))}><option value="">Все бригады</option>{departmentBrigades.map(brigade=><option value={brigade.id} key={brigade.id}>{brigade.name}</option>)}</select></label>{(departmentFilter||ticketFilter||brigadeFilter)&&<button type="button" onClick={resetFilters}>Сбросить</button>}</div>{error && <div className="map-load-error">{error}</div>}{!error&&routeHint&&<div className="map-route-note">{routeHint}</div>}<button className="layers-trigger" onClick={() => setPanelOpen(value => !value)}>▦ Слои</button>{panelOpen && <div className="layers-window"><div className="layers-title"><div><b>Слои карты</b><span>Подложка и городские объекты</span></div><button onClick={() => setPanelOpen(false)}>×</button></div><fieldset><legend>Подложка</legend>{(Object.keys(bases) as BaseId[]).map(item => <label key={item}><input type="radio" name="base-map" checked={base === item} onChange={() => setBase(item)}/><span className={`base-preview ${item}`}/><b>{bases[item].label}</b></label>)}</fieldset><fieldset><legend>Инфраструктура</legend>{(Object.keys(layerMeta) as LayerId[]).map(item => <label key={item}><input type="checkbox" checked={layers.includes(item)} onChange={() => toggleLayer(item)}/><i style={{ background: layerMeta[item].color }}>{layerMeta[item].icon}</i><span>{layerMeta[item].label}</span></label>)}</fieldset><small>Открытые данные © OpenStreetMap</small></div>}{selectedInfrastructure&&<section className="infrastructure-card" aria-label="Карточка объекта инфраструктуры"><button className="infrastructure-card-close" aria-label="Закрыть карточку" onClick={()=>setSelectedInfrastructure(undefined)}>×</button><span className="eyebrow">{passport?"Паспорт объекта":"Данные OpenStreetMap"}</span><h3>{passport?.name||selectedInfrastructure.name}</h3><p>{layerMeta[selectedInfrastructure.category].label} · {selectedInfrastructure.kind}</p><dl><div><dt>Внешний ID</dt><dd>{selectedInfrastructure.id}</dd></div>{selectedInfrastructure.ref&&<div><dt>Номер</dt><dd>{selectedInfrastructure.ref}</dd></div>}{selectedInfrastructure.operator&&<div><dt>Оператор</dt><dd>{selectedInfrastructure.operator}</dd></div>}{selectedInfrastructure.network&&<div><dt>Сеть</dt><dd>{selectedInfrastructure.network}</dd></div>}<div><dt>Координаты</dt><dd>{selectedInfrastructure.latitude?.toFixed(6)}, {selectedInfrastructure.longitude?.toFixed(6)}</dd></div>{passport&&<><div><dt>ID паспорта</dt><dd>{passport.id}</dd></div><div><dt>Состояние</dt><dd>{enumText(passport.status,assetStatusLabels)}</dd></div><div><dt>Риск</dt><dd>{enumText(passport.risk_level,riskLabels)}</dd></div><div><dt>Критичность</dt><dd>{Math.round(Number(passport.criticality||0)*100)}%</dd></div></>}</dl>{passportBusy&&<p className="passport-state">Проверяем реестр…</p>}{passportError&&<p className="passport-error">{passportError}</p>}{!passport&&!passportBusy&&<><p className="passport-state">Паспорт для этого объекта ещё не создан.</p>{canCreatePassport?<button className="passport-create" onClick={()=>void createPassport()}>Создать паспорт объекта</button>:<small>Для создания паспорта нужны права сотрудника городской службы.</small>}</>}</section>}<div className="map-legend"><span><i className="dot incident"/> Инцидент</span><span><i className="dot vehicle"/> Машина</span>{route.length > 1 && <span><i className="line"/> Назначенный маршрут</span>}</div></div>;
}
