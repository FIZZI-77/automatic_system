"use client";
/* eslint-disable react-hooks/set-state-in-effect */

import { useEffect, useRef, useState } from "react";
import "leaflet/dist/leaflet.css";
import { api, config, type Position, type Role, type Session } from "./api";
import { loadBrigades, type BrigadeRecord } from "./brigade-store";

type Point = [number, number];
export type BrigadeZoneRecord = { id: string; brigade_id: string; name: string; priority: number; points: Point[] };

type Props = { vehicles: Position[]; session: Session; role:Role; zones: BrigadeZoneRecord[]; onSaved: (zone: BrigadeZoneRecord) => void; onDeleted: (id:string) => void; onNotice: (text: string) => void };

export function BrigadeZones({ vehicles, session, role, zones, onSaved, onDeleted, onNotice }: Props) {
  const root = useRef<HTMLDivElement>(null);
  const pointsRef = useRef<Point[]>([]);
  const [points, setPoints] = useState<Point[]>([]);
  const [brigades,setBrigades]=useState<BrigadeRecord[]>(loadBrigades);
  const [brigadeId, setBrigadeId] = useState(loadBrigades()[0]?.id || vehicles[0]?.brigade_id || "");
  const [name, setName] = useState("Центральная зона");
  const [priority, setPriority] = useState(10);
  const [revision, setRevision] = useState(0);
  const [editingId,setEditingId]=useState<string>();
  const [filters,setFilters]=useState({query:"",status:"",specialization:""});
  useEffect(()=>{const sync=(event:Event)=>setBrigades((event as CustomEvent<BrigadeRecord[]>).detail||loadBrigades());window.addEventListener("city-brigades-changed",sync);return()=>window.removeEventListener("city-brigades-changed",sync)},[]);
  useEffect(()=>{if(!brigadeId&&brigades[0])setBrigadeId(brigades[0].id)},[brigadeId,brigades]);

  useEffect(() => {
    if (!root.current) return;
    let disposed = false; let mapInstance: { remove: () => void } | undefined;
    import("leaflet").then(L => {
      if (disposed || !root.current) return;
      root.current.innerHTML = "";
      const map = L.map(root.current).setView([55.751244, 37.618423], 12);
      mapInstance = map;
      L.tileLayer(config.openMapTileUrl, { attribution: config.openMapAttribution, maxZoom: 19 }).addTo(map);
      const savedLayer = L.layerGroup().addTo(map);
      zones.filter(zone => zone.brigade_id === brigadeId).forEach(zone => L.polygon(zone.points, { color: "#7c6b9c", fillColor: "#cfc4df", fillOpacity: .25, weight: 3 }).bindTooltip(`${zone.name} · приоритет ${zone.priority}`).addTo(savedLayer));
      const drawingLayer = L.layerGroup().addTo(map);
      const redraw = (values: Point[]) => {
        drawingLayer.clearLayers();
        values.forEach((point, index) => {
          const marker=L.circleMarker(point, { radius: 8, color: "#fff", weight: 3, fillColor: "#547b68", fillOpacity: 1 })
            .bindTooltip(`${index + 1} · правая кнопка — удалить`)
            .addTo(drawingLayer);
          marker.on("mousedown", event => {
            if(event.originalEvent.button!==2)return;
            L.DomEvent.preventDefault(event.originalEvent);
            L.DomEvent.stopPropagation(event.originalEvent);
            setPoints(current => {
              const next=current.filter((_, pointIndex)=>pointIndex!==index);
              pointsRef.current=next;
              redraw(next);
              return next;
            });
          });
        });
        if (values.length > 1) L.polyline(values, { color: "#547b68", weight: 3, dashArray: "7 6" }).addTo(drawingLayer);
        if (values.length > 2) L.polygon(values, { color: "#547b68", fillColor: "#bcd7c8", fillOpacity: .3, weight: 3 }).addTo(drawingLayer);
      };
      redraw(pointsRef.current);
      map.on("click", event => setPoints(current => { const next = [...current, [event.latlng.lat, event.latlng.lng] as Point]; pointsRef.current=next; redraw(next); return next; }));
      map.on("contextmenu", event => L.DomEvent.preventDefault(event.originalEvent));
      vehicles.forEach(vehicle => L.circleMarker([vehicle.latitude, vehicle.longitude], { radius: 7, color: "white", weight: 3, fillColor: vehicle.brigade_id === brigadeId ? "#7c6b9c" : "#314f43", fillOpacity: 1 }).bindTooltip(`Бригада ${vehicle.brigade_id}`).addTo(map));
      window.setTimeout(() => map.invalidateSize(), 50);
    });
    return () => { disposed = true; mapInstance?.remove(); };
  }, [vehicles, zones, brigadeId, revision]);

  function clearDrawing() { pointsRef.current=[]; setPoints([]); setRevision(value => value + 1); }

  async function save() {
    if (points.length < 3) { onNotice("Нужно поставить минимум три точки области"); return; }
    const record: BrigadeZoneRecord = { id: editingId||`zone-${Date.now()}`, brigade_id: brigadeId, name, priority, points };
    const ring = [...points.map(([lat, lon]) => [lon, lat]), [points[0][1], points[0][0]]];
    if (session.accessToken !== "demo") {
      const brigade=brigades.find(item=>item.id===brigadeId);
      const payload={ brigade_id: brigadeId, department_id: brigade?.department_id || session.user?.department_id, name, geo_json: JSON.stringify({ type: "Polygon", coordinates: [ring] }), priority };
      const result = await api<{zone?: {id?: string}}>(editingId?config.endpoints.brigadeZonesUpdate:config.endpoints.brigadeZonesCreate, editingId?{id:editingId,...payload}:payload, "POST", session.accessToken);
      record.id = result.zone?.id || record.id;
    }
    onSaved(record);
    setEditingId(undefined);
    clearDrawing();
    onNotice(`Зона «${name}» назначена только бригаде ${brigadeId}`);
  }

  function edit(zone:BrigadeZoneRecord){setEditingId(zone.id);setName(zone.name);setPriority(zone.priority);pointsRef.current=zone.points;setPoints(zone.points);setRevision(value=>value+1)}
  async function remove(zone:BrigadeZoneRecord){if(session.accessToken!=="demo")await api(config.endpoints.brigadeZonesDelete,{id:zone.id},"POST",session.accessToken);onDeleted(zone.id);if(editingId===zone.id){setEditingId(undefined);clearDrawing()}onNotice(`Зона «${zone.name}» удалена`)}

  const departmentScope=role==="dispatcher"?session.user?.department_id:"";
  const scopedBrigades=brigades.filter(item=>!departmentScope||item.department_id===departmentScope);
  const statuses=Array.from(new Set(scopedBrigades.map(item=>item.status).filter(Boolean))).sort();
  const specializations=Array.from(new Set(scopedBrigades.map(item=>item.specialization).filter(Boolean))).sort();
  const query=filters.query.trim().toLocaleLowerCase("ru");
  const filteredBrigades=scopedBrigades.filter(item=>(!query||[item.name,item.id,item.description,item.specialization].some(value=>value?.toLocaleLowerCase("ru").includes(query)))&&(!filters.status||item.status===filters.status)&&(!filters.specialization||item.specialization===filters.specialization));
  const currentBrigade=scopedBrigades.find(item=>item.id===brigadeId);
  const selectableBrigades=currentBrigade&&!filteredBrigades.some(item=>item.id===currentBrigade.id)?[currentBrigade,...filteredBrigades]:filteredBrigades;
  const brigadeIsScoped=scopedBrigades.some(item=>item.id===brigadeId),firstScopedBrigadeId=scopedBrigades[0]?.id;
  useEffect(()=>{if(!brigadeIsScoped&&firstScopedBrigadeId){pointsRef.current=[];setPoints([]);setEditingId(undefined);setBrigadeId(firstScopedBrigadeId)}},[brigadeIsScoped,firstScopedBrigadeId]);
  const brigadeZones = zones.filter(zone => zone.brigade_id === brigadeId);
  return <section className="zones-page"><div className="zones-map"><div ref={root}/><div className="draw-hint"><b>Нарисуйте область</b><span>Левая кнопка добавляет точку, правая кнопка по точке удаляет её</span></div></div><div className="zone-panel"><div><span className="eyebrow">Зона обслуживания</span><h2>{editingId?"Изменение территории":"Назначение территории"}</h2><p>{departmentScope?"Доступны только бригады вашего департамента.":"На карте показаны зоны только выбранной бригады."}</p></div><div className="zone-brigade-filters"><label className="wide">Поиск бригады<input type="search" value={filters.query} onChange={event=>setFilters(value=>({...value,query:event.target.value}))} placeholder="Название, ID или специализация"/></label><label>Статус<select value={filters.status} onChange={event=>setFilters(value=>({...value,status:event.target.value}))}><option value="">Все</option>{statuses.map(status=><option key={status}>{status}</option>)}</select></label><label>Специализация<select value={filters.specialization} onChange={event=>setFilters(value=>({...value,specialization:event.target.value}))}><option value="">Все</option>{specializations.map(item=><option key={item}>{item}</option>)}</select></label><div><span>Найдено: <b>{filteredBrigades.length}</b></span><button type="button" onClick={()=>setFilters({query:"",status:"",specialization:""})}>Сбросить</button></div></div><label>Бригада<select value={brigadeId} onChange={event => { setBrigadeId(event.target.value);setEditingId(undefined); clearDrawing(); }}>{selectableBrigades.map(brigade => <option value={brigade.id} key={brigade.id}>{brigade.name} · {brigade.status}</option>)}</select>{!filteredBrigades.length&&<small>По фильтрам совпадений нет; текущая бригада оставлена выбранной.</small>}</label><label>Название<input value={name} onChange={event => setName(event.target.value)}/></label><label>Приоритет<input type="number" min="0" max="100" value={priority} onChange={event => setPriority(Number(event.target.value))}/></label><div className="zone-stats"><span>Нарисовано вершин <b>{points.length}</b></span><span>Зон у бригады <b>{brigadeZones.length}</b></span></div>{brigadeZones.length > 0 && <div className="saved-zones">{brigadeZones.map(zone => <div key={zone.id}><span><b>{zone.name}</b><small>Приоритет {zone.priority}</small></span><button onClick={()=>edit(zone)}>Изменить</button><button className="danger-action" onClick={()=>void remove(zone)}>Удалить</button></div>)}</div>}<div className="zone-actions"><button className="ghost" onClick={()=>{setEditingId(undefined);clearDrawing()}}>Очистить</button><button className="primary" onClick={save} disabled={!brigadeId}>{editingId?"Обновить зону":"Сохранить зону"}</button></div></div></section>;
}
