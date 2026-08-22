"use client";
/* eslint-disable jsx-a11y/click-events-have-key-events, jsx-a11y/no-noninteractive-element-interactions */
import { useEffect, useState } from "react";
import type { Position, Ticket } from "./api";
import type { BrigadeZoneRecord } from "./brigade-zones";
import { loadBrigades, vehicleDisplayName, type BrigadeRecord } from "./brigade-store";

const statusNames: Record<string, string> = {
  ACTIVE: "Активна", AVAILABLE: "Свободна", BUSY: "Занята", ON_ROUTE: "В пути",
  ON_SITE: "На месте", OFFLINE: "Не на линии", INACTIVE: "Неактивна", ARCHIVED: "В архиве",
};

function positionTime(value: number) {
  if (!value) return "Время не указано";
  const date = new Date(value > 1e12 ? value : value * 1000);
  return Number.isNaN(date.getTime()) ? "Время не указано" : `Позиция: ${date.toLocaleString("ru-RU")}`;
}

export function BrigadesPage({ tickets, vehicles, zones, onOpenMap, onOpenZones }: {
  tickets: Ticket[];
  vehicles: Position[];
  zones: BrigadeZoneRecord[];
  onOpenMap: (id: string) => void;
  onOpenZones: () => void;
}) {
  const [brigades, setBrigades] = useState<BrigadeRecord[]>(loadBrigades);
  const [selected, setSelected] = useState<string>();

  useEffect(() => {
    const sync = (event: Event) => setBrigades((event as CustomEvent<BrigadeRecord[]>).detail || loadBrigades());
    window.addEventListener("city-brigades-changed", sync);
    return () => window.removeEventListener("city-brigades-changed", sync);
  }, []);

  const current = brigades.find((brigade) => brigade.id === selected);
  const currentVehicles = vehicles.filter((vehicle) => vehicle.brigade_id === selected);
  const jobs = tickets.filter((ticket) => ticket.brigade_id === selected && ["ASSIGNED", "IN_PROGRESS"].includes(ticket.status));
  const brigadeZones = zones.filter((zone) => zone.brigade_id === selected);

  return <section className="content-page">
    <div className="page-toolbar">
      <div><h2>Городские бригады</h2><p>Состав бригад, все закреплённые машины и их последние координаты</p></div>
      <button className="primary" onClick={onOpenZones}>Настроить зоны</button>
    </div>
    <div className={`brigades-layout ${current ? "has-detail" : ""}`}>
      <div className="brigade-grid">{brigades.map((brigade) => {
        const brigadeVehicles = vehicles.filter((vehicle) => vehicle.brigade_id === brigade.id);
        const job = tickets.find((ticket) => ticket.brigade_id === brigade.id && ["ASSIGNED", "IN_PROGRESS"].includes(ticket.status));
        return <article className={selected === brigade.id ? "selected" : ""} key={brigade.id} onClick={() => setSelected(brigade.id)}>
          <i>{brigadeVehicles.length ? "▲" : "—"}</i>
          <div>
            <span>{statusNames[brigade.status] || brigade.status}</span>
            <h3>{brigade.name}</h3>
            <small>ID бригады: {brigade.id}</small>
            <p>{job ? job.title : brigade.specialization}</p>
            <small className="brigade-vehicle-count">Машин с координатами: {brigadeVehicles.length}</small>
          </div>
          {brigadeVehicles.length
            ? <button onClick={(event) => { event.stopPropagation(); onOpenMap(brigadeVehicles[0].vehicle_id); }}>Все на карте</button>
            : <button disabled>Нет координат</button>}
        </article>;
      })}</div>
      {current && <aside className="brigade-detail">
        <button className="detail-close" onClick={() => setSelected(undefined)}>×</button>
        <span className="eyebrow">Единая карточка бригады</span>
        <h2>{current.name}</h2>
        <p className="entity-id">ID бригады: {current.id}</p>
        <div className="brigade-status">● {statusNames[current.status] || current.status}</div>
        <p className="no-jobs">{current.description}</p>
        <dl>
          <div><dt>Специализация</dt><dd>{current.specialization}</dd></div>
          <div><dt>Машин с координатами</dt><dd>{currentVehicles.length}</dd></div>
          <div><dt>Активных заявок</dt><dd>{jobs.length}</dd></div>
          <div><dt>Зон обслуживания</dt><dd>{brigadeZones.length}</dd></div>
        </dl>
        <h3>Машины бригады</h3>
        {currentVehicles.length ? <div className="brigade-vehicles">{currentVehicles.map((vehicle) => <button key={vehicle.vehicle_id} onClick={() => onOpenMap(vehicle.vehicle_id)}>
          <i>▲</i>
          <span><b>{vehicleDisplayName(vehicle.vehicle_id)}</b><small>ID машины: {vehicle.vehicle_id}</small><small>{Math.round(vehicle.speed_kmh)} км/ч · курс {Math.round(vehicle.heading)}°</small><small>{positionTime(Number(vehicle.recorded_at))}</small></span>
          <em>На карте →</em>
        </button>)}</div> : <p className="no-jobs">От машин бригады ещё не поступали координаты.</p>}
        <h3>Текущие задания</h3>
        {jobs.length ? jobs.map((job) => <button className="brigade-job" key={job.id} onClick={() => onOpenMap(job.id)}><b>{job.title}</b><small>{job.address}</small><em>{job.status}</em></button>) : <p className="no-jobs">Активных заданий нет.</p>}
        <h3>Закреплённые зоны</h3>
        {brigadeZones.length ? brigadeZones.map((zone) => <div className="brigade-zone" key={zone.id}><b>{zone.name}</b><small>Приоритет {zone.priority}</small></div>) : <p className="no-jobs">Зоны не назначены.</p>}
      </aside>}
    </div>
  </section>;
}
