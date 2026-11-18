"use client";

import { useState } from "react";

import { Position, Ticket } from "./api";

import {
  brigadeDisplayName,
  vehicleDisplayName,
  type BrigadeRecord,
} from "./brigade-store";

import { hasFreshPosition } from "./city-shared";

function vehicleState(
  vehicle: Position,
  brigades: BrigadeRecord[],
  tickets: Ticket[],
) {
  if (!hasFreshPosition(vehicle)) return "Последняя позиция";
  const brigade = brigades.find((item) => item.id === vehicle.brigade_id),
    job = tickets.find(
      (ticket) =>
        ticket.brigade_id === vehicle.brigade_id &&
        ["ASSIGNED", "IN_PROGRESS"].includes(ticket.status),
    );
  if (brigade?.status === "ON_ROUTE" || (job && Number(vehicle.speed_kmh) > 3))
    return "В пути";
  if (brigade?.status === "ON_SITE") return "На месте";
  if (brigade?.status === "AVAILABLE") return "Свободна";
  if (brigade?.status === "BUSY" || job) return "Выполняет заявку";
  return "На линии";
}

export function VehicleGroups({
  vehicles,
  brigades,
  tickets,
  selected,
  onSelect,
}: {
  vehicles: Position[];
  brigades: BrigadeRecord[];
  tickets: Ticket[];
  selected?: string;
  onSelect: (id: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [freshness, setFreshness] = useState<"all" | "fresh" | "stale">("all");
  const [showAll, setShowAll] = useState(false);
  const normalized = query.trim().toLocaleLowerCase("ru-RU");
  const filtered = vehicles.filter((vehicle) => {
    const brigade = brigades.find((item) => item.id === vehicle.brigade_id);
    const matchesQuery =
      !normalized ||
      [
        vehicle.vehicle_id,
        vehicleDisplayName(vehicle.vehicle_id),
        vehicle.brigade_id,
        brigade?.name,
      ].some((value) => value?.toLocaleLowerCase("ru-RU").includes(normalized));
    const fresh = hasFreshPosition(vehicle);
    return (
      matchesQuery &&
      (freshness === "all" || (freshness === "fresh" ? fresh : !fresh))
    );
  });
  const visible = showAll ? filtered : filtered.slice(0, 12);
  const groups = Array.from(
    new Set(visible.map((vehicle) => vehicle.brigade_id)),
  ).map((brigadeId) => ({
    brigadeId,
    vehicles: visible.filter((vehicle) => vehicle.brigade_id === brigadeId),
  }));
  return (
    <div className="vehicle-list">
      <div className="list-caption">
        <span>Машины по бригадам</span>
        <b>
          {filtered.length} из {vehicles.length}
        </b>
      </div>
      <div className="vehicle-list-filters">
        <input
          aria-label="Поиск машин"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Машина или бригада"
        />
        <select
          aria-label="Актуальность координат"
          value={freshness}
          onChange={(event) =>
            setFreshness(event.target.value as "all" | "fresh" | "stale")
          }
        >
          <option value="all">Все координаты</option>
          <option value="fresh">На связи</option>
          <option value="stale">Давно не обновлялись</option>
        </select>
      </div>
      {groups.map((group) => {
        const active =
            selected === group.brigadeId ||
            group.vehicles.some((vehicle) => vehicle.vehicle_id === selected),
          brigadeName =
            brigades.find((brigade) => brigade.id === group.brigadeId)?.name ||
            brigadeDisplayName(group.brigadeId);
        return (
          <button
            key={group.brigadeId}
            className={active ? "selected" : ""}
            onClick={() => onSelect(group.brigadeId)}
          >
            <i>▲</i>
            <div>
              <b>{brigadeName}</b>
              {group.vehicles.map((vehicle) => (
                <span className="vehicle-feed-row" key={vehicle.vehicle_id}>
                  <small>{vehicleDisplayName(vehicle.vehicle_id)}</small>
                  <em>{vehicleState(vehicle, brigades, tickets)}</em>
                </span>
              ))}
            </div>
            <span>⌖</span>
          </button>
        );
      })}
      {!groups.length && (
        <p className="list-empty">Машины по заданным условиям не найдены.</p>
      )}
      {filtered.length > 12 && (
        <button
          className="vehicle-list-more"
          onClick={() => setShowAll((value) => !value)}
        >
          {showAll ? "Свернуть список" : `Показать все (${filtered.length})`}
        </button>
      )}
    </div>
  );
}
