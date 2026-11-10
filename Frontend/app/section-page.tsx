"use client";

/* eslint-disable jsx-a11y/click-events-have-key-events, jsx-a11y/no-noninteractive-element-interactions */

import { useState } from "react";

import { Position, Role, Session, Ticket } from "./api";

import { type BrigadeZoneRecord } from "./brigade-zones";

import { AnalyticsPage } from "./analytics-page";

import { BrigadesPage } from "./brigades-page";

import { TicketWorkspace } from "./ticket-workspace";

import {
  AuditPage,
  CreateTicketPage,
  NotificationsPage,
  ProfilePage,
  ReportsPage,
  SLAPage,
} from "./service-pages";

import {
  AssetsPage,
  OperationsPage,
  QualificationsPage,
  ServiceCatalogPage,
} from "./admin-modules";

import { CertificationsPage } from "./certifications-page";

import { statusNames, pageTitles } from "./city-shared";

export function SectionPage({
  section,
  tickets,
  vehicles,
  zones,
  session,
  role,
  onTicketUpdate,
  onTicketCreated,
  onNotice,
  onOpenMap,
  onOpenZones,
}: {
  section: string;
  tickets: Ticket[];
  vehicles: Position[];
  zones: BrigadeZoneRecord[];
  session: Session;
  role: Role;
  onTicketUpdate: (ticket: Ticket) => void;
  onTicketCreated: (ticket: Ticket) => void;
  onNotice: (text: string) => void;
  onOpenMap: (id: string) => void;
  onOpenZones: () => void;
}) {
  const [selectedBrigade, setSelectedBrigade] = useState<string>();
  if (section === "analytics")
    return (
      <AnalyticsPage tickets={tickets} session={session} onNotice={onNotice} />
    );
  if (section === "brigades")
    return (
      <BrigadesPage
        tickets={tickets}
        vehicles={vehicles}
        zones={zones}
        onOpenMap={onOpenMap}
        onOpenZones={onOpenZones}
      />
    );
  if (section === "sla")
    return (
      <SLAPage
        session={session}
        tickets={tickets}
        role={role}
        onOpenMap={onOpenMap}
        onNotice={onNotice}
      />
    );
  if (section === "tickets")
    return (
      <TicketWorkspace
        tickets={tickets}
        session={session}
        role={role}
        onUpdate={onTicketUpdate}
        onMap={onOpenMap}
        onNotice={onNotice}
      />
    );
  if (section === "create")
    return (
      <CreateTicketPage
        session={session}
        onCreated={onTicketCreated}
        onNotice={onNotice}
      />
    );
  if (section === "notifications")
    return <NotificationsPage session={session} onNotice={onNotice} />;
  if (section === "profile")
    return <ProfilePage session={session} role={role} onNotice={onNotice} />;
  if (section === "reports")
    return (
      <ReportsPage
        session={session}
        tickets={tickets}
        role={role}
        onNotice={onNotice}
      />
    );
  if (section === "audit")
    return <AuditPage session={session} onNotice={onNotice} />;
  if (section === "assets")
    return <AssetsPage session={session} onNotice={onNotice} />;
  if (section === "catalog")
    return <ServiceCatalogPage session={session} onNotice={onNotice} />;
  if (section === "qualifications")
    return <QualificationsPage session={session} onNotice={onNotice} />;
  if (section === "certifications")
    return <CertificationsPage session={session} onNotice={onNotice} />;
  if (section === "operations")
    return (
      <OperationsPage
        session={session}
        role={role}
        tickets={tickets}
        onNotice={onNotice}
      />
    );
  if (section === "brigades") {
    const activeVehicle = vehicles.find(
      (vehicle) => vehicle.brigade_id === selectedBrigade,
    );
    const jobs = tickets.filter(
      (ticket) =>
        ticket.brigade_id === selectedBrigade &&
        ["ASSIGNED", "IN_PROGRESS"].includes(ticket.status),
    );
    const brigadeZones = zones.filter(
      (zone) => zone.brigade_id === selectedBrigade,
    );
    return (
      <section className="content-page">
        <div className="page-toolbar">
          <div>
            <h2>Бригады на линии</h2>
            <p>
              Нажмите на карточку, чтобы открыть состав, заявки и территорию
            </p>
          </div>
          <button className="primary" onClick={onOpenZones}>
            Настроить зоны
          </button>
        </div>
        <div className={`brigades-layout ${activeVehicle ? "has-detail" : ""}`}>
          <div className="brigade-grid">
            {vehicles.map((vehicle) => {
              const job = tickets.find(
                (ticket) =>
                  ticket.brigade_id === vehicle.brigade_id &&
                  ["ASSIGNED", "IN_PROGRESS"].includes(ticket.status),
              );
              return (
                <article
                  className={
                    selectedBrigade === vehicle.brigade_id ? "selected" : ""
                  }
                  key={vehicle.vehicle_id}
                  onClick={() => setSelectedBrigade(vehicle.brigade_id)}
                >
                  <i>▲</i>
                  <div>
                    <span>НА ЛИНИИ</span>
                    <h3>Бригада {vehicle.brigade_id}</h3>
                    <p>{job ? job.title : "Свободна"}</p>
                  </div>
                  <button
                    onClick={(event) => {
                      event.stopPropagation();
                      onOpenMap(vehicle.vehicle_id);
                    }}
                  >
                    На карте
                  </button>
                </article>
              );
            })}
          </div>
          {activeVehicle && (
            <aside className="brigade-detail">
              <button
                className="detail-close"
                onClick={() => setSelectedBrigade(undefined)}
              >
                ×
              </button>
              <span className="eyebrow">Детальная информация</span>
              <h2>Бригада {activeVehicle.brigade_id}</h2>
              <div className="brigade-status">● На линии</div>
              <dl>
                <div>
                  <dt>Машина</dt>
                  <dd>{activeVehicle.vehicle_id}</dd>
                </div>
                <div>
                  <dt>Скорость</dt>
                  <dd>{Math.round(activeVehicle.speed_kmh)} км/ч</dd>
                </div>
                <div>
                  <dt>Курс</dt>
                  <dd>{Math.round(activeVehicle.heading)}°</dd>
                </div>
                <div>
                  <dt>Активных заявок</dt>
                  <dd>{jobs.length}</dd>
                </div>
                <div>
                  <dt>Зон обслуживания</dt>
                  <dd>{brigadeZones.length}</dd>
                </div>
              </dl>
              <h3>Текущие задания</h3>
              {jobs.length ? (
                jobs.map((job) => (
                  <button
                    className="brigade-job"
                    key={job.id}
                    onClick={() => onOpenMap(job.id)}
                  >
                    <b>{job.title}</b>
                    <small>{job.address}</small>
                    <em>{statusNames[job.status] || job.status}</em>
                  </button>
                ))
              ) : (
                <p className="no-jobs">
                  Бригада свободна и готова к назначению.
                </p>
              )}
              <h3>Закреплённые зоны</h3>
              {brigadeZones.length ? (
                brigadeZones.map((zone) => (
                  <div className="brigade-zone" key={zone.id}>
                    <b>{zone.name}</b>
                    <small>
                      Приоритет {zone.priority} · {zone.points.length} вершин
                    </small>
                  </div>
                ))
              ) : (
                <p className="no-jobs">Зоны для этой бригады не назначены.</p>
              )}
            </aside>
          )}
        </div>
      </section>
    );
  }
  const copy: Record<string, [string, string]> = {
    analytics: [
      "Динамика обращений",
      "Сводные показатели по районам и службам",
    ],
    sla: ["Исполнение SLA", "Контроль сроков и обращений под риском"],
    reports: ["Отчёты смены", "Выполненные работы и затраченное время"],
    notifications: [
      "Центр уведомлений",
      "Изменения статусов и новые назначения",
    ],
    profile: ["Профиль сотрудника", "Доступы, контакты и настройки"],
    create: ["Сообщить о проблеме", "Опишите ситуацию и отметьте место"],
    admin: ["Управление системой", "Роли, справочники и интеграции"],
  };
  const [title, subtitle] = copy[section] || [
    pageTitles[section] || "Раздел",
    "Рабочее пространство городских служб",
  ];
  return (
    <section className="content-page">
      <div className="page-toolbar">
        <div>
          <h2>{title}</h2>
          <p>{subtitle}</p>
        </div>
      </div>
      <div className="empty-state">
        <span>◎</span>
        <h3>{title}</h3>
        <p>
          Раздел подключён к навигации. Здесь отображаются данные, доступные для
          роли «{pageTitles[section] || section}».
        </p>
      </div>
    </section>
  );
}
