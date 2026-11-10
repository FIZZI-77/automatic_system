"use client";

/* eslint-disable react-hooks/set-state-in-effect */

import { useEffect, useState } from "react";

import { api, config, type Session } from "./api";

import { ReadableDetails } from "./readable-details";

import { type Notice } from "./service-shared";

type AuditEntry = {
  id: string;
  event_id: string;
  topic: string;
  action: string;
  actor_id?: string;
  entity_type?: string;
  entity_id?: string;
  occurred_at?: string | { seconds: number };
  recorded_at?: string | { seconds: number };
  data?: Record<string, unknown>;
  request_id?: string;
  trace_id?: string;
};

const auditActions: Record<string, string> = {
  "ticket.created": "Создана заявка",
  "ticket.updated": "Обновлена заявка",
  "ticket.assigned": "Назначена бригада",
  "ticket.completed": "Заявка завершена",
  "ticket.canceled": "Отменена заявка",
  "ticket.status_changed": "Изменён статус заявки",
  "ticket_category.created": "Создана категория заявок",
  "ticket_category.updated": "Обновлена категория заявок",
  "ticket_category.deactivated": "Отключена категория заявок",
  "auth.user.registered": "Зарегистрирован пользователь",
  "auth.user.password_changed": "Изменён пароль пользователя",
  "auth.session.logged_out": "Пользователь вышел из системы",
  "sla.CREATED": "Создан контроль SLA",
  "sla.RESPONSE_WARNING": "Срок реакции под риском",
  "sla.RESOLUTION_WARNING": "Срок выполнения под риском",
  "sla.RESPONSE_BREACHED": "Нарушен срок реакции",
  "sla.RESOLUTION_BREACHED": "Нарушен срок выполнения",
  "sla.RESPONSE_RECORDED": "Реакция зафиксирована",
  "sla.CANCELLED": "Контроль SLA отменён",
  "asset.CREATED": "Создан паспорт объекта",
  "asset.UPDATED": "Обновлён паспорт объекта",
  "asset.RISK_UPDATED": "Пересчитан риск объекта",
  "asset.INCIDENT_RECORDED": "Зарегистрирован инцидент объекта",
  "report.CREATED": "Создан отчёт",
  "report.COMPLETED": "Отчёт сформирован",
  "routing.route.created.v1": "Построен маршрут",
  "routing.route.recalculated.v1": "Маршрут перестроен",
  "routing.route.status.changed.v1": "Изменён статус маршрута",
  "routing.route.status_changed.v1": "Изменён статус маршрута",
  routing_route_status_changed_v1: "Изменён статус маршрута",
  BrigadeStatusChanged: "Изменён статус бригады",
  BrigadeSignalLost: "Потерян сигнал бригады",
  "department.created": "Создан департамент",
  "department.archived": "Департамент отправлен в архив",
};

const auditEntities: Record<string, string> = {
  ticket: "Заявка",
  ticket_category: "Категория заявок",
  sla: "Контроль SLA",
  asset: "Объект инфраструктуры",
  report: "Отчёт",
  routing: "Маршрут",
  auth: "Учётная запись",
  department: "Департамент",
  brigade: "Бригада",
  BrigadeStatusChanged: "Бригада",
  BrigadeSignalLost: "Бригада",
};

const auditTopics: Record<string, string> = {
  tickets: "Заявки",
  sla: "Контроль SLA",
  assets: "Инфраструктура",
  reports: "Отчёты",
  routing: "Маршруты",
  auth: "Пользователи и входы",
  departments: "Департаменты",
  brigades: "Бригады",
  locations: "Местоположение",
  profiles: "Сотрудники",
  notifications: "Уведомления",
  dispatch: "Назначения",
  "tickets.events.v1": "Заявки",
  "sla.events.v1": "Контроль SLA",
  "assets.events.v1": "Инфраструктура",
  "reports.events.v1": "Отчёты",
  "routing.events.v1": "Маршруты",
  "auth.events.v1": "Пользователи и входы",
  "departments.events.v1": "Департаменты",
  "brigades.events.v1": "Бригады",
  "locations.events.v1": "Местоположение",
  "profiles.events.v1": "Сотрудники",
  "notifications.events.v1": "Уведомления",
  "dispatch.events.v1": "Назначения",
};

function readableAuditAction(value: string) {
  return (
    auditActions[value] ||
    value
      .replace(/[._]/g, " ")
      .replace(/\bcreated\b/gi, "создано")
      .replace(/\bupdated\b/gi, "обновлено")
      .replace(/\bcompleted\b/gi, "завершено")
      .replace(/\bcancelled|canceled\b/gi, "отменено")
  );
}

function readableAuditEntity(value?: string) {
  return value
    ? auditEntities[value] || value.replace(/_/g, " ")
    : "Системный объект";
}

function readableAuditTopic(value: string) {
  return (
    auditTopics[value] || value.replace(".events.v1", "").replace(/_/g, " ")
  );
}

function shortAuditId(value?: string) {
  if (!value) return "—";
  return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

const auditValueNames: Record<string, string> = {
  "normal scheduled maintenance": "Продолжать плановое обслуживание",
  "shorten inspection interval": "Сократить интервал между осмотрами",
  "priority inspection and preventive repair":
    "Провести приоритетный осмотр и профилактический ремонт",
  "immediate inspection and replacement planning":
    "Немедленно осмотреть объект и запланировать замену",
  "service life is nearly exhausted": "Срок службы близок к окончанию",
  "repeated failures within 90 days":
    "Повторные неисправности за последние 90 дней",
  "inspection is overdue": "Плановый осмотр просрочен",
  "poor latest inspection condition":
    "Последний осмотр показал неудовлетворительное состояние",
};

function auditDateValue(value: unknown) {
  if (!value) return "—";
  const raw =
    typeof value === "object" && value !== null && "seconds" in value
      ? (value as { seconds: unknown }).seconds
      : value;
  const numeric = Number(raw),
    parsed =
      Number.isFinite(numeric) && numeric > 0
        ? new Date(numeric > 10_000_000_000 ? numeric : numeric * 1000)
        : new Date(String(raw));
  return Number.isNaN(parsed.getTime())
    ? String(raw)
    : parsed.toLocaleString("ru-RU");
}

function humanizeAuditPayload(value: unknown, key = ""): unknown {
  if (Array.isArray(value))
    return value.map((item) => humanizeAuditPayload(item, key));
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(
        ([childKey, childValue]) => [
          childKey,
          humanizeAuditPayload(childValue, childKey),
        ],
      ),
    );
  const source = String(value ?? "");
  if (key === "event_type") return readableAuditAction(source);
  if (key === "topic") return readableAuditTopic(source);
  return auditValueNames[source] || value;
}

function auditDetails(entry: Record<string, unknown>) {
  return {
    occurred_at: auditDateValue(entry.occurred_at),
    action: readableAuditAction(String(entry.action || "")),
    entity_type: readableAuditEntity(String(entry.entity_type || "")),
    entity_id: entry.entity_id,
    actor_id: entry.actor_id
      ? `Пользователь ${shortAuditId(String(entry.actor_id))}`
      : "Системный процесс",
    topic: readableAuditTopic(String(entry.topic || "")),
    data: humanizeAuditPayload(entry.data),
  };
}

export function AuditPage({
  session,
  onNotice,
}: {
  session: Session;
  onNotice: Notice;
}) {
  const demo = session.accessToken === "demo";
  const [items, setItems] = useState<AuditEntry[]>([]),
    [auditFilters, setAuditFilters] = useState({
      action: "",
      topic: "",
      entity_type: "",
      from: "",
      to: "",
    }),
    [selected, setSelected] = useState<Record<string, unknown>>();
  const [auditQuery, setAuditQuery] = useState("");
  useEffect(() => {
    if (demo) {
      setItems([
        {
          id: "audit-demo",
          event_id: "event-demo",
          topic: "tickets",
          action: "ticket.completed",
          actor_id: "demo-worker",
          entity_type: "ticket",
          entity_id: "inc-1042",
          occurred_at: new Date().toISOString(),
        },
      ]);
      return;
    }
    let active = true;
    api<{ entries: AuditEntry[] }>(
      config.endpoints.audit,
      {
        limit: 100,
        offset: 0,
        ...(auditFilters.action ? { action: auditFilters.action } : {}),
        ...(auditFilters.topic ? { topic: auditFilters.topic } : {}),
        ...(auditFilters.entity_type
          ? { entity_type: auditFilters.entity_type }
          : {}),
        ...(auditFilters.from
          ? { from: `${auditFilters.from}T00:00:00Z` }
          : {}),
        ...(auditFilters.to ? { to: `${auditFilters.to}T23:59:59Z` } : {}),
      },
      "POST",
      session.accessToken,
    )
      .then((result) => {
        if (active) setItems(result.entries || []);
      })
      .catch((error) => {
        if (active)
          onNotice(
            error instanceof Error
              ? error.message
              : "Не удалось загрузить аудит",
          );
      });
    return () => {
      active = false;
    };
  }, [auditFilters, demo, onNotice, session.accessToken]);
  const date = (value: AuditEntry["occurred_at"]) => {
    if (!value) return "—";
    return new Date(
      typeof value === "string" ? value : Number(value.seconds || 0) * 1000,
    ).toLocaleString("ru-RU");
  };
  async function open(item: AuditEntry) {
    if (demo) {
      setSelected(auditDetails(item as unknown as Record<string, unknown>));
      return;
    }
    try {
      const result = await api<Record<string, unknown>>(
          config.endpoints.auditGet,
          { id: item.id },
          "POST",
          session.accessToken,
        ),
        entry = (
          result.entry && typeof result.entry === "object"
            ? result.entry
            : result
        ) as Record<string, unknown>;
      setSelected(auditDetails(entry));
    } catch (error) {
      onNotice(
        error instanceof Error
          ? error.message
          : "Не удалось открыть запись аудита",
      );
    }
  }
  const normalizedAuditQuery = auditQuery.trim().toLocaleLowerCase("ru-RU");
  const visibleItems = (
    demo
      ? items.filter(
          (item) =>
            (!auditFilters.action ||
              item.action.includes(auditFilters.action)) &&
            (!auditFilters.topic || item.topic.includes(auditFilters.topic)) &&
            (!auditFilters.entity_type ||
              item.entity_type === auditFilters.entity_type),
        )
      : items
  ).filter(
    (item) =>
      !normalizedAuditQuery ||
      [
        item.id,
        item.event_id,
        item.entity_id,
        item.actor_id,
        item.action,
        item.topic,
        item.entity_type,
        readableAuditAction(item.action),
        readableAuditEntity(item.entity_type),
        readableAuditTopic(item.topic),
      ].some((value) =>
        String(value || "")
          .toLocaleLowerCase("ru-RU")
          .includes(normalizedAuditQuery),
      ),
  );
  return (
    <section className="content-page audit-page">
      <div className="page-toolbar">
        <div>
          <h2>Журнал аудита</h2>
          <p>Неизменяемая история действий пользователей и сервисов</p>
        </div>
      </div>
      <div className="service-filters">
        <label className="filter-search">
          Поиск
          <input
            value={auditQuery}
            onChange={(event) => setAuditQuery(event.target.value)}
            placeholder="UUID, название действия или раздел"
          />
        </label>
        <label>
          Код действия
          <input
            value={auditFilters.action}
            onChange={(event) =>
              setAuditFilters((v) => ({ ...v, action: event.target.value }))
            }
            placeholder="Например, ticket.created"
          />
        </label>
        <label>
          Код источника
          <input
            value={auditFilters.topic}
            onChange={(event) =>
              setAuditFilters((v) => ({ ...v, topic: event.target.value }))
            }
            placeholder="Например, tickets.events.v1"
          />
        </label>
        <label>
          Код объекта
          <input
            value={auditFilters.entity_type}
            onChange={(event) =>
              setAuditFilters((v) => ({
                ...v,
                entity_type: event.target.value,
              }))
            }
            placeholder="Например, ticket"
          />
        </label>
        <label>
          С даты
          <input
            type="date"
            value={auditFilters.from}
            onChange={(event) =>
              setAuditFilters((v) => ({ ...v, from: event.target.value }))
            }
          />
        </label>
        <label>
          По дату
          <input
            type="date"
            value={auditFilters.to}
            onChange={(event) =>
              setAuditFilters((v) => ({ ...v, to: event.target.value }))
            }
          />
        </label>
        <button
          onClick={() => {
            setAuditFilters({
              action: "",
              topic: "",
              entity_type: "",
              from: "",
              to: "",
            });
            setAuditQuery("");
          }}
        >
          Сбросить
        </button>
      </div>
      <div className="audit-table">
        <div className="audit-head">
          <span>Время</span>
          <span>Что произошло</span>
          <span>С чем</span>
          <span>Кто выполнил</span>
          <span>Раздел системы</span>
        </div>
        {visibleItems.map((item) => (
          <button
            className="audit-row"
            key={item.id}
            onClick={() => void open(item)}
          >
            <time>{date(item.occurred_at)}</time>
            <b>{readableAuditAction(item.action)}</b>
            <span>
              {readableAuditEntity(item.entity_type)}
              <small>
                {item.entity_id
                  ? `№ ${shortAuditId(item.entity_id)}`
                  : "Без номера"}
              </small>
            </span>
            <span>
              {item.actor_id
                ? `Пользователь ${shortAuditId(item.actor_id)}`
                : "Системный процесс"}
            </span>
            <em>{readableAuditTopic(item.topic)}</em>
          </button>
        ))}
      </div>
      {selected && (
        <div
          className="audit-modal"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setSelected(undefined);
          }}
        >
          <div role="dialog" aria-modal="true">
            <button
              className="detail-close"
              onClick={() => setSelected(undefined)}
            >
              ×
            </button>
            <span className="eyebrow">Запись аудита</span>
            <h2>{String(selected.action || "Событие системы")}</h2>
            <ReadableDetails
              data={Object.fromEntries(
                Object.entries(selected).filter(([key]) => key !== "action"),
              )}
            />
          </div>
        </div>
      )}
    </section>
  );
}
