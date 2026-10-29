"use client";

/* eslint-disable react-hooks/set-state-in-effect */

import { useEffect, useState } from "react";

import { api, config, type Role, type Session, type Ticket } from "./api";

import { ReadableDetails } from "./readable-details";

import { type Notice } from "./service-shared";

type TicketSLA = {
  id: string;
  ticket_id: string;
  priority: string | number;
  status: string | number;
  response_deadline?: string | { seconds: number };
  resolution_deadline?: string | { seconds: number };
  response_breached: boolean;
  resolution_breached: boolean;
  response_warning_sent: boolean;
  resolution_warning_sent: boolean;
};

const slaPriorities: Record<string, string> = {
  "1": "Низкий",
  "2": "Средний",
  "3": "Высокий",
  "4": "Экстренный",
  LOW: "Низкий",
  MEDIUM: "Средний",
  HIGH: "Высокий",
  EMERGENCY: "Экстренный",
};

const slaStatuses: Record<string, string> = {
  "1": "Активно",
  "2": "Завершено",
  "3": "Отменено",
  ACTIVE: "Активно",
  COMPLETED: "Завершено",
  CANCELLED: "Отменено",
};

const slaEvents: Record<string, string> = {
  "1": "SLA создан",
  "2": "Реакция зафиксирована",
  "3": "Срок реакции под риском",
  "4": "Срок реакции нарушен",
  "5": "Срок выполнения под риском",
  "6": "Срок выполнения нарушен",
  "7": "Сроки SLA пересчитаны",
  "8": "SLA завершён",
  "9": "SLA отменён",
  CREATED: "SLA создан",
  RESPONSE_RECORDED: "Реакция зафиксирована",
  RESPONSE_WARNING: "Срок реакции под риском",
  RESPONSE_BREACHED: "Срок реакции нарушен",
  RESOLUTION_WARNING: "Срок выполнения под риском",
  RESOLUTION_BREACHED: "Срок выполнения нарушен",
  RECALCULATED: "Сроки SLA пересчитаны",
  COMPLETED: "SLA завершён",
  CANCELLED: "SLA отменён",
};

function slaPriorityLabel(value: unknown) {
  const key = String(value).toUpperCase().replace("TICKET_PRIORITY_", "");
  return slaPriorities[key] || String(value ?? "—");
}

function slaStatusLabel(value: unknown) {
  const key = String(value).toUpperCase().replace("SLA_STATUS_", "");
  return slaStatuses[key] || String(value ?? "—");
}

function humanizeSLARecord(value: Record<string, unknown>) {
  const source = (
    value.sla && typeof value.sla === "object" ? value.sla : value
  ) as Record<string, unknown>;
  return Object.fromEntries(
    Object.entries(source).map(([key, item]) =>
      key === "priority"
        ? [key, slaPriorityLabel(item)]
        : key === "status"
          ? [key, slaStatusLabel(item)]
          : key === "event_type"
            ? [
                key,
                slaEvents[
                  String(item).toUpperCase().replace("SLA_EVENT_TYPE_", "")
                ] || item,
              ]
            : [key, item],
    ),
  );
}

export function SLAPage({
  session,
  tickets,
  role,
  onOpenMap,
  onNotice,
}: {
  session: Session;
  tickets: Ticket[];
  role: Role;
  onOpenMap: (id: string) => void;
  onNotice: Notice;
}) {
  const demo = session.accessToken === "demo",
    scopeDepartment =
      role === "dispatcher" ? session.user?.department_id || "" : "";
  const [rows, setRows] = useState<TicketSLA[]>([]),
    [selected, setSelected] = useState<{
      sla: Record<string, unknown>;
      history: Record<string, unknown>[];
    }>(),
    [slaFilters, setSlaFilters] = useState({
      department_id: "",
      status: "",
      breached: "",
    });
  const [slaQuery, setSlaQuery] = useState("");
  useEffect(() => {
    if (demo) {
      setRows(
        tickets.map((ticket) => ({
          id: `sla-${ticket.id}`,
          ticket_id: ticket.id,
          priority: ticket.priority,
          status: ticket.status,
          response_breached: false,
          resolution_breached: false,
          response_warning_sent: false,
          resolution_warning_sent: false,
        })),
      );
      return;
    }
    let active = true;
    api<{ slas: TicketSLA[] }>(
      config.endpoints.slaList,
      {
        limit: 100,
        offset: 0,
        ...(scopeDepartment || slaFilters.department_id
          ? { department_id: scopeDepartment || slaFilters.department_id }
          : {}),
        ...(slaFilters.status ? { status: slaFilters.status } : {}),
        ...(slaFilters.breached
          ? { breached: slaFilters.breached === "true" }
          : {}),
      },
      "POST",
      session.accessToken,
    )
      .then((result) => {
        if (active) setRows(result.slas || []);
      })
      .catch((error) => {
        if (active)
          onNotice(
            error instanceof Error ? error.message : "Не удалось загрузить SLA",
          );
      });
    return () => {
      active = false;
    };
  }, [
    demo,
    onNotice,
    scopeDepartment,
    session.accessToken,
    slaFilters,
    tickets,
  ]);
  const breached = rows.filter(
      (row) => row.response_breached || row.resolution_breached,
    ).length,
    risk = rows.filter(
      (row) =>
        !row.response_breached &&
        !row.resolution_breached &&
        (row.response_warning_sent || row.resolution_warning_sent),
    ).length,
    normal = rows.length - breached - risk;
  const deadline = (value: TicketSLA["resolution_deadline"]) => {
    if (!value) return "—";
    const date =
      typeof value === "string"
        ? new Date(value)
        : new Date(Number(value.seconds || 0) * 1000);
    return date.toLocaleString("ru-RU");
  };
  async function openSLA(row: TicketSLA) {
    if (demo) {
      setSelected({
        sla: humanizeSLARecord(row as unknown as Record<string, unknown>),
        history: [],
      });
      return;
    }
    try {
      const [sla, history] = await Promise.all([
        api<Record<string, unknown>>(
          config.endpoints.slaTicketGet,
          { ticket_id: row.ticket_id },
          "POST",
          session.accessToken,
        ),
        api<{ history: Record<string, unknown>[] }>(
          config.endpoints.slaHistory,
          { ticket_id: row.ticket_id },
          "POST",
          session.accessToken,
        ),
      ]);
      setSelected({
        sla: humanizeSLARecord(sla),
        history: (history.history || []).map(humanizeSLARecord),
      });
    } catch (error) {
      onNotice(
        error instanceof Error
          ? error.message
          : "Не удалось открыть историю SLA",
      );
    }
  }
  const normalizedSlaQuery = slaQuery.trim().toLocaleLowerCase("ru-RU");
  const visibleRows = (
    demo
      ? rows.filter(
          (row) =>
            (!slaFilters.department_id ||
              tickets.find((ticket) => ticket.id === row.ticket_id)
                ?.department_id === slaFilters.department_id) &&
            (!slaFilters.status ||
              String(row.status).toUpperCase() === slaFilters.status) &&
            (!slaFilters.breached ||
              (row.response_breached || row.resolution_breached) ===
                (slaFilters.breached === "true")),
        )
      : rows
  ).filter((row) => {
    const ticket = tickets.find((item) => item.id === row.ticket_id);
    return (
      !normalizedSlaQuery ||
      [
        row.id,
        row.ticket_id,
        ticket?.id,
        ticket?.title,
        ticket?.address,
        ticket?.department_id,
      ].some((value) =>
        String(value || "")
          .toLocaleLowerCase("ru-RU")
          .includes(normalizedSlaQuery),
      )
    );
  });
  return (
    <section className="content-page sla-page">
      <div className="page-toolbar">
        <div>
          <h2>Исполнение SLA</h2>
          <p>
            Состояние рассчитывается SLA Service, а не локальными таймерами
            интерфейса
          </p>
        </div>
      </div>
      <div className="service-filters">
        <label className="filter-search">
          Поиск
          <input
            value={slaQuery}
            onChange={(e) => setSlaQuery(e.target.value)}
            placeholder="UUID заявки, название или адрес"
          />
        </label>
        <label>
          Департамент
          <select
            value={slaFilters.department_id}
            onChange={(e) =>
              setSlaFilters((v) => ({ ...v, department_id: e.target.value }))
            }
          >
            <option value="">Все</option>
            {Array.from(
              new Set(
                tickets.map((ticket) => ticket.department_id).filter(Boolean),
              ),
            ).map((id) => (
              <option key={id} value={id}>
                {id}
              </option>
            ))}
          </select>
        </label>
        <label>
          Статус
          <select
            value={slaFilters.status}
            onChange={(e) =>
              setSlaFilters((v) => ({ ...v, status: e.target.value }))
            }
          >
            <option value="">Все</option>
            <option value="ACTIVE">Активно</option>
            <option value="COMPLETED">Завершено</option>
            <option value="CANCELLED">Отменено</option>
          </select>
        </label>
        <label>
          Нарушение
          <select
            value={slaFilters.breached}
            onChange={(e) =>
              setSlaFilters((v) => ({ ...v, breached: e.target.value }))
            }
          >
            <option value="">Все</option>
            <option value="true">Нарушено</option>
            <option value="false">Без нарушения</option>
          </select>
        </label>
        <button
          onClick={() => {
            setSlaFilters({ department_id: "", status: "", breached: "" });
            setSlaQuery("");
          }}
        >
          Сбросить
        </button>
      </div>
      <div className="sla-summary">
        <article>
          <span>В нормативе</span>
          <b>{normal}</b>
          <small>
            {rows.length ? Math.round((normal / rows.length) * 100) : 100}%
            заявок
          </small>
        </article>
        <article>
          <span>Под риском</span>
          <b>{risk}</b>
          <small>предупреждение сервиса</small>
        </article>
        <article>
          <span>Нарушено</span>
          <b>{breached}</b>
          <small>требуют эскалации</small>
        </article>
        <article>
          <span>Всего под контролем</span>
          <b>{rows.length}</b>
          <small>активных записей SLA</small>
        </article>
      </div>
      <div className="sla-table">
        <div className="sla-table-head">
          <span>Заявка</span>
          <span>Приоритет</span>
          <span>Дедлайн</span>
          <span>Статус</span>
          <span>Состояние</span>
        </div>
        {visibleRows.map((row) => {
          const ticket = tickets.find((item) => item.id === row.ticket_id),
            level =
              row.response_breached || row.resolution_breached
                ? "breached"
                : row.response_warning_sent || row.resolution_warning_sent
                  ? "risk"
                  : "normal";
          return (
            <button key={row.id} onClick={() => void openSLA(row)}>
              <div>
                <b>{ticket?.title || row.ticket_id}</b>
                <small>{ticket?.address || "Адрес заявки"}</small>
              </div>
              <span>{slaPriorityLabel(row.priority)}</span>
              <span>{deadline(row.resolution_deadline)}</span>
              <span>{slaStatusLabel(row.status)}</span>
              <em className={`sla-level ${level}`}>
                {level === "breached"
                  ? "Нарушено"
                  : level === "risk"
                    ? "Под риском"
                    : "В нормативе"}
              </em>
            </button>
          );
        })}
      </div>
      {selected && (
        <div
          className="sla-detail-modal"
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
            <span className="eyebrow">Карточка SLA</span>
            <h2>Расчёт и история</h2>
            <ReadableDetails className="sla-main-details" data={selected.sla} />
            <h3>Изменения</h3>
            {selected.history.length ? (
              selected.history.map((item, index) => (
                <article
                  className="readable-history-card"
                  key={String(item.id || index)}
                >
                  <ReadableDetails data={item} />
                </article>
              ))
            ) : (
              <p>История пока пуста.</p>
            )}
            <button
              className="ghost"
              onClick={() => {
                const ticketId = String(selected.sla.ticket_id || "");
                if (ticketId) onOpenMap(ticketId);
              }}
            >
              Показать заявку на карте
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
