"use client";

/* eslint-disable react-hooks/set-state-in-effect */

import { FormEvent, useCallback, useEffect, useState } from "react";

import { api, config, Role, Session, type Ticket } from "./api";

import { ReadableDetails } from "./readable-details";

import {
  type Notice,
  type Dict,
  enumLabel,
  text,
  timestamp,
  Empty,
  Modal,
} from "./admin-shared";

const dispatchStatuses = [
  "UNKNOWN",
  "PENDING",
  "RESERVED",
  "CONFIRMING",
  "ASSIGNED",
  "FAILED",
  "CANCELLED",
  "EXPIRED",
];

const dispatchModes = ["UNKNOWN", "MANUAL", "AUTOMATIC"];

const routeStatuses = [
  "UNKNOWN",
  "PLANNED",
  "ACTIVE",
  "COMPLETED",
  "CANCELLED",
];

const deliveryStatuses = [
  "UNKNOWN",
  "PENDING",
  "PROCESSING",
  "SENT",
  "FAILED",
  "DEAD",
  "SKIPPED",
];

const deliveryChannels = ["UNKNOWN", "IN_APP", "PUSH", "EMAIL", "SMS"];

export function OperationsPage({
  session,
  role,
  tickets,
  onNotice,
}: {
  session: Session;
  role: Role;
  tickets: Ticket[];
  onNotice: Notice;
}) {
  const demo = session.accessToken === "demo",
    [tab, setTab] = useState<
      "dispatch" | "routes" | "templates" | "deliveries"
    >("dispatch"),
    [items, setItems] = useState<Dict[]>([]),
    [selected, setSelected] = useState<Dict>(),
    [modal, setModal] = useState(false);
  const [operationFilters, setOperationFilters] = useState({
    ticket_id: "",
    brigade_id: "",
    status: "",
    event_type: "",
    channel: "",
  });
  const [operationQuery, setOperationQuery] = useState("");
  const load = useCallback(async () => {
    if (demo) {
      const now = Math.floor(Date.now() / 1000),
        fixtures: Record<typeof tab, Dict[]> = {
          dispatch: [
            {
              id: "dispatch-demo-1",
              ticket_id: "INC-1042",
              brigade_id: "Бригада №7",
              route_id: "route-demo-2",
              mode: "AUTO",
              status: "ASSIGNED",
              version: 3,
              created_at: now - 2700,
            },
            {
              id: "dispatch-demo-2",
              ticket_id: "INC-1038",
              brigade_id: "Бригада №14",
              route_id: "route-demo-1",
              mode: "MANUAL",
              status: "ASSIGNED",
              version: 2,
              created_at: now - 1500,
            },
            {
              id: "dispatch-demo-3",
              ticket_id: "INC-1017",
              mode: "AUTO",
              status: "FAILED",
              failure_reason: "Нет подходящей свободной бригады",
              version: 1,
              created_at: now - 7200,
            },
          ],
          routes: [
            {
              id: "route-demo-1",
              ticket_id: "INC-1038",
              brigade_id: "Бригада №14",
              status: "PLANNED",
              calculation: { distance_meters: 2400, duration_seconds: 540 },
              created_at: now - 1500,
            },
            {
              id: "route-demo-2",
              ticket_id: "INC-1042",
              brigade_id: "Бригада №7",
              status: "ACTIVE",
              calculation: { distance_meters: 1800, duration_seconds: 420 },
              created_at: now - 2700,
            },
          ],
          templates: [
            {
              id: "template-demo-1",
              event_type: "ticket.assigned",
              channel: "IN_APP",
              status: "ACTIVE",
              subject: "Бригада назначена",
              body: "По заявке назначена городская бригада",
              created_at: now - 86400,
            },
            {
              id: "template-demo-2",
              event_type: "sla.warning",
              channel: "EMAIL",
              status: "ACTIVE",
              subject: "Риск нарушения SLA",
              body: "Приближается контрольный срок",
              created_at: now - 86400,
            },
          ],
          deliveries: [
            {
              id: "delivery-demo-1",
              event_type: "ticket.assigned",
              channel: "IN_APP",
              status: "SENT",
              subject: "demo.user@city.local",
              attempts: 1,
              created_at: now - 1500,
            },
            {
              id: "delivery-demo-2",
              event_type: "sla.warning",
              channel: "PUSH",
              status: "FAILED",
              subject: "demo-dispatcher-device",
              attempts: 3,
              created_at: now - 600,
            },
          ],
        };
      setItems(fixtures[tab]);
      setSelected(undefined);
      return;
    }
    try {
      let endpoint = config.endpoints.dispatchList,
        key = "operations";
      const body: Dict = { limit: 100, offset: 0 };
      if (tab === "dispatch" || tab === "routes") {
        if (operationFilters.ticket_id)
          body.ticket_id = operationFilters.ticket_id;
        if (operationFilters.brigade_id)
          body.brigade_id = operationFilters.brigade_id;
        if (operationFilters.status) body.status = operationFilters.status;
      }
      if (tab === "routes") {
        endpoint = config.endpoints.routesList;
        key = "routes";
      }
      if (tab === "templates") {
        endpoint = config.endpoints.notificationTemplatesList;
        key = "templates";
        if (operationFilters.event_type)
          body.event_type = operationFilters.event_type;
        if (operationFilters.channel) body.channel = operationFilters.channel;
      }
      if (tab === "deliveries") {
        endpoint = config.endpoints.notificationDeliveriesList;
        key = "deliveries";
        if (operationFilters.status) body.status = operationFilters.status;
        if (operationFilters.channel) body.channel = operationFilters.channel;
      }
      const result = await api<Record<string, Dict[]>>(
        endpoint,
        body,
        "POST",
        session.accessToken,
      );
      const normalized = (result[key] || []).map((item) =>
        tab === "dispatch"
          ? {
              ...item,
              status: enumLabel(item.status, dispatchStatuses),
              mode: enumLabel(item.mode, dispatchModes),
              created_at: item.created_at ?? item.created_at_unix_ms,
            }
          : tab === "routes"
            ? {
                ...item,
                status: enumLabel(item.status, routeStatuses),
                created_at: item.created_at ?? item.created_at_unix_ms,
              }
            : tab === "templates"
              ? { ...item, channel: enumLabel(item.channel, deliveryChannels) }
              : tab === "deliveries"
                ? {
                    ...item,
                    status: enumLabel(item.status, deliveryStatuses),
                    channel: enumLabel(item.channel, deliveryChannels),
                    event_type:
                      item.event_type ||
                      `Уведомление ${text(item.notification_id).slice(0, 8)}`,
                    subject:
                      item.subject || enumLabel(item.channel, deliveryChannels),
                  }
                : item,
      );
      setItems(normalized);
      setSelected(undefined);
    } catch (error) {
      onNotice(
        error instanceof Error
          ? error.message
          : "Не удалось загрузить операционный журнал",
      );
    }
  }, [demo, onNotice, operationFilters, session.accessToken, tab]);
  useEffect(() => {
    void load();
  }, [load]);
  async function routeStatus(status: string) {
    if (!selected) return;
    if (!demo)
      await api(
        config.endpoints.routesStatus,
        { id: selected.id, status },
        "POST",
        session.accessToken,
      );
    await load();
    onNotice("Статус маршрута обновлён");
  }
  async function cancelDispatch() {
    if (!selected) return;
    if (!demo)
      await api(
        config.endpoints.dispatchCancel,
        {
          id: selected.id,
          cancelled_by: session.user?.user_id,
          expected_version: Number(selected.version || 1),
          reason: "Отменено диспетчером",
        },
        "POST",
        session.accessToken,
      );
    await load();
    onNotice("Назначение отменено");
  }
  async function saveTemplate(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const d = new FormData(e.currentTarget);
    if (!demo)
      await api(
        config.endpoints.notificationTemplatesUpsert,
        {
          event_type: String(d.get("event_type")),
          channel: String(d.get("channel")),
          subject: String(d.get("subject")),
          body: String(d.get("body")),
          active: true,
        },
        "POST",
        session.accessToken,
      );
    setModal(false);
    await load();
    onNotice("Шаблон уведомления сохранён");
  }
  function applyFilters(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const d = new FormData(e.currentTarget);
    setOperationFilters({
      ticket_id: String(d.get("ticket_id") || ""),
      brigade_id: String(d.get("brigade_id") || ""),
      status: String(d.get("status") || ""),
      event_type: String(d.get("event_type") || ""),
      channel: String(d.get("channel") || ""),
    });
  }
  const tabs: [typeof tab, string][] = [
    ["dispatch", "Назначения"],
    ["routes", "Маршруты"],
    ["templates", "Шаблоны"],
    ["deliveries", "Доставка"],
  ];
  function switchTab(nextTab: typeof tab) {
    setItems([]);
    setSelected(undefined);
    setOperationFilters({
      ticket_id: "",
      brigade_id: "",
      status: "",
      event_type: "",
      channel: "",
    });
    setTab(nextTab);
  }
  const allowedTicketIds = new Set(
    tickets.map((item) => item.id.toLowerCase()),
  );
  const departmentItems =
    role === "dispatcher" && (tab === "dispatch" || tab === "routes")
      ? items.filter(
          (item) =>
            !item.ticket_id ||
            allowedTicketIds.has(text(item.ticket_id).toLowerCase()),
        )
      : items;
  const filteredItems = demo
    ? departmentItems.filter(
        (item) =>
          (!operationFilters.ticket_id ||
            text(item.ticket_id)
              .toLowerCase()
              .includes(operationFilters.ticket_id.toLowerCase())) &&
          (!operationFilters.brigade_id ||
            text(item.brigade_id)
              .toLowerCase()
              .includes(operationFilters.brigade_id.toLowerCase())) &&
          (!operationFilters.status ||
            text(item.status).toUpperCase() === operationFilters.status) &&
          (!operationFilters.event_type ||
            text(item.event_type)
              .toLowerCase()
              .includes(operationFilters.event_type.toLowerCase())) &&
          (!operationFilters.channel ||
            text(item.channel).toUpperCase() === operationFilters.channel),
      )
    : departmentItems;
  const normalizedOperationQuery = operationQuery
    .trim()
    .toLocaleLowerCase("ru-RU");
  const visibleItems = filteredItems.filter(
    (item) =>
      !normalizedOperationQuery ||
      JSON.stringify(item)
        .toLocaleLowerCase("ru-RU")
        .includes(normalizedOperationQuery),
  );
  return (
    <section className="ops-page">
      <div className="ops-head">
        <div>
          <span className="eyebrow">Операционный контроль</span>
          <h2>Маршруты, назначения и доставка</h2>
          <p>
            Состояние серверных процессов и детальная информация по каждой
            операции.
          </p>
        </div>
        {tab === "templates" && role === "admin" && (
          <button className="primary" onClick={() => setModal(true)}>
            + Шаблон
          </button>
        )}
      </div>
      <div className="ops-tabs">
        {tabs
          .filter(
            ([id]) =>
              role === "admin" ||
              !(["templates", "deliveries"] as string[]).includes(id),
          )
          .map(([id, label]) => (
            <button
              key={id}
              className={tab === id ? "active" : ""}
              onClick={() => switchTab(id)}
            >
              {label}
            </button>
          ))}
      </div>
      <form className="service-filters" onSubmit={applyFilters}>
        <label className="filter-search">
          Поиск
          <input
            value={operationQuery}
            onChange={(event) => setOperationQuery(event.target.value)}
            placeholder="UUID, название или значение"
          />
        </label>
        {(tab === "dispatch" || tab === "routes") && (
          <>
            <label>
              Заявка
              <input
                name="ticket_id"
                defaultValue={operationFilters.ticket_id}
                placeholder="UUID или номер"
              />
            </label>
            <label>
              Бригада
              <input
                name="brigade_id"
                defaultValue={operationFilters.brigade_id}
                placeholder="UUID"
              />
            </label>
            <label>
              Статус
              <select name="status" defaultValue={operationFilters.status}>
                <option value="">Все</option>
                {(tab === "dispatch" ? dispatchStatuses : routeStatuses)
                  .slice(1)
                  .map((value) => (
                    <option key={value}>{value}</option>
                  ))}
              </select>
            </label>
          </>
        )}
        {tab === "templates" && (
          <>
            <label className="filter-search">
              Тип события
              <input
                name="event_type"
                defaultValue={operationFilters.event_type}
                placeholder="ticket.assigned"
              />
            </label>
            <label>
              Канал
              <select name="channel" defaultValue={operationFilters.channel}>
                <option value="">Все</option>
                <option>IN_APP</option>
                <option>EMAIL</option>
                <option>PUSH</option>
                <option>SMS</option>
              </select>
            </label>
          </>
        )}
        {tab === "deliveries" && (
          <>
            <label>
              Статус
              <select name="status" defaultValue={operationFilters.status}>
                <option value="">Все</option>
                <option>PENDING</option>
                <option>PROCESSING</option>
                <option>SENT</option>
                <option>FAILED</option>
                <option>DEAD</option>
                <option>SKIPPED</option>
              </select>
            </label>
            <label>
              Канал
              <select name="channel" defaultValue={operationFilters.channel}>
                <option value="">Все</option>
                <option>IN_APP</option>
                <option>EMAIL</option>
                <option>PUSH</option>
                <option>SMS</option>
              </select>
            </label>
          </>
        )}
        <button type="submit">Применить</button>
        <button
          type="button"
          onClick={() => {
            setOperationFilters({
              ticket_id: "",
              brigade_id: "",
              status: "",
              event_type: "",
              channel: "",
            });
            setOperationQuery("");
          }}
        >
          Сбросить
        </button>
      </form>
      <div className={`ops-layout ${selected ? "selected" : ""}`}>
        <div className="operation-list">
          {visibleItems.map((item, index) => (
            <button
              key={text(item.id, index)}
              className={selected?.id === item.id ? "selected" : ""}
              onClick={() => setSelected(item)}
            >
              <span
                className={`ops-state ${text(item.status, "active").toLowerCase()}`}
              >
                ● {text(item.status, item.channel)}
              </span>
              <h3>
                {text(
                  item.event_type,
                  item.ticket_id
                    ? `Заявка ${item.ticket_id}`
                    : `Операция ${index + 1}`,
                )}
              </h3>
              <p>{text(item.brigade_id, item.subject)}</p>
              <small>{timestamp(item.created_at)}</small>
            </button>
          ))}
        </div>
        {!visibleItems.length && (
          <Empty>По выбранным фильтрам записей нет.</Empty>
        )}
        {selected && (
          <aside className="ops-detail">
            <button
              className="detail-close"
              onClick={() => setSelected(undefined)}
            >
              ×
            </button>
            <span className="eyebrow">Детали операции</span>
            <h2>{text(selected.event_type, selected.id)}</h2>
            <ReadableDetails data={selected} />
            {tab === "dispatch" &&
              !["ASSIGNED", "CANCELLED", "FAILED", "EXPIRED"].includes(
                text(selected.status),
              ) && (
                <button
                  className="danger-action"
                  onClick={() => void cancelDispatch()}
                >
                  Отменить назначение
                </button>
              )}
            {tab === "routes" && (
              <div className="ops-actions">
                <button onClick={() => void routeStatus("ACTIVE")}>
                  Активировать
                </button>
                <button onClick={() => void routeStatus("COMPLETED")}>
                  Завершить
                </button>
                <button
                  className="danger-action"
                  onClick={() => void routeStatus("CANCELLED")}
                >
                  Отменить
                </button>
              </div>
            )}
          </aside>
        )}
      </div>
      {modal && (
        <Modal title="Шаблон уведомления" onClose={() => setModal(false)}>
          <form className="ops-form" onSubmit={saveTemplate}>
            <label>
              Событие
              <input name="event_type" placeholder="ticket.assigned" required />
            </label>
            <label>
              Канал
              <select name="channel">
                <option>IN_APP</option>
                <option>EMAIL</option>
                <option>PUSH</option>
                <option>SMS</option>
              </select>
            </label>
            <label>
              Тема
              <input name="subject" />
            </label>
            <label>
              Текст
              <textarea name="body" rows={5} required />
            </label>
            <button className="primary">Сохранить</button>
          </form>
        </Modal>
      )}
    </section>
  );
}
