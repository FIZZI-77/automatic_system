"use client";

/* eslint-disable react-hooks/set-state-in-effect, react-hooks/exhaustive-deps */

import { FormEvent, useEffect, useState } from "react";

import { api, config, type Role, type Session, type Ticket } from "./api";

import { type Notice, type Department, type Category } from "./service-shared";

type GeneratedReport = {
  id: string;
  name: string;
  type: string | number;
  format: string | number;
  status: string | number;
  error?: string;
  created_at?: string;
};

const reportTypes = [
  "UNSPECIFIED",
  "TICKET_OVERVIEW",
  "SLA_SUMMARY",
  "TICKET_BREAKDOWN",
  "DAILY_TICKETS",
];

const reportFormats = ["UNSPECIFIED", "PDF", "XLSX", "CSV"];

const reportStatuses = [
  "UNSPECIFIED",
  "PENDING",
  "PROCESSING",
  "COMPLETED",
  "FAILED",
  "CANCELED",
];

function reportEnum(value: string | number, labels: string[]): string {
  return typeof value === "number" ? labels[value] || "UNSPECIFIED" : value;
}

export function ReportsPage({
  session,
  tickets,
  role,
  onNotice,
}: {
  session: Session;
  tickets: Ticket[];
  role: Role;
  onNotice: Notice;
}) {
  const demo = session.accessToken === "demo";
  const scopeDepartment =
    role === "dispatcher" ? session.user?.department_id || "" : "";
  const [items, setItems] = useState<GeneratedReport[]>([]),
    [busy, setBusy] = useState(false),
    [statusFilter, setStatusFilter] = useState(""),
    [reportQuery, setReportQuery] = useState("");
  const [mode, setMode] = useState<"full" | "ticket">(
      role === "worker" ? "ticket" : "full",
    ),
    [files, setFiles] = useState<File[]>([]);
  const [departments, setDepartments] = useState<Department[]>([]),
    [categories, setCategories] = useState<Category[]>([]);
  const [ticketArtifacts, setTicketArtifacts] = useState<
    Array<{
      file_id: string;
      name: string;
      ticket_id: string;
      ticket_title: string;
    }>
  >([]);
  const activeTickets = tickets.filter((ticket) =>
    ["ASSIGNED", "IN_PROGRESS"].includes(ticket.status),
  );

  async function load() {
    if (demo) {
      setItems([
        {
          id: "demo-report",
          name: "Сводка обращений",
          type: "TICKET_OVERVIEW",
          format: "PDF",
          status: "COMPLETED",
        },
      ]);
      return;
    }
    try {
      const result = await api<{ reports: GeneratedReport[] }>(
        config.endpoints.reportsList,
        {
          limit: 100,
          offset: 0,
          ...(statusFilter ? { status: statusFilter.toLowerCase() } : {}),
        },
        "POST",
        session.accessToken,
      );
      setItems(
        (result.reports || []).map((item) => ({
          ...item,
          type: reportEnum(item.type, reportTypes),
          format: reportEnum(item.format, reportFormats),
          status: reportEnum(item.status, reportStatuses),
        })),
      );
    } catch (error) {
      setItems([]);
      onNotice(
        error instanceof Error ? error.message : "Не удалось загрузить отчёты",
      );
    }
  }
  useEffect(() => {
    if (role !== "worker") void load();
  }, [demo, role, session.accessToken, statusFilter]);
  useEffect(() => {
    if (role === "worker") return;
    if (demo) {
      setDepartments(
        [
          { id: "dep-roads", name: "Дорожное хозяйство" },
          { id: "dep-utilities", name: "Городское хозяйство" },
        ].filter((item) => !scopeDepartment || item.id === scopeDepartment),
      );
      setCategories([
        { id: "cat-roads", name: "Дороги" },
        { id: "cat-light", name: "Освещение" },
      ]);
      return;
    }
    let active = true;
    Promise.all([
      api<{ departments: Department[] }>(
        config.endpoints.departmentsList,
        { limit: 100, offset: 0 },
        "POST",
        session.accessToken,
      ),
      api<{ categories: Category[] }>(
        config.endpoints.ticketCategoriesList,
        { limit: 100, offset: 0 },
        "POST",
        session.accessToken,
      ),
    ])
      .then(([departmentResult, categoryResult]) => {
        if (active) {
          setDepartments(
            (departmentResult.departments || []).filter(
              (item) => !scopeDepartment || item.id === scopeDepartment,
            ),
          );
          setCategories(categoryResult.categories || []);
        }
      })
      .catch((error) => {
        if (active)
          onNotice(
            error instanceof Error
              ? error.message
              : "Не удалось загрузить фильтры отчёта",
          );
      });
    return () => {
      active = false;
    };
  }, [demo, onNotice, role, scopeDepartment, session.accessToken]);

  async function createFull(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget),
      from = String(form.get("from") || ""),
      to = String(form.get("to") || "");
    const filter = {
      ...(from ? { from: new Date(from + "T00:00:00Z").toISOString() } : {}),
      ...(to ? { to: new Date(to + "T23:59:59Z").toISOString() } : {}),
      ...(scopeDepartment || form.get("department_id")
        ? {
            department_id: scopeDepartment || String(form.get("department_id")),
          }
        : {}),
      ...(form.get("category_id")
        ? { category_id: String(form.get("category_id")) }
        : {}),
      ...(form.get("priority")
        ? { priority: String(form.get("priority")) }
        : {}),
    };
    setBusy(true);
    try {
      if (!demo)
        await api(
          config.endpoints.reportsCreate,
          {
            name: String(form.get("name")),
            type: String(form.get("type")),
            format: String(form.get("format")),
            filter,
          },
          "POST",
          session.accessToken,
        );
      onNotice("Полный аналитический отчёт поставлен в очередь");
      await load();
    } catch (error) {
      onNotice(
        error instanceof Error
          ? error.message
          : "Не удалось создать полный отчёт",
      );
    } finally {
      setBusy(false);
    }
  }

  async function createTicketReport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget,
      form = new FormData(formElement),
      ticketId = String(form.get("ticket_id") || ""),
      description = String(form.get("description") || "").trim(),
      ticket = tickets.find((item) => item.id === ticketId);
    if (!ticket) {
      onNotice("Выберите заявку");
      return;
    }
    setBusy(true);
    try {
      const fileIds: string[] = [];
      if (!demo)
        for (const file of files) {
          const created = await api<{
            file: { id: string };
            upload_url: string;
          }>(
            config.endpoints.filesUploadCreate,
            {
              name: file.name,
              content_type: file.type || "application/octet-stream",
              size: file.size,
            },
            "POST",
            session.accessToken,
          );
          const uploaded = await fetch(created.upload_url, {
            method: "PUT",
            headers: {
              "Content-Type": file.type || "application/octet-stream",
            },
            body: file,
          });
          if (!uploaded.ok)
            throw new Error("Не удалось загрузить " + file.name);
          await api(
            config.endpoints.filesUploadConfirm,
            { file_id: created.file.id },
            "POST",
            session.accessToken,
          );
          fileIds.push(created.file.id);
        }
      if (demo) {
        setTicketArtifacts((current) => [
          {
            file_id: "demo-ticket-report-" + Date.now(),
            name: "Отчёт " + ticket.id + ".pdf",
            ticket_id: ticket.id,
            ticket_title: ticket.title,
          },
          ...current,
        ]);
      } else {
        await api(
          config.endpoints.completionReportsCreate,
          { ticket_id: ticket.id, description, file_ids: fileIds },
          "POST",
          session.accessToken,
        );
      }
      setFiles([]);
      formElement.reset();
      onNotice(
        demo
          ? "PDF по заявке «" + ticket.title + "» сформирован"
          : "Акт по заявке «" +
              ticket.title +
              "» поставлен в очередь. PDF появится в карточке заявки после обработки",
      );
    } catch (error) {
      onNotice(
        error instanceof Error
          ? error.message
          : "Не удалось сформировать отчёт по заявке",
      );
    } finally {
      setBusy(false);
    }
  }

  async function action(
    item: GeneratedReport,
    kind: "download" | "retry" | "cancel",
  ) {
    if (demo) {
      onNotice("Действие доступно после входа");
      return;
    }
    if (kind === "download") {
      const result = await api<{ download_url: string }>(
        config.endpoints.reportsDownload,
        { report_id: item.id },
        "POST",
        session.accessToken,
      );
      window.open(result.download_url, "_blank", "noopener,noreferrer");
    } else {
      await api(
        kind === "retry"
          ? config.endpoints.reportsRetry
          : config.endpoints.reportsCancel,
        { report_id: item.id },
        "POST",
        session.accessToken,
      );
      await load();
    }
  }
  async function downloadTicketArtifact(fileId: string) {
    if (demo) {
      onNotice("Скачивание доступно после входа");
      return;
    }
    try {
      const result = await api<{ download_url: string }>(
        config.endpoints.filesDownload,
        { file_id: fileId },
        "POST",
        session.accessToken,
      );
      window.open(result.download_url, "_blank", "noopener,noreferrer");
    } catch (error) {
      onNotice(
        error instanceof Error ? error.message : "Не удалось скачать отчёт",
      );
    }
  }

  const visibleItems = (
    demo && statusFilter
      ? items.filter(
          (item) => String(item.status).toUpperCase() === statusFilter,
        )
      : items
  ).filter(
    (item) =>
      !reportQuery.trim() ||
      `${item.id} ${item.name} ${item.type} ${item.format} ${item.status}`
        .toLocaleLowerCase("ru-RU")
        .includes(reportQuery.trim().toLocaleLowerCase("ru-RU")),
  );
  return (
    <section className="content-page reports-page">
      <div className="page-toolbar">
        <div>
          <h2>Отчёты</h2>
          <p>
            {role === "worker"
              ? "Акт выполнения по назначенной заявке"
              : "Полная аналитика или акт выполнения по конкретной заявке"}
          </p>
        </div>
      </div>
      {role !== "worker" && (
        <div
          className="report-mode-tabs"
          role="tablist"
          aria-label="Режим формирования отчёта"
        >
          <button
            className={mode === "full" ? "active" : ""}
            onClick={() => setMode("full")}
          >
            Полный отчёт
          </button>
          <button
            className={mode === "ticket" ? "active" : ""}
            onClick={() => setMode("ticket")}
          >
            По заявке
          </button>
        </div>
      )}
      {role !== "worker" && mode === "full" ? (
        <form className="report-builder" onSubmit={createFull}>
          <div className="report-builder-head">
            <div>
              <span className="eyebrow">Аналитика</span>
              <h3>Полный аналитический отчёт</h3>
              <p>Сводка по всем данным или по выбранным условиям.</p>
            </div>
          </div>
          <div className="report-fields">
            <label className="wide">
              Название
              <input
                name="name"
                required
                defaultValue="Полный отчёт по городским обращениям"
              />
            </label>
            <label>
              Тип
              <select name="type">
                <option value="ticket_overview">Обзор заявок</option>
                <option value="sla_summary">SLA</option>
                <option value="ticket_breakdown">
                  Распределение по департаментам
                </option>
                <option value="daily_tickets">Динамика по дням</option>
              </select>
            </label>
            <label>
              Формат
              <select name="format">
                <option value="pdf">PDF</option>
                <option value="xlsx">XLSX</option>
                <option value="csv">CSV</option>
              </select>
            </label>
            <label>
              С даты
              <input name="from" type="date" />
            </label>
            <label>
              По дату
              <input name="to" type="date" />
            </label>
            <label>
              Департамент
              <select
                name="department_id"
                defaultValue={scopeDepartment}
                disabled={Boolean(scopeDepartment)}
              >
                <option value="">Все департаменты</option>
                {departments.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Категория
              <select name="category_id">
                <option value="">Все категории</option>
                {categories.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Приоритет
              <select name="priority">
                <option value="">Все приоритеты</option>
                <option>LOW</option>
                <option>MEDIUM</option>
                <option>HIGH</option>
                <option>EMERGENCY</option>
              </select>
            </label>
          </div>
          <div className="report-submit">
            <small>
              Если условия не выбраны, отчёт охватит все доступные данные.
            </small>
            <button className="primary" disabled={busy}>
              {busy ? "Формируем…" : "Сформировать полный отчёт"}
            </button>
          </div>
        </form>
      ) : (
        <form
          className="report-builder ticket-report-builder"
          onSubmit={createTicketReport}
        >
          <div className="report-builder-head">
            <div>
              <span className="eyebrow">Заявка</span>
              <h3>Отчёт о выполнении</h3>
              <p>
                PDF с заявкой, адресом, автором, бригадой, составом и описанием
                работ.
              </p>
            </div>
          </div>
          <div className="report-fields">
            <label className="wide">
              Заявка
              <select name="ticket_id" required defaultValue="">
                <option value="" disabled>
                  Выберите активную заявку
                </option>
                {activeTickets.map((ticket) => (
                  <option key={ticket.id} value={ticket.id}>
                    {ticket.title} · {ticket.address}
                  </option>
                ))}
              </select>
            </label>
            <label className="wide">
              Что было выполнено
              <textarea
                name="description"
                rows={5}
                required
                minLength={3}
                placeholder="Опишите выполненные работы и результат"
              />
            </label>
            <label className="wide report-file-field">
              Фотографии и документы
              <input
                name="files"
                type="file"
                multiple
                accept="image/*,.pdf,.doc,.docx"
                onChange={(event) =>
                  setFiles(Array.from(event.target.files || []))
                }
              />
              <span>
                {files.length
                  ? "Выбрано файлов: " + files.length
                  : "Фотографии будут встроены в PDF"}
              </span>
            </label>
          </div>
          {!activeTickets.length && (
            <p className="report-warning">
              Нет назначенных или выполняемых заявок, для которых можно создать
              отчёт.
            </p>
          )}
          <div className="report-submit">
            <small>Создание отчёта не завершает заявку автоматически.</small>
            <button
              className="primary"
              disabled={busy || !activeTickets.length}
            >
              {busy ? "Формируем PDF…" : "Сформировать по заявке"}
            </button>
          </div>
        </form>
      )}
      {ticketArtifacts.length > 0 && (
        <div className="ticket-artifacts">
          <h3>Сформированные отчёты по заявкам</h3>
          {ticketArtifacts.map((item) => (
            <article key={item.file_id}>
              <div>
                <b>{item.ticket_title}</b>
                <small>{item.name}</small>
              </div>
              <button onClick={() => void downloadTicketArtifact(item.file_id)}>
                Скачать PDF
              </button>
            </article>
          ))}
        </div>
      )}
      {role !== "worker" && (
        <>
          <div className="report-history-head">
            <h3>Полные аналитические отчёты</h3>
            <div className="service-filters compact">
              <label className="filter-search">
                Поиск
                <input
                  value={reportQuery}
                  onChange={(event) => setReportQuery(event.target.value)}
                  placeholder="Название, тип или ID"
                />
              </label>
              <label>
                Статус
                <select
                  value={statusFilter}
                  onChange={(event) => setStatusFilter(event.target.value)}
                >
                  <option value="">Все</option>
                  <option>PENDING</option>
                  <option>PROCESSING</option>
                  <option>COMPLETED</option>
                  <option>FAILED</option>
                  <option>CANCELED</option>
                </select>
              </label>
              <button
                onClick={() => {
                  setStatusFilter("");
                  setReportQuery("");
                }}
              >
                Сбросить
              </button>
            </div>
          </div>
          <div className="report-table">
            {visibleItems.map((item) => (
              <article key={item.id}>
                <div>
                  <b>{item.name}</b>
                  <small>
                    {String(item.type)} · {String(item.format)}
                  </small>
                </div>
                <em>{String(item.status)}</em>
                <div>
                  {item.status === "COMPLETED" && (
                    <button onClick={() => action(item, "download")}>
                      Скачать
                    </button>
                  )}
                  {item.status === "FAILED" && (
                    <button onClick={() => action(item, "retry")}>
                      Повторить
                    </button>
                  )}
                  {(item.status === "PENDING" || item.status === "FAILED") && (
                    <button onClick={() => action(item, "cancel")}>
                      Отменить
                    </button>
                  )}
                </div>
              </article>
            ))}
          </div>
        </>
      )}
    </section>
  );
}
