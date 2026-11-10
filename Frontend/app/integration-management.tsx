"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, config, type Session } from "./api";

type Department = { id: string; name: string };
type Integration = {
  id: string;
  name: string;
  client_id: string;
  secret_prefix: string;
  allowed_department_id?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_used_at?: string;
};

export function IntegrationManagement({
  session,
  departments,
  onNotice,
}: {
  session: Session;
  departments: Department[];
  onNotice: (text: string) => void;
}) {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [secret, setSecret] = useState("");
  const [busyID, setBusyID] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api<{ integrations: Integration[] }>(
        config.endpoints.ticketIntegrationsList,
        { limit: 100, offset: 0 },
        "POST",
        session.accessToken,
      );
      setIntegrations(result.integrations || []);
    } catch (error) {
      onNotice(
        error instanceof Error
          ? error.message
          : "Не удалось загрузить интеграции",
      );
    } finally {
      setLoading(false);
    }
  }, [onNotice, session.accessToken]);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => void load());
    return () => window.cancelAnimationFrame(frame);
  }, [load]);

  async function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget,
      data = new FormData(form);
    setBusyID("new");
    try {
      const result = await api<{ integration: Integration; secret: string }>(
        config.endpoints.ticketIntegrationsRegister,
        {
          name: String(data.get("name") || "").trim(),
          client_id: String(data.get("client_id") || "").trim(),
          allowed_department_id:
            String(data.get("allowed_department_id") || "") || undefined,
        },
        "POST",
        session.accessToken,
      );
      setSecret(result.secret);
      setIntegrations((current) => [result.integration, ...current]);
      setShowForm(false);
      form.reset();
      onNotice(`Интеграция «${result.integration.name}» зарегистрирована`);
    } catch (error) {
      onNotice(
        error instanceof Error
          ? error.message
          : "Не удалось зарегистрировать интеграцию",
      );
    } finally {
      setBusyID("");
    }
  }

  async function setActive(integration: Integration) {
    setBusyID(integration.id);
    try {
      const result = await api<{ integration: Integration }>(
        config.endpoints.ticketIntegrationsSetActive,
        { integration_id: integration.id, is_active: !integration.is_active },
        "POST",
        session.accessToken,
      );
      setIntegrations((current) =>
        current.map((item) =>
          item.id === integration.id ? result.integration : item,
        ),
      );
      onNotice(
        result.integration.is_active
          ? "Интеграция включена"
          : "Интеграция отключена",
      );
    } catch (error) {
      onNotice(
        error instanceof Error
          ? error.message
          : "Не удалось изменить статус интеграции",
      );
    } finally {
      setBusyID("");
    }
  }

  async function rotate(integration: Integration) {
    if (
      !window.confirm(
        `Выпустить новый секрет для «${integration.name}»? Старый секрет перестанет работать сразу.`,
      )
    )
      return;
    setBusyID(integration.id);
    try {
      const result = await api<{ integration: Integration; secret: string }>(
        config.endpoints.ticketIntegrationsRotateSecret,
        { integration_id: integration.id },
        "POST",
        session.accessToken,
      );
      setIntegrations((current) =>
        current.map((item) =>
          item.id === integration.id ? result.integration : item,
        ),
      );
      setSecret(result.secret);
      onNotice("Новый секрет выпущен. Скопируйте его сейчас.");
    } catch (error) {
      onNotice(
        error instanceof Error ? error.message : "Не удалось обновить секрет",
      );
    } finally {
      setBusyID("");
    }
  }

  async function copySecret() {
    await navigator.clipboard.writeText(secret);
    onNotice("Секрет скопирован");
  }

  return (
    <section className="integration-management">
      <div className="integration-toolbar">
        <div>
          <h3>Предприятия и порталы</h3>
          <p>
            API-клиенты, ограничения по департаментам и история использования.
          </p>
        </div>
        <button className="primary" onClick={() => setShowForm(true)}>
          + Зарегистрировать
        </button>
      </div>
      {secret && (
        <aside className="integration-secret" role="status">
          <div>
            <b>Секрет показан только один раз</b>
            <code>{secret}</code>
          </div>
          <button onClick={() => void copySecret()}>Копировать</button>
          <button
            className="detail-close"
            aria-label="Скрыть секрет"
            onClick={() => setSecret("")}
          >
            ×
          </button>
        </aside>
      )}
      {loading ? (
        <p>Загружаем интеграции…</p>
      ) : (
        <div className="manage-card-grid">
          {integrations.map((item) => (
            <article key={item.id}>
              <span
                className={`manage-state ${item.is_active ? "active" : "inactive"}`}
              >
                ● {item.is_active ? "Активна" : "Отключена"}
              </span>
              <h3>{item.name}</h3>
              <p>
                <code>{item.client_id}</code>
              </p>
              <dl>
                <div>
                  <dt>Префикс секрета</dt>
                  <dd>
                    <code>{item.secret_prefix}…</code>
                  </dd>
                </div>
                <div>
                  <dt>Департамент</dt>
                  <dd>
                    {departments.find(
                      (department) =>
                        department.id === item.allowed_department_id,
                    )?.name ||
                      item.allowed_department_id ||
                      "Все департаменты"}
                  </dd>
                </div>
                <div>
                  <dt>Последний запрос</dt>
                  <dd>
                    {item.last_used_at
                      ? new Date(item.last_used_at).toLocaleString("ru-RU")
                      : "Ещё не использовалась"}
                  </dd>
                </div>
              </dl>
              <div>
                <button
                  disabled={busyID === item.id}
                  onClick={() => void rotate(item)}
                >
                  Обновить секрет
                </button>
                <button
                  className={item.is_active ? "danger-action" : "primary"}
                  disabled={busyID === item.id}
                  onClick={() => void setActive(item)}
                >
                  {item.is_active ? "Отключить" : "Включить"}
                </button>
              </div>
            </article>
          ))}
          {!integrations.length && <p>Интеграции ещё не зарегистрированы.</p>}
        </div>
      )}
      {showForm && (
        <div
          className="management-modal"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setShowForm(false);
          }}
        >
          <form
            role="dialog"
            aria-modal="true"
            aria-label="Регистрация интеграции"
            onSubmit={register}
          >
            <button
              type="button"
              className="modal-close"
              onClick={() => setShowForm(false)}
            >
              ×
            </button>
            <span className="eyebrow">Внешний API</span>
            <h2>Новое предприятие или портал</h2>
            <label>
              Название
              <input name="name" required maxLength={255} />
            </label>
            <label>
              Client ID
              <input
                name="client_id"
                required
                minLength={3}
                maxLength={100}
                pattern="[A-Za-z0-9._:-]+"
                placeholder="mosvodokanal-portal"
              />
            </label>
            <label>
              Доступ к департаменту
              <select name="allowed_department_id">
                <option value="">Все департаменты</option>
                {departments.map((department) => (
                  <option key={department.id} value={department.id}>
                    {department.name}
                  </option>
                ))}
              </select>
            </label>
            <p>
              После регистрации секрет будет показан один раз. Сохраните его в
              защищённом хранилище предприятия.
            </p>
            <button className="primary" disabled={busyID === "new"}>
              {busyID === "new" ? "Регистрируем…" : "Зарегистрировать"}
            </button>
          </form>
        </div>
      )}
    </section>
  );
}
