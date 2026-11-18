"use client";

/* eslint-disable react-hooks/set-state-in-effect */

import { FormEvent, useCallback, useEffect, useState } from "react";

import { api, config, type Session, type Ticket } from "./api";

import {
  TicketLocationPicker,
  type TicketLocation,
} from "./ticket-location-picker";

import { type Notice, type Category, type Department } from "./service-shared";

export function CreateTicketPage({
  session,
  onCreated,
  onNotice,
}: {
  session: Session;
  onCreated: (ticket: Ticket) => void;
  onNotice: Notice;
}) {
  const demo = session.accessToken === "demo";
  const [categories, setCategories] = useState<Category[]>([]),
    [departments, setDepartments] = useState<Department[]>([]),
    [busy, setBusy] = useState(false),
    [catalogsLoading, setCatalogsLoading] = useState(!demo),
    [location, setLocation] = useState<TicketLocation>();
  const selectLocation = useCallback(
    (next: TicketLocation) => setLocation(next),
    [],
  );
  useEffect(() => {
    if (demo) {
      setCategories([{ id: "cat-demo", name: "Городская инфраструктура" }]);
      setDepartments([{ id: "dep-roads", name: "Дорожное хозяйство" }]);
      setCatalogsLoading(false);
      return;
    }
    setCatalogsLoading(true);
    Promise.all([
      api<{ categories: Category[] }>(
        config.endpoints.ticketCategoriesList,
        { limit: 100, offset: 0 },
        "POST",
        session.accessToken,
      ),
      api<{ departments: Department[] }>(
        config.endpoints.departmentsList,
        { limit: 100, offset: 0 },
        "POST",
        session.accessToken,
      ),
    ])
      .then(([c, d]) => {
        setCategories(c.categories || []);
        setDepartments(d.departments || []);
      })
      .catch((error) =>
        onNotice(
          error instanceof Error
            ? error.message
            : "Не удалось загрузить справочники",
        ),
      )
      .finally(() => setCatalogsLoading(false));
  }, [demo, onNotice, session.accessToken]);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!location) {
      onNotice("Выберите адрес из подсказок или укажите точку на карте");
      return;
    }
    const formElement = event.currentTarget,
      form = new FormData(formElement);
    setBusy(true);
    try {
      const draft = {
        id: `draft-${Date.now()}`,
        department_id: String(form.get("department_id")),
        category_id: String(form.get("category_id")),
        user_id: session.user?.user_id || "",
        title: String(form.get("title")),
        description: String(form.get("description")),
        status: "NEW",
        priority: String(form.get("priority")),
        address: location.address,
        latitude: location.latitude,
        longitude: location.longitude,
        created_at: Date.now() / 1000,
        updated_at: Date.now() / 1000,
      };
      let ticket = draft as Ticket;
      if (!demo) {
        const result = await api<{ ticket: Ticket }>(
          config.endpoints.ticketsCreate,
          draft,
          "POST",
          session.accessToken,
        );
        ticket = result.ticket;
      }
      onCreated(ticket);
      formElement.reset();
      setLocation(undefined);
      onNotice(`Заявка «${ticket.title}» создана`);
    } catch (error) {
      onNotice(
        error instanceof Error ? error.message : "Не удалось создать заявку",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="content-page service-form-page">
      <div className="page-toolbar">
        <div>
          <h2>Сообщить о проблеме</h2>
          <p>Новая заявка сразу попадёт в очередь выбранной городской службы</p>
        </div>
      </div>
      <form className="service-form" onSubmit={submit}>
        <div className="form-grid">
          <label>
            Департамент
            <select
              name="department_id"
              required
              disabled={catalogsLoading || departments.length === 0}
            >
              {departments.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Категория
            <select
              name="category_id"
              required
              disabled={catalogsLoading || categories.length === 0}
            >
              {categories.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
          <label className="wide">
            Заголовок
            <input name="title" required minLength={3} />
          </label>
          <label className="wide">
            Описание
            <textarea name="description" required rows={5} />
          </label>
          <TicketLocationPicker value={location} onChange={selectLocation} />
          <label>
            Приоритет
            <select name="priority" defaultValue="MEDIUM">
              <option value="LOW">Низкий</option>
              <option value="MEDIUM">Средний</option>
              <option value="HIGH">Высокий</option>
              <option value="EMERGENCY">Экстренный</option>
            </select>
          </label>
        </div>
        <button
          className="primary"
          disabled={
            busy ||
            catalogsLoading ||
            departments.length === 0 ||
            categories.length === 0
          }
        >
          {busy
            ? "Создаём…"
            : catalogsLoading
              ? "Загружаем справочники…"
              : "Создать заявку"}
        </button>
      </form>
    </section>
  );
}
