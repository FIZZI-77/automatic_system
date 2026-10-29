"use client";

/* eslint-disable react-hooks/set-state-in-effect */

import { FormEvent, useCallback, useEffect, useState } from "react";

import { api, config, Session } from "./api";

import { text, type Notice, Modal } from "./admin-shared";

type SLARule = {
  id: string;
  name: string;
  department_id?: string;
  category_id?: string;
  priority?: string | number;
  response_time_seconds: number;
  resolution_time_seconds: number;
  warning_percent: number;
  active: boolean;
  is_active?: boolean;
};

type Category = {
  id: string;
  code: string;
  name: string;
  description?: string;
  is_active: boolean;
};

type CatalogDepartment = { id: string; name: string };

function slaPriorityName(value: unknown) {
  if (typeof value === "number")
    return ["", "LOW", "MEDIUM", "HIGH", "EMERGENCY"][value] || "";
  const source = text(value, "").toUpperCase();
  return source.replace("TICKET_PRIORITY_", "").replace("PRIORITY_", "");
}

export function ServiceCatalogPage({
  session,
  onNotice,
}: {
  session: Session;
  onNotice: Notice;
}) {
  const demo = session.accessToken === "demo",
    [tab, setTab] = useState<"sla" | "categories">("sla"),
    [rules, setRules] = useState<SLARule[]>([]),
    [categories, setCategories] = useState<Category[]>([]),
    [departments, setDepartments] = useState<CatalogDepartment[]>([]),
    [editing, setEditing] = useState<SLARule | Category>(),
    [modal, setModal] = useState(false),
    [formActive, setFormActive] = useState(true);
  const [catalogFilters, setCatalogFilters] = useState({
    query: "",
    department_id: "",
    category_id: "",
    priority: "",
    active: "",
  });
  const load = useCallback(async () => {
    if (demo) {
      setRules([
        {
          id: "sla-demo-1",
          name: "Экстренное водоснабжение",
          priority: "EMERGENCY",
          response_time_seconds: 600,
          resolution_time_seconds: 7200,
          warning_percent: 70,
          active: true,
        },
        {
          id: "sla-demo-2",
          name: "Дорожные повреждения",
          priority: "HIGH",
          response_time_seconds: 1800,
          resolution_time_seconds: 14400,
          warning_percent: 80,
          active: true,
        },
        {
          id: "sla-demo-3",
          name: "Городское освещение",
          priority: "HIGH",
          response_time_seconds: 1200,
          resolution_time_seconds: 10800,
          warning_percent: 75,
          active: true,
        },
      ]);
      setCategories([
        {
          id: "cat-demo-1",
          code: "ROAD_DAMAGE",
          name: "Дорожное покрытие",
          description: "Ямы и повреждения полотна",
          is_active: true,
        },
        {
          id: "cat-demo-2",
          code: "STREET_LIGHT",
          name: "Уличное освещение",
          description: "Фонари, опоры и электропитание",
          is_active: true,
        },
        {
          id: "cat-demo-3",
          code: "WATER",
          name: "Водоснабжение",
          description: "Протечки и аварийные работы",
          is_active: true,
        },
      ]);
      setDepartments([
        { id: "dep-roads", name: "Дорожное хозяйство" },
        { id: "dep-utilities", name: "Городское хозяйство" },
      ]);
      return;
    }
    try {
      const rulePayload = {
          limit: 100,
          offset: 0,
          ...(catalogFilters.department_id
            ? { department_id: catalogFilters.department_id }
            : {}),
          ...(catalogFilters.category_id
            ? { category_id: catalogFilters.category_id }
            : {}),
          ...(catalogFilters.priority
            ? { priority: catalogFilters.priority }
            : {}),
          ...(catalogFilters.active
            ? { active: catalogFilters.active === "true" }
            : {}),
        },
        categoryPayload = {
          only_active: catalogFilters.active === "true",
          limit: 100,
          offset: 0,
        };
      const [r, c, d] = await Promise.all([
        api<{ rules: SLARule[] }>(
          config.endpoints.slaRulesList,
          rulePayload,
          "POST",
          session.accessToken,
        ),
        api<{ categories: Category[] }>(
          config.endpoints.ticketCategoriesList,
          categoryPayload,
          "POST",
          session.accessToken,
        ),
        api<{ departments: CatalogDepartment[] }>(
          config.endpoints.departmentsList,
          { limit: 100, offset: 0 },
          "POST",
          session.accessToken,
        ),
      ]);
      setRules(
        (r.rules || []).map((rule) => ({
          ...rule,
          priority: slaPriorityName(rule.priority),
          active:
            typeof rule.active === "boolean"
              ? rule.active
              : Boolean(rule.is_active),
        })),
      );
      setCategories(c.categories || []);
      setDepartments(d.departments || []);
    } catch (error) {
      onNotice(
        error instanceof Error
          ? error.message
          : "Не удалось загрузить справочники",
      );
    }
  }, [catalogFilters, demo, onNotice, session.accessToken]);
  useEffect(() => {
    void load();
  }, [load]);
  async function save(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const d = new FormData(e.currentTarget);
    if (tab === "sla") {
      const old = editing as SLARule | undefined,
        departmentId = String(d.get("department_id") || ""),
        categoryId = String(d.get("category_id") || ""),
        priority = String(d.get("priority") || ""),
        base = {
          name: String(d.get("name")),
          department_id: departmentId,
          category_id: categoryId,
          response_time_seconds: Number(d.get("response")) * 60,
          resolution_time_seconds: Number(d.get("resolution")) * 60,
          warning_percent: Number(d.get("warning")),
          ...(priority ? { priority } : {}),
        },
        payload = old ? { id: old.id, ...base, active: formActive } : base;
      if (!demo)
        await api(
          old
            ? config.endpoints.slaRulesUpdate
            : config.endpoints.slaRulesCreate,
          payload,
          "POST",
          session.accessToken,
        );
    } else {
      const old = editing as Category | undefined,
        payload = old
          ? {
              category_id: old.id,
              name: String(d.get("name")),
              description: String(d.get("description")),
              is_active: formActive,
            }
          : {
              code: String(d.get("code")),
              name: String(d.get("name")),
              description: String(d.get("description")),
            };
      if (!demo)
        await api(
          old
            ? config.endpoints.ticketCategoriesUpdate
            : config.endpoints.ticketCategoriesCreate,
          payload,
          "POST",
          session.accessToken,
        );
    }
    setModal(false);
    setEditing(undefined);
    await load();
    onNotice("Справочник обновлён");
  }
  async function remove() {
    if (!editing) return;
    if (!demo)
      await api(
        tab === "sla"
          ? config.endpoints.slaRulesDelete
          : config.endpoints.ticketCategoriesDelete,
        tab === "sla" ? { id: editing.id } : { category_id: editing.id },
        "POST",
        session.accessToken,
      );
    setModal(false);
    setEditing(undefined);
    await load();
    onNotice("Запись удалена");
  }
  const normalizedCatalogQuery = catalogFilters.query
    .trim()
    .toLocaleLowerCase("ru-RU");
  const matchesCatalogQuery = (values: unknown[]) =>
    !normalizedCatalogQuery ||
    values.some((value) =>
      String(value || "")
        .toLocaleLowerCase("ru-RU")
        .includes(normalizedCatalogQuery),
    );
  const visibleRules = (
      demo
        ? rules.filter(
            (rule) =>
              (!catalogFilters.department_id ||
                rule.department_id === catalogFilters.department_id) &&
              (!catalogFilters.category_id ||
                rule.category_id === catalogFilters.category_id) &&
              (!catalogFilters.priority ||
                rule.priority === catalogFilters.priority) &&
              (!catalogFilters.active ||
                rule.active === (catalogFilters.active === "true")),
          )
        : rules
    ).filter((rule) =>
      matchesCatalogQuery([
        rule.id,
        rule.name,
        rule.department_id,
        rule.category_id,
        departments.find((item) => item.id === rule.department_id)?.name,
        categories.find((item) => item.id === rule.category_id)?.name,
      ]),
    ),
    visibleCategories = categories.filter(
      (category) =>
        (!catalogFilters.active ||
          category.is_active === (catalogFilters.active === "true")) &&
        matchesCatalogQuery([
          category.id,
          category.code,
          category.name,
          category.description,
        ]),
    );
  return (
    <section className="ops-page">
      <div className="ops-head">
        <div>
          <span className="eyebrow">Настройки процессов</span>
          <h2>Регламенты и категории</h2>
          <p>Правила SLA и классификатор городских обращений.</p>
        </div>
        <button
          className="primary"
          onClick={() => {
            setEditing(undefined);
            setFormActive(true);
            setModal(true);
          }}
        >
          + Новая запись
        </button>
      </div>
      <div className="ops-tabs">
        <button
          className={tab === "sla" ? "active" : ""}
          onClick={() => setTab("sla")}
        >
          Правила SLA <b>{visibleRules.length}</b>
        </button>
        <button
          className={tab === "categories" ? "active" : ""}
          onClick={() => setTab("categories")}
        >
          Категории заявок <b>{visibleCategories.length}</b>
        </button>
      </div>
      <div className="service-filters">
        <label className="filter-search">
          Поиск
          <input
            value={catalogFilters.query}
            onChange={(e) =>
              setCatalogFilters((v) => ({ ...v, query: e.target.value }))
            }
            placeholder="UUID, название или код"
          />
        </label>
        {tab === "sla" && (
          <>
            <label>
              Департамент
              <select
                value={catalogFilters.department_id}
                onChange={(e) =>
                  setCatalogFilters((v) => ({
                    ...v,
                    department_id: e.target.value,
                  }))
                }
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
              <select
                value={catalogFilters.category_id}
                onChange={(e) =>
                  setCatalogFilters((v) => ({
                    ...v,
                    category_id: e.target.value,
                  }))
                }
              >
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
              <select
                value={catalogFilters.priority}
                onChange={(e) =>
                  setCatalogFilters((v) => ({ ...v, priority: e.target.value }))
                }
              >
                <option value="">Все</option>
                <option value="LOW">Низкий</option>
                <option value="MEDIUM">Средний</option>
                <option value="HIGH">Высокий</option>
                <option value="EMERGENCY">Экстренный</option>
              </select>
            </label>
          </>
        )}
        <label>
          Активность
          <select
            value={catalogFilters.active}
            onChange={(e) =>
              setCatalogFilters((v) => ({ ...v, active: e.target.value }))
            }
          >
            <option value="">Все</option>
            <option value="true">Активные</option>
            <option value="false">Неактивные</option>
          </select>
        </label>
        <button
          onClick={() =>
            setCatalogFilters({
              query: "",
              department_id: "",
              category_id: "",
              priority: "",
              active: "",
            })
          }
        >
          Сбросить
        </button>
      </div>
      <div className="catalog-list">
        {tab === "sla"
          ? visibleRules.map((rule) => (
              <button
                key={rule.id}
                onClick={() => {
                  setEditing(rule);
                  setFormActive(Boolean(rule.active));
                  setModal(true);
                }}
              >
                <span
                  className={`ops-state ${rule.active ? "active" : "inactive"}`}
                >
                  ● {rule.active ? "Активен" : "Выключен"}
                </span>
                <h3>{rule.name}</h3>
                <p>
                  {{
                    LOW: "Низкий",
                    MEDIUM: "Средний",
                    HIGH: "Высокий",
                    EMERGENCY: "Экстренный",
                  }[slaPriorityName(rule.priority)] || "Все приоритеты"}
                </p>
                <small>
                  {departments.find((item) => item.id === rule.department_id)
                    ?.name || "Все департаменты"}{" "}
                  ·{" "}
                  {categories.find((item) => item.id === rule.category_id)
                    ?.name || "Все категории"}
                </small>
                <div>
                  <b>
                    Реакция {Math.round(rule.response_time_seconds / 60)} мин
                  </b>
                  <b>
                    Решение {Math.round(rule.resolution_time_seconds / 60)} мин
                  </b>
                  <span>Предупреждение {rule.warning_percent}%</span>
                </div>
              </button>
            ))
          : visibleCategories.map((category) => (
              <button
                key={category.id}
                onClick={() => {
                  setEditing(category);
                  setFormActive(Boolean(category.is_active));
                  setModal(true);
                }}
              >
                <span
                  className={`ops-state ${category.is_active ? "active" : "inactive"}`}
                >
                  ● {category.is_active ? "Активна" : "Выключена"}
                </span>
                <h3>{category.name}</h3>
                <p>{category.code}</p>
                <small>{category.description || "Без описания"}</small>
              </button>
            ))}
      </div>
      {modal && (
        <Modal
          className="catalog-rule-modal"
          title={editing ? "Изменить запись" : "Создать запись"}
          onClose={() => {
            setModal(false);
            setEditing(undefined);
          }}
        >
          <form
            key={`${tab}-${editing?.id || "new"}`}
            className="ops-form"
            onSubmit={save}
          >
            {tab === "sla" ? (
              <>
                <label>
                  Название
                  <input
                    name="name"
                    defaultValue={(editing as SLARule)?.name}
                    required
                  />
                </label>
                <div>
                  <label>
                    Департамент
                    <select
                      name="department_id"
                      defaultValue={(editing as SLARule)?.department_id || ""}
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
                    Категория заявки
                    <select
                      name="category_id"
                      defaultValue={(editing as SLARule)?.category_id || ""}
                    >
                      <option value="">Все категории</option>
                      {categories.map((item) => (
                        <option key={item.id} value={item.id}>
                          {item.name}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
                <label>
                  Приоритет
                  <select
                    name="priority"
                    defaultValue={
                      slaPriorityName((editing as SLARule)?.priority) || ""
                    }
                  >
                    <option value="">Любой приоритет</option>
                    <option value="LOW">Низкий</option>
                    <option value="MEDIUM">Средний</option>
                    <option value="HIGH">Высокий</option>
                    <option value="EMERGENCY">Экстренный</option>
                  </select>
                </label>
                <div>
                  <label>
                    Срок реакции, мин
                    <input
                      name="response"
                      type="number"
                      min="1"
                      defaultValue={Math.max(
                        1,
                        Math.round(
                          ((editing as SLARule)?.response_time_seconds ||
                            1800) / 60,
                        ),
                      )}
                      required
                    />
                  </label>
                  <label>
                    Срок выполнения, мин
                    <input
                      name="resolution"
                      type="number"
                      min="1"
                      defaultValue={Math.max(
                        1,
                        Math.round(
                          ((editing as SLARule)?.resolution_time_seconds ||
                            14400) / 60,
                        ),
                      )}
                      required
                    />
                  </label>
                </div>
                <label>
                  Когда предупредить, % срока
                  <input
                    name="warning"
                    type="number"
                    min="1"
                    max="99"
                    defaultValue={(editing as SLARule)?.warning_percent || 80}
                  />
                </label>
                {editing && (
                  <label className="check regulation-active">
                    <input
                      aria-label="Регламент активен"
                      name="active"
                      type="checkbox"
                      checked={formActive}
                      onChange={(event) => setFormActive(event.target.checked)}
                    />
                    <span>
                      <b>
                        {formActive
                          ? "Регламент активен"
                          : "Регламент выключен"}
                      </b>
                      <small>
                        {formActive
                          ? "Применяется к новым заявкам"
                          : "Не используется при расчёте SLA"}
                      </small>
                    </span>
                  </label>
                )}
              </>
            ) : (
              <>
                <label>
                  Код
                  <input
                    name="code"
                    defaultValue={(editing as Category)?.code}
                    disabled={Boolean(editing)}
                    required
                  />
                </label>
                <label>
                  Название
                  <input
                    name="name"
                    defaultValue={(editing as Category)?.name}
                    required
                  />
                </label>
                <label>
                  Описание
                  <textarea
                    name="description"
                    rows={4}
                    defaultValue={(editing as Category)?.description}
                  />
                </label>
                {editing && (
                  <label className="check regulation-active">
                    <input
                      aria-label="Категория активна"
                      name="active"
                      type="checkbox"
                      checked={formActive}
                      onChange={(event) => setFormActive(event.target.checked)}
                    />
                    <span>
                      <b>
                        {formActive
                          ? "Категория активна"
                          : "Категория выключена"}
                      </b>
                      <small>
                        {formActive
                          ? "Доступна при создании заявок"
                          : "Скрыта из списка новых заявок"}
                      </small>
                    </span>
                  </label>
                )}
              </>
            )}
            <div className="modal-buttons">
              {editing && (
                <button
                  type="button"
                  className="danger-action"
                  onClick={() => void remove()}
                >
                  Удалить
                </button>
              )}
              <button className="primary">Сохранить</button>
            </div>
          </form>
        </Modal>
      )}
    </section>
  );
}
