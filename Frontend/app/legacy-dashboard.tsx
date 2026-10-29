"use client";

/* eslint-disable jsx-a11y/anchor-is-valid */

import { useEffect, useState } from "react";

import { api, config, Position, Role, Session, Ticket } from "./api";

import { CityMap } from "./city-map";

import { defaultBrigades } from "./brigade-store";

import { demoTickets, demoVehicles } from "./city-demo-data";

import { navByRole, roleNames, statusNames } from "./city-shared";

import { VehicleGroups } from "./vehicle-groups";

export function LegacyDashboard({
  session,
  role,
  setDemoRole,
  onExit,
}: {
  session: Session;
  role: Role;
  setDemoRole: (r: Role) => void;
  onExit: () => void;
}) {
  const [section, setSection] = useState("overview");
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [vehicles, setVehicles] = useState<Position[]>([]);
  const [selected, setSelected] = useState<string>();
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState("");
  const demo = session.accessToken === "demo";
  const [renderedAt] = useState(() => Date.now() / 1000);
  useEffect(() => {
    let active = true;
    (async () => {
      try {
        if (demo) {
          setTickets(demoTickets);
          setVehicles(demoVehicles);
          return;
        }
        const result = await api<{ tickets: Ticket[] }>(
          config.endpoints.ticketsList,
          { limit: 100, offset: 0, sort_by: "created_at", sort_order: "desc" },
          "POST",
          session.accessToken,
        );
        if (active) setTickets(result.tickets || []);
      } catch (e) {
        if (active)
          setNotice(e instanceof Error ? e.message : "Ошибка загрузки");
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [demo, session.accessToken]);
  const activeTickets = tickets.filter(
    (t) => !["DONE", "CANCELED"].includes(t.status),
  );
  const selectedTicket =
    tickets.find((t) => t.id === selected) || activeTickets[0];
  const title =
    role === "dispatcher"
      ? "Ситуационный центр"
      : role === "worker"
        ? "Рабочая смена"
        : role === "admin"
          ? "Управление городом"
          : "Добрый день";
  return (
    <div className="app-shell">
      <aside>
        <a className="brand inverse" href="#">
          <span>Г</span>
          <b>
            Город
            <br />
            рядом
          </b>
        </a>
        <nav>
          {navByRole[role].map((item) => (
            <button
              key={item.id}
              className={section === item.id ? "active" : ""}
              onClick={() => setSection(item.id)}
            >
              <i>{item.icon}</i>
              <span>{item.label}</span>
            </button>
          ))}
        </nav>
        <div className="aside-bottom">
          <button>
            <i>?</i>
            <span>Поддержка</span>
          </button>
          <button onClick={onExit}>
            <i>↗</i>
            <span>Выйти</span>
          </button>
        </div>
      </aside>
      <main className="workspace">
        <header>
          <div>
            <small>{roleNames[role]} · Москва</small>
            <h1>{title}</h1>
          </div>
          <div className="header-actions">
            <button className="icon-btn" aria-label="Поиск">
              ⌕
            </button>
            <button className="icon-btn" aria-label="Уведомления">
              ◌
            </button>
            <div className="avatar">
              {session.user?.email?.slice(0, 2).toUpperCase() || "ГР"}
            </div>
          </div>
        </header>
        {demo && (
          <div className="demo-bar">
            <span>Демонстрационный режим</span>
            <div>
              {(["user", "worker", "dispatcher", "admin"] as Role[]).map(
                (r) => (
                  <button
                    className={r === role ? "active" : ""}
                    onClick={() => setDemoRole(r)}
                    key={r}
                  >
                    {roleNames[r]}
                  </button>
                ),
              )}
            </div>
          </div>
        )}
        {notice && (
          <div className="notice">
            {notice}
            <button onClick={() => setNotice("")}>×</button>
          </div>
        )}
        <section className="kpis">
          <article>
            <span>Активные заявки</span>
            <b>{activeTickets.length}</b>
            <small className="up">↑ 8% за сегодня</small>
          </article>
          <article>
            <span>Бригады на линии</span>
            <b>
              {vehicles.length || 11}
              <em> / 14</em>
            </b>
            <small>3 свободны</small>
          </article>
          <article>
            <span>Среднее время реакции</span>
            <b>
              18 <em>мин</em>
            </b>
            <small className="up">↓ 4 мин к среднему</small>
          </article>
          <article>
            <span>В рамках SLA</span>
            <b>
              94<em>%</em>
            </b>
            <small>2 требуют внимания</small>
          </article>
        </section>
        <section className="dashboard-grid">
          <div className="map-card">
            <div className="card-head">
              <div>
                <h2>
                  {section === "tickets" ? "Инциденты" : "Оперативная карта"}
                </h2>
                <p>Заявки, маршруты и городские бригады</p>
              </div>
              <div className="segmented">
                <button className="active">Все</button>
                <button>Заявки</button>
                <button>Бригады</button>
              </div>
            </div>
            <CityMap
              tickets={activeTickets}
              vehicles={vehicles}
              brigades={defaultBrigades}
              selected={selected}
              onSelect={setSelected}
            />
          </div>
          <div className="feed-card">
            <div className="card-head">
              <div>
                <h2>Требуют внимания</h2>
                <p>
                  {activeTickets.length} инцидентов · {vehicles.length} машин
                </p>
              </div>
              <button className="link" onClick={() => setSection("tickets")}>
                Все →
              </button>
            </div>
            <div className="ticket-list">
              {loading ? (
                <p>Загружаем данные…</p>
              ) : (
                activeTickets.slice(0, 4).map((t) => (
                  <button
                    key={t.id}
                    className={selected === t.id ? "selected" : ""}
                    onClick={() => setSelected(t.id)}
                  >
                    <span className={`priority ${t.priority.toLowerCase()}`} />
                    <div>
                      <b>{t.title}</b>
                      <small>{t.address}</small>
                      <div>
                        <em className={`status ${t.status.toLowerCase()}`}>
                          {statusNames[t.status] || t.status}
                        </em>
                        <time>
                          {Math.max(
                            1,
                            Math.round((renderedAt - t.created_at) / 60),
                          )}{" "}
                          мин назад
                        </time>
                      </div>
                    </div>
                  </button>
                ))
              )}
            </div>
            <VehicleGroups
              vehicles={vehicles}
              brigades={defaultBrigades}
              tickets={activeTickets}
              selected={selected}
              onSelect={setSelected}
            />
            {selectedTicket && (
              <div className="quick-action">
                <div>
                  <span>Выбрана заявка</span>
                  <b>{selectedTicket.title}</b>
                </div>
                <button
                  onClick={() =>
                    setNotice(
                      demo
                        ? "В демо действия не отправляются"
                        : "Команда подготовлена",
                    )
                  }
                >
                  {role === "dispatcher"
                    ? "Назначить бригаду"
                    : role === "worker"
                      ? "Начать работу"
                      : "Открыть"}
                </button>
              </div>
            )}
          </div>
        </section>
        <section className="bottom-grid">
          <div className="activity">
            <div className="card-head">
              <div>
                <h2>Последние события</h2>
                <p>Обновления в реальном времени</p>
              </div>
              <span className="live">● LIVE</span>
            </div>
            <ul>
              <li>
                <i className="mint">✓</i>
                <div>
                  <b>Бригада №14 приняла заявку</b>
                  <small>Повреждение водопровода · 3 мин назад</small>
                </div>
              </li>
              <li>
                <i className="peach">⌖</i>
                <div>
                  <b>Построен новый маршрут</b>
                  <small>Расчётное прибытие через 12 минут</small>
                </div>
              </li>
              <li>
                <i className="lilac">◌</i>
                <div>
                  <b>Получена новая заявка</b>
                  <small>Не работает освещение · 8 мин назад</small>
                </div>
              </li>
            </ul>
          </div>
          <div className="sla-card">
            <div className="card-head">
              <div>
                <h2>Исполнение SLA</h2>
                <p>За текущие сутки</p>
              </div>
              <button className="link">Подробнее →</button>
            </div>
            <div className="ring">
              <div>
                <b>94%</b>
                <span>в срок</span>
              </div>
            </div>
            <div className="sla-legend">
              <span>
                <i className="ok" />
                Выполнено <b>46</b>
              </span>
              <span>
                <i className="warn" />
                Под риском <b>3</b>
              </span>
              <span>
                <i className="bad" />
                Нарушено <b>1</b>
              </span>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
