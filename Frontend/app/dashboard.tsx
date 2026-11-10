"use client";

/* eslint-disable jsx-a11y/anchor-is-valid, jsx-a11y/no-autofocus, jsx-a11y/label-has-associated-control */

import { useEffect, useRef, useState } from "react";

import { type Theme } from "./use-theme";

import { api, config, Position, Role, Session, Ticket } from "./api";

import { CityMap } from "./city-map";

import { BrigadeZones, type BrigadeZoneRecord } from "./brigade-zones";

import { ManagementPage } from "./management-page";

import {
  defaultBrigades,
  publishBrigades,
  type BrigadeRecord,
} from "./brigade-store";

import {
  roleNames,
  pageTitles,
  hasFreshPosition,
  operationalStatuses,
  navByRole,
  managementNavigation,
  extraNavigation,
  pluralRu,
} from "./city-shared";

import { demoTickets, demoVehicles } from "./city-demo-data";

import { TicketCards } from "./ticket-cards";

import { VehicleGroups } from "./vehicle-groups";

import { SectionPage } from "./section-page";

export function DashboardV2({
  theme,
  onToggleTheme,
  session,
  role,
  setDemoRole,
  onExit,
}: {
  theme: Theme;
  onToggleTheme: () => void;
  session: Session;
  role: Role;
  setDemoRole: (r: Role) => void;
  onExit: () => void;
}) {
  const toggleTheme = onToggleTheme;
  const [section, setSection] = useState("overview");
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [accountName, setAccountName] = useState(
    session.accessToken === "demo"
      ? `Демо: ${roleNames[role]}`
      : session.user?.email?.split("@")[0] || "Профиль",
  );
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const demoTicketsLoaded = useRef(false);
  const [vehicles, setVehicles] = useState<Position[]>([]);
  const [loadedBrigades, setLoadedBrigades] = useState<BrigadeRecord[]>([]);
  const [selected, setSelected] = useState<string>();
  const [notice, setNotice] = useState("");
  const [zones, setZones] = useState<BrigadeZoneRecord[]>([]);
  const [dispatcherDepartmentId, setDispatcherDepartmentId] = useState(
    role === "dispatcher"
      ? session.user?.department_id ||
          (session.accessToken === "demo" ? "dep-roads" : "")
      : "",
  );
  const [overviewMetrics, setOverviewMetrics] = useState<{
    avg_response_seconds: number;
  } | null>(null);
  const [slaMetrics, setSlaMetrics] = useState<{
    breach_rate: number;
    response_warnings: number;
    resolution_warnings: number;
  } | null>(null);
  const demo = session.accessToken === "demo";
  useEffect(() => {
    const requestedSection = new URLSearchParams(window.location.search).get(
      "section",
    );
    if (requestedSection && pageTitles[requestedSection]) {
      const update = window.setTimeout(() => setSection(requestedSection), 0);
      return () => window.clearTimeout(update);
    }
  }, []);
  useEffect(() => {
    if (demo) return;
    let active = true;
    api<{ user_profile?: { full_name?: string } }>(
      config.endpoints.profile,
      undefined,
      "GET",
      session.accessToken,
    )
      .then((result) => {
        if (active && result.user_profile?.full_name)
          setAccountName(result.user_profile.full_name);
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [demo, session.accessToken]);
  useEffect(() => {
    let active = true;
    (async () => {
      try {
        let departmentId = "";
        if (role === "dispatcher") {
          if (demo) departmentId = "dep-roads";
          else if (session.user?.department_id)
            departmentId = session.user.department_id;
          else {
            const resolved = await api<{
              department_id: string;
              can_operate: boolean;
            }>(
              config.endpoints.workingDepartment,
              { user_id: session.user?.user_id },
              "POST",
              session.accessToken,
            );
            if (!resolved.can_operate || !resolved.department_id)
              throw new Error(
                "У диспетчера нет активного рабочего департамента",
              );
            departmentId = resolved.department_id;
          }
        }
        if (active) setDispatcherDepartmentId(departmentId);
        if (demo) {
          const demoBrigades = departmentId
            ? defaultBrigades.filter(
                (item) => item.department_id === departmentId,
              )
            : defaultBrigades;
          const brigadeIds = new Set(demoBrigades.map((item) => item.id));
          if (active) {
            publishBrigades(demoBrigades);
            setLoadedBrigades(demoBrigades);
            if (!demoTicketsLoaded.current) {
              setTickets(demoTickets);
              demoTicketsLoaded.current = true;
            }
            setVehicles(
              departmentId
                ? demoVehicles.filter((item) => brigadeIds.has(item.brigade_id))
                : demoVehicles,
            );
            setOverviewMetrics({ avg_response_seconds: 1080 });
            setSlaMetrics({
              breach_rate: 6,
              response_warnings: 2,
              resolution_warnings: 0,
            });
          }
          return;
        }
        if (role === "user") {
          const ticketResult = await api<{ tickets: Ticket[] }>(
            config.endpoints.ticketsList,
            {
              limit: 100,
              offset: 0,
              sort_by: "created_at",
              sort_order: "desc",
            },
            "POST",
            session.accessToken,
          );
          if (active) {
            publishBrigades([]);
            setLoadedBrigades([]);
            setTickets(ticketResult.tickets || []);
            setVehicles([]);
            setZones([]);
            setOverviewMetrics(null);
            setSlaMetrics(null);
          }
          return;
        }
        if (role === "worker") {
          const [ticketResult, brigadeResult] = await Promise.all([
            api<{ tickets: Ticket[] }>(
              config.endpoints.ticketsList,
              {
                limit: 100,
                offset: 0,
                sort_by: "created_at",
                sort_order: "desc",
              },
              "POST",
              session.accessToken,
            ),
            api<{ brigade: BrigadeRecord }>(
              config.endpoints.brigadeByUser,
              { user_id: session.user?.user_id, only_active: true },
              "POST",
              session.accessToken,
            ).catch(() => undefined),
          ]);
          const ownBrigades = brigadeResult?.brigade
            ? [brigadeResult.brigade]
            : [];
          let ownVehicles: Position[] = [];
          if (brigadeResult?.brigade) {
            const brigadeId = brigadeResult.brigade.id,
              historyTo = new Date(),
              historyFrom = new Date(
                historyTo.getTime() - 7 * 24 * 60 * 60 * 1000,
              );
            const [currentResult, historyResult] = await Promise.all([
              api<{ locations: Record<string, { position?: Position }> }>(
                config.endpoints.locationsBatch,
                { brigade_ids: [brigadeId], allow_stale: true },
                "POST",
                session.accessToken,
              ).catch(
                (): { locations: Record<string, { position?: Position }> } => ({
                  locations: {},
                }),
              ),
              api<{ positions: Position[] }>(
                config.endpoints.locationsHistory,
                {
                  brigade_id: brigadeId,
                  from: historyFrom.toISOString(),
                  to: historyTo.toISOString(),
                  limit: 1000,
                  offset: 0,
                  order: "desc",
                },
                "POST",
                session.accessToken,
              ).catch(() => ({ positions: [] })),
            ]);
            const latestByVehicle = new Map<string, Position>();
            [
              ...Object.values(currentResult.locations || {}).flatMap((item) =>
                item.position ? [item.position] : [],
              ),
              ...(historyResult.positions || []),
            ].forEach((position) => {
              const previous = latestByVehicle.get(position.vehicle_id);
              if (
                !previous ||
                Number(position.recorded_at) >= Number(previous.recorded_at)
              )
                latestByVehicle.set(position.vehicle_id, position);
            });
            ownVehicles = Array.from(latestByVehicle.values());
          }
          const workerTickets = ticketResult.tickets || [];
          const responseTimes = workerTickets
            .filter(
              (ticket) =>
                ticket.brigade_id === brigadeResult?.brigade?.id &&
                Number(ticket.assigned_at) > Number(ticket.created_at),
            )
            .map(
              (ticket) =>
                Number(ticket.assigned_at) - Number(ticket.created_at),
            );
          const avgResponseSeconds = responseTimes.length
            ? responseTimes.reduce((sum, value) => sum + value, 0) /
              responseTimes.length
            : 0;
          if (active) {
            publishBrigades(ownBrigades);
            setLoadedBrigades(ownBrigades);
            setTickets(workerTickets);
            setVehicles(ownVehicles);
            setZones([]);
            setOverviewMetrics({ avg_response_seconds: avgResponseSeconds });
            setSlaMetrics(null);
          }
          return;
        }
        const departmentFilter = departmentId
          ? { department_id: departmentId }
          : {};
        const [ticketResult, brigadeResult, analyticsResult, slaResult] =
          await Promise.all([
            api<{ tickets: Ticket[] }>(
              config.endpoints.ticketsList,
              {
                limit: 100,
                offset: 0,
                sort_by: "created_at",
                sort_order: "desc",
                ...departmentFilter,
              },
              "POST",
              session.accessToken,
            ),
            api<{ brigades: BrigadeRecord[] }>(
              config.endpoints.brigadesList,
              { limit: 100, offset: 0, ...departmentFilter },
              "POST",
              session.accessToken,
            ).catch(() => ({ brigades: [] })),
            api<{ avg_response_seconds: number }>(
              config.endpoints.analyticsOverview,
              { filter: departmentFilter },
              "POST",
              session.accessToken,
            ).catch(() => null),
            api<{
              breach_rate: number;
              response_warnings: number;
              resolution_warnings: number;
            }>(
              config.endpoints.analyticsSlaSummary,
              { filter: departmentFilter },
              "POST",
              session.accessToken,
            ).catch(() => null),
          ]);
        const brigades = (brigadeResult.brigades || []).filter(
          (item) => !departmentId || item.department_id === departmentId,
        );
        let positions: Position[] = [];
        if (brigades.length) {
          const historyTo = new Date(),
            historyFrom = new Date(
              historyTo.getTime() - 7 * 24 * 60 * 60 * 1000,
            );
          const [locationResult, historyResults] = await Promise.all([
            api<{ locations: Record<string, { position?: Position }> }>(
              config.endpoints.locationsBatch,
              {
                brigade_ids: brigades.map((item) => item.id),
                allow_stale: true,
              },
              "POST",
              session.accessToken,
            ).catch(
              (): { locations: Record<string, { position?: Position }> } => ({
                locations: {},
              }),
            ),
            Promise.all(
              brigades.map(async (brigade) => {
                try {
                  const result = await api<{ positions: Position[] }>(
                    config.endpoints.locationsHistory,
                    {
                      brigade_id: brigade.id,
                      from: historyFrom.toISOString(),
                      to: historyTo.toISOString(),
                      limit: 1000,
                      offset: 0,
                      order: "desc",
                    },
                    "POST",
                    session.accessToken,
                  );
                  return result.positions || [];
                } catch {
                  return [];
                }
              }),
            ),
          ]);
          const latestByVehicle = new Map<string, Position>();
          [
            ...Object.values(locationResult.locations || {}).flatMap((item) =>
              item.position ? [item.position] : [],
            ),
            ...historyResults.flat(),
          ].forEach((position) => {
            const previous = latestByVehicle.get(position.vehicle_id);
            if (
              !previous ||
              Number(position.recorded_at) >= Number(previous.recorded_at)
            )
              latestByVehicle.set(position.vehicle_id, position);
          });
          positions = Array.from(latestByVehicle.values());
        }
        const zoneResults = await Promise.all(
          brigades.map(async (brigade) => {
            try {
              const result = await api<{
                zones: Array<{
                  id: string;
                  brigade_id: string;
                  name: string;
                  priority: number;
                  geo_json: string;
                }>;
              }>(
                config.endpoints.brigadeZonesList,
                { brigade_id: brigade.id, active: true },
                "POST",
                session.accessToken,
              );
              return result.zones || [];
            } catch {
              return [];
            }
          }),
        );
        const loadedZones = zoneResults.flat().flatMap((zone) => {
          try {
            const geometry = JSON.parse(zone.geo_json),
              ring = geometry.coordinates?.[0] || [];
            return [
              {
                id: zone.id,
                brigade_id: zone.brigade_id,
                name: zone.name,
                priority: zone.priority,
                points: ring
                  .slice(0, -1)
                  .map(
                    ([lon, lat]: [number, number]) =>
                      [lat, lon] as [number, number],
                  ),
              },
            ];
          } catch {
            return [];
          }
        });
        if (active) {
          publishBrigades(brigades);
          setLoadedBrigades(brigades);
          setTickets(
            (ticketResult.tickets || []).filter(
              (item) => !departmentId || item.department_id === departmentId,
            ),
          );
          setVehicles(positions);
          setZones(loadedZones);
          setOverviewMetrics(analyticsResult);
          setSlaMetrics(slaResult);
        }
      } catch (error) {
        if (active)
          setNotice(error instanceof Error ? error.message : "Ошибка загрузки");
      }
    })();
    return () => {
      active = false;
    };
  }, [
    demo,
    role,
    session.accessToken,
    session.user?.department_id,
    session.user?.user_id,
  ]);
  useEffect(() => {
    if (
      demo ||
      section !== "tickets" ||
      (role === "dispatcher" && !dispatcherDepartmentId)
    )
      return;
    let active = true;
    const departmentFilter =
      role === "dispatcher" ? { department_id: dispatcherDepartmentId } : {};
    void api<{ tickets: Ticket[] }>(
      config.endpoints.ticketsList,
      {
        limit: 100,
        offset: 0,
        sort_by: "created_at",
        sort_order: "desc",
        ...departmentFilter,
      },
      "POST",
      session.accessToken,
    )
      .then((result) => {
        if (active) setTickets(result.tickets || []);
      })
      .catch((error) => {
        if (active)
          setNotice(
            error instanceof Error
              ? error.message
              : "Не удалось обновить заявки",
          );
      });
    return () => {
      active = false;
    };
  }, [demo, dispatcherDepartmentId, role, section, session.accessToken]);
  useEffect(() => {
    if (demo) return;
    const separator = config.wsUrl.includes("?") ? "&" : "?";
    const socket = new WebSocket(
      `${config.wsUrl}${separator}access_token=${encodeURIComponent(session.accessToken)}`,
    );
    socket.onmessage = (event) => {
      try {
        const incoming = JSON.parse(event.data) as {
          title?: string;
          body?: string;
          message?: string;
        };
        const message = [incoming.title, incoming.body || incoming.message]
          .filter(Boolean)
          .join(": ");
        setNotice(message || "Получено новое уведомление");
      } catch {
        setNotice("Получено новое уведомление");
      }
    };
    return () => socket.close();
  }, [demo, session.accessToken]);
  useEffect(() => {
    if (!notice) return;
    const timeout = window.setTimeout(() => setNotice(""), 7000);
    return () => window.clearTimeout(timeout);
  }, [notice]);
  const visibleTickets =
    demo && role === "dispatcher"
      ? tickets.filter(
          (ticket) => ticket.department_id === dispatcherDepartmentId,
        )
      : tickets;
  const activeTickets = visibleTickets.filter(
    (ticket) => !["DONE", "CANCELED"].includes(ticket.status),
  );
  // Location API is already scoped to the brigades visible to the current user.
  // Keep last known positions on the map even when a brigade is offline or inactive.
  const mapVehicles = vehicles;
  const onlineVehicles = mapVehicles.filter(hasFreshPosition);
  const activeBrigades = loadedBrigades.filter((brigade) =>
    operationalStatuses.has(brigade.status),
  );
  const scopedSession: Session =
    dispatcherDepartmentId && session.user
      ? {
          ...session,
          user: { ...session.user, department_id: dispatcherDepartmentId },
        }
      : session;
  const navigation = [
    ...navByRole[role],
    ...(role === "dispatcher" ? [managementNavigation] : []),
    ...(["dispatcher", "admin"].includes(role) ? [extraNavigation] : []),
  ];
  const normalizedSearch = searchQuery.trim().toLocaleLowerCase("ru-RU");
  const searchTickets = normalizedSearch
    ? visibleTickets
        .filter((ticket) =>
          [ticket.id, ticket.title, ticket.address].some((value) =>
            value.toLocaleLowerCase("ru-RU").includes(normalizedSearch),
          ),
        )
        .slice(0, 6)
    : [];
  const searchSections = normalizedSearch
    ? navigation
        .filter((item) =>
          item.label.toLocaleLowerCase("ru-RU").includes(normalizedSearch),
        )
        .slice(0, 5)
    : [];
  const displayAccountName = demo ? `Демо: ${roleNames[role]}` : accountName;
  const accountInitials =
    displayAccountName
      .split(/[\s._-]+/)
      .filter(Boolean)
      .map((part) => part[0])
      .join("")
      .slice(0, 2)
      .toLocaleUpperCase("ru-RU") || "П";
  const pageTitle =
    section === "overview"
      ? navByRole[role][0].label
      : pageTitles[section] || "Городские сервисы";
  return (
    <div className={`app-shell theme-${theme}`} data-theme={theme}>
      <aside>
        <a className="brand inverse" href="#">
          <span>Г</span>
        </a>
        <nav>
          {navigation.map((item) => (
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
          <button onClick={onExit}>
            <i>↗</i>
            <span>Выйти</span>
          </button>
        </div>
      </aside>
      <main className={`workspace section-${section}`}>
        <header>
          <div>
            <small>{roleNames[role]} · Москва</small>
            <h1>{pageTitle}</h1>
          </div>
          <div className="header-actions">
            <button
              className="theme-toggle"
              aria-label={
                theme === "light"
                  ? "Включить тёмную тему"
                  : "Включить светлую тему"
              }
              title={theme === "light" ? "Тёмная тема" : "Светлая тема"}
              onClick={toggleTheme}
            >
              <span aria-hidden="true">{theme === "light" ? "◐" : "☀"}</span>
              <b>{theme === "light" ? "Тёмная" : "Светлая"}</b>
            </button>
            <button
              className="header-action"
              aria-label="Открыть поиск"
              onClick={() => setSearchOpen(true)}
            >
              <svg aria-hidden="true" viewBox="0 0 24 24">
                <circle cx="11" cy="11" r="6" />
                <path d="m16 16 4 4" />
              </svg>
              <b>Поиск</b>
            </button>
            <button
              className="header-action"
              aria-label="Открыть уведомления"
              onClick={() => setSection("notifications")}
            >
              <svg aria-hidden="true" viewBox="0 0 24 24">
                <path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9" />
                <path d="M10 21h4" />
              </svg>
              <b>Уведомления</b>
            </button>
            <button
              className="account-button"
              aria-label="Открыть профиль"
              onClick={() => setSection("profile")}
            >
              <span className="avatar">{accountInitials}</span>
              <span>
                <b>{displayAccountName}</b>
                <small>{roleNames[role]}</small>
              </span>
            </button>
          </div>
        </header>
        {searchOpen && (
          <div
            className="header-search-backdrop"
            role="presentation"
            onMouseDown={(event) => {
              if (event.target === event.currentTarget) setSearchOpen(false);
            }}
          >
            <section
              className="header-search-dialog"
              role="dialog"
              aria-modal="true"
              aria-label="Поиск по системе"
            >
              <button
                className="modal-close"
                aria-label="Закрыть поиск"
                onClick={() => setSearchOpen(false)}
              >
                ×
              </button>
              <span className="eyebrow">Поиск по системе</span>
              <h2>Что вы хотите найти?</h2>
              <label className="header-search-input">
                <svg aria-hidden="true" viewBox="0 0 24 24">
                  <circle cx="11" cy="11" r="6" />
                  <path d="m16 16 4 4" />
                </svg>
                <input
                  type="search"
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                  placeholder="Заявка, адрес или раздел"
                  autoFocus
                />
              </label>
              {normalizedSearch ? (
                <div className="header-search-results">
                  {searchTickets.map((ticket) => (
                    <button
                      key={ticket.id}
                      onClick={() => {
                        setSelected(ticket.id);
                        setSection("map");
                        setSearchOpen(false);
                      }}
                    >
                      <span>Заявка</span>
                      <b>{ticket.title}</b>
                      <small>{ticket.address}</small>
                    </button>
                  ))}
                  {searchSections.map((item) => (
                    <button
                      key={item.id}
                      onClick={() => {
                        setSection(item.id);
                        setSearchOpen(false);
                      }}
                    >
                      <span>Раздел</span>
                      <b>{item.label}</b>
                      <small>Перейти в раздел</small>
                    </button>
                  ))}
                  {!searchTickets.length && !searchSections.length && (
                    <p>Ничего не найдено. Попробуйте изменить запрос.</p>
                  )}
                </div>
              ) : (
                <p className="header-search-hint">
                  Начните вводить название заявки, адрес или раздел меню.
                </p>
              )}
            </section>
          </div>
        )}
        {demo && (
          <div className="demo-bar">
            <span>Демонстрационный режим</span>
            <div>
              {(["user", "worker", "dispatcher", "admin"] as Role[]).map(
                (item) => (
                  <button
                    className={item === role ? "active" : ""}
                    onClick={() => {
                      setDemoRole(item);
                      setSection("overview");
                    }}
                    key={item}
                  >
                    {roleNames[item]}
                  </button>
                ),
              )}
            </div>
          </div>
        )}
        {notice && (
          <div className="notice app-toast" role="status" aria-live="polite">
            <span>{notice}</span>
            <button
              aria-label="Закрыть уведомление"
              onClick={() => setNotice("")}
            >
              ×
            </button>
          </div>
        )}
        {section === "admin" || section === "management" ? (
          <ManagementPage
            session={scopedSession}
            role={role}
            onNotice={setNotice}
          />
        ) : section === "zones" ? (
          <BrigadeZones
            vehicles={vehicles}
            session={scopedSession}
            role={role}
            zones={zones}
            onSaved={(zone) =>
              setZones((current) => [
                ...current.filter((item) => item.id !== zone.id),
                zone,
              ])
            }
            onDeleted={(id) =>
              setZones((current) => current.filter((item) => item.id !== id))
            }
            onNotice={setNotice}
          />
        ) : section === "overview" || section === "map" ? (
          <>
            {section === "overview" && (
              <section className="kpis">
                <article>
                  <span>Активные заявки</span>
                  <b>{activeTickets.length}</b>
                  <small>По данным Ticket Service</small>
                </article>
                <article>
                  <span>Бригады на линии</span>
                  <b>{activeBrigades.length}</b>
                  <small>
                    {onlineVehicles.length}{" "}
                    {pluralRu(
                      onlineVehicles.length,
                      "машина",
                      "машины",
                      "машин",
                    )}{" "}
                    {onlineVehicles.length === 1 ? "передаёт" : "передают"}{" "}
                    координаты
                  </small>
                </article>
                <article>
                  <span>Среднее время реакции</span>
                  <b>
                    {overviewMetrics
                      ? Math.round(
                          (Number(overviewMetrics.avg_response_seconds) || 0) /
                            60,
                        )
                      : "—"}{" "}
                    {overviewMetrics && <em>мин</em>}
                  </b>
                  <small>
                    {role === "worker"
                      ? "От создания до назначения заявок бригады"
                      : "По событиям Analytics Service"}
                  </small>
                </article>
                <article>
                  <span>В рамках SLA</span>
                  <b>
                    {slaMetrics
                      ? Math.max(
                          0,
                          Math.round(
                            100 - (Number(slaMetrics.breach_rate) || 0),
                          ),
                        )
                      : "—"}
                    {slaMetrics && <em>%</em>}
                  </b>
                  <small>
                    {slaMetrics
                      ? `${(Number(slaMetrics.response_warnings) || 0) + (Number(slaMetrics.resolution_warnings) || 0)} требуют внимания`
                      : role === "admin" || role === "dispatcher"
                        ? "Данные SLA недоступны"
                        : "Показатель недоступен для этой роли"}
                  </small>
                </article>
              </section>
            )}
            <section className="dashboard-grid">
              <div className="map-card">
                <div className="card-head">
                  <div>
                    <h2>Инфраструктурная карта Москвы</h2>
                    <p>Открытые городские данные, заявки, маршруты и машины</p>
                  </div>
                </div>
                <CityMap
                  tickets={activeTickets}
                  vehicles={mapVehicles}
                  brigades={loadedBrigades}
                  selected={selected}
                  session={scopedSession}
                  onSelect={setSelected}
                  onNotice={setNotice}
                />
              </div>
              <div className="feed-card">
                <div className="card-head">
                  <div>
                    <h2>Оперативная лента</h2>
                    <p>
                      {activeTickets.length}{" "}
                      {pluralRu(
                        activeTickets.length,
                        "инцидент",
                        "инцидента",
                        "инцидентов",
                      )}{" "}
                      · {mapVehicles.length}{" "}
                      {pluralRu(
                        mapVehicles.length,
                        "машина",
                        "машины",
                        "машин",
                      )}{" "}
                      на карте
                    </p>
                  </div>
                </div>
                <TicketCards
                  tickets={activeTickets}
                  selected={selected}
                  onSelect={setSelected}
                />
                <VehicleGroups
                  vehicles={mapVehicles}
                  brigades={loadedBrigades}
                  tickets={activeTickets}
                  selected={selected}
                  onSelect={setSelected}
                />
              </div>
            </section>
          </>
        ) : (
          <SectionPage
            section={section}
            tickets={visibleTickets}
            vehicles={vehicles}
            zones={zones}
            session={scopedSession}
            role={role}
            onTicketUpdate={(ticket) =>
              setTickets((current) =>
                current.map((item) => (item.id === ticket.id ? ticket : item)),
              )
            }
            onTicketCreated={(ticket) =>
              setTickets((current) => [ticket, ...current])
            }
            onNotice={setNotice}
            onOpenMap={(id) => {
              setSelected(id);
              setSection("map");
            }}
            onOpenZones={() => setSection("zones")}
          />
        )}
      </main>
    </div>
  );
}
