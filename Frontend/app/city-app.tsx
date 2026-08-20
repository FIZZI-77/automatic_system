"use client";
/* eslint-disable jsx-a11y/anchor-is-valid, jsx-a11y/click-events-have-key-events, jsx-a11y/no-noninteractive-element-interactions, jsx-a11y/no-autofocus, jsx-a11y/label-has-associated-control */

import { FormEvent, useEffect, useState } from "react";
import { api, config, CurrentUser, loadSession, normalizeRole, Position, Role, saveSession, Session, Ticket } from "./api";
import { CityMap } from "./city-map";
import { BrigadeZones, type BrigadeZoneRecord } from "./brigade-zones";
import "./workspace-pages.css";
import { ManagementPage } from "./management-page";
import { AnalyticsPage } from "./analytics-page";
import { BrigadesPage } from "./brigades-page";
import { brigadeDisplayName, defaultBrigades, loadBrigades, publishBrigades, vehicleDisplayName, type BrigadeRecord } from "./brigade-store";
import { TicketWorkspace } from "./ticket-workspace";
import { AuditPage, CreateTicketPage, NotificationsPage, ProfilePage, ReportsPage, SLAPage } from "./service-pages";
import { AssetsPage, OperationsPage, QualificationsPage, ServiceCatalogPage } from "./admin-modules";
import { CertificationsPage } from "./certifications-page";

const roleNames: Record<Role, string> = { user: "Житель", worker: "Работник", dispatcher: "Диспетчер", admin: "Администратор" };
const statusNames: Record<string, string> = { NEW: "Новая", ASSIGNED: "Назначена", IN_PROGRESS: "В работе", DONE: "Завершена", CANCELED: "Отменена" };
const demoTickets: Ticket[] = [
  { id: "inc-1042", department_id: "dep-utilities", category_id: "", user_id: "", brigade_id: "b-14", title: "Повреждение водопровода", description: "Сильная течь у проезжей части", status: "IN_PROGRESS", priority: "EMERGENCY", address: "ул. Большая Дмитровка, 18", latitude: 55.7652, longitude: 37.6127, created_at: Date.now()/1000-1800, updated_at: Date.now()/1000 },
  { id: "inc-1038", department_id: "dep-roads", category_id: "", user_id: "", brigade_id: "b-07", title: "Не работает освещение", description: "Три фонаря во дворе", status: "ASSIGNED", priority: "HIGH", address: "Страстной бульвар, 6", latitude: 55.7683, longitude: 37.6059, created_at: Date.now()/1000-4200, updated_at: Date.now()/1000 },
  { id: "inc-1031", department_id: "dep-roads", category_id: "", user_id: "", title: "Повреждён дорожный знак", description: "Знак наклонён в сторону дороги", status: "NEW", priority: "MEDIUM", address: "Тверская ул., 12", latitude: 55.7601, longitude: 37.6101, created_at: Date.now()/1000-7200, updated_at: Date.now()/1000 },
  { id: "inc-1026", department_id: "dep-roads", category_id: "", user_id: "", title: "Яма на дороге", description: "Опасна для движения", status: "NEW", priority: "HIGH", address: "Петровка, 22", latitude: 55.7664, longitude: 37.6178, created_at: Date.now()/1000-12000, updated_at: Date.now()/1000 },
  { id: "inc-1021", department_id: "dep-utilities", category_id: "", user_id: "", title: "Упавшее дерево", description: "Перекрыта часть тротуара", status: "NEW", priority: "HIGH", address: "Чистопрудный бульвар, 9", latitude: 55.7647, longitude: 37.6408, created_at: Date.now()/1000-15000, updated_at: Date.now()/1000 },
  { id: "inc-1017", department_id: "dep-roads", category_id: "", user_id: "", title: "Повреждён люк", description: "Требуется ограждение", status: "NEW", priority: "EMERGENCY", address: "Пречистенка, 31", latitude: 55.7422, longitude: 37.5901, created_at: Date.now()/1000-19000, updated_at: Date.now()/1000 },
];
const demoVehicles: Position[] = [
  { vehicle_id: "v-14-1", brigade_id: "b-14", latitude: 55.76290, longitude: 37.60760, speed_kmh: 34, heading: 72, recorded_at: Date.now()/1000 },
  { vehicle_id: "v-14-2", brigade_id: "b-14", latitude: 55.76312, longitude: 37.60792, speed_kmh: 32, heading: 72, recorded_at: Date.now()/1000 },
  { vehicle_id: "v-14-3", brigade_id: "b-14", latitude: 55.76270, longitude: 37.60735, speed_kmh: 30, heading: 72, recorded_at: Date.now()/1000 },
  { vehicle_id: "v-07-1", brigade_id: "b-07", latitude: 55.77020, longitude: 37.61620, speed_kmh: 18, heading: 210, recorded_at: Date.now()/1000 },
  { vehicle_id: "v-07-2", brigade_id: "b-07", latitude: 55.77043, longitude: 37.61586, speed_kmh: 17, heading: 210, recorded_at: Date.now()/1000 },
];
const operationalStatuses=new Set(["ACTIVE","AVAILABLE","BUSY","ON_ROUTE","ON_SITE"]);
function operationalVehicles(vehicles:Position[]){const active=new Set(loadBrigades().filter(brigade=>operationalStatuses.has(brigade.status)).map(brigade=>brigade.id)),freshAfter=Date.now()/1000-120;return vehicles.filter(vehicle=>active.has(vehicle.brigade_id)&&Number(vehicle.recorded_at)>=freshAfter)}
function pluralRu(value:number,one:string,few:string,many:string){const mod100=value%100,mod10=value%10;return mod100>=11&&mod100<=14?many:mod10===1?one:mod10>=2&&mod10<=4?few:many}

const navByRole: Record<Role, { icon: string; label: string; id: string }[]> = {
  user: [{icon:"⌂",label:"Обзор",id:"overview"},{icon:"◎",label:"Мои заявки",id:"tickets"},{icon:"＋",label:"Сообщить",id:"create"},{icon:"◌",label:"Уведомления",id:"notifications"},{icon:"◇",label:"Профиль",id:"profile"}],
  worker: [{icon:"⌂",label:"Смена",id:"overview"},{icon:"✓",label:"Задания",id:"tickets"},{icon:"⌖",label:"Маршрут",id:"map"},{icon:"▤",label:"Отчёты",id:"reports"},{icon:"◇",label:"Профиль",id:"profile"}],
  dispatcher: [{icon:"⌂",label:"Ситуационный центр",id:"overview"},{icon:"⌖",label:"Живая карта",id:"map"},{icon:"◎",label:"Инциденты",id:"tickets"},{icon:"♜",label:"Бригады",id:"brigades"},{icon:"▥",label:"SLA",id:"sla"},{icon:"⇄",label:"Операции",id:"operations"},{icon:"▤",label:"Отчёты",id:"reports"},{icon:"◊",label:"Уведомления",id:"notifications"}],
  admin: [{icon:"⌂",label:"Показатели",id:"overview"},{icon:"◎",label:"Заявки",id:"tickets"},{icon:"♜",label:"Структура",id:"brigades"},{icon:"▦",label:"Аналитика",id:"analytics"},{icon:"▥",label:"SLA",id:"sla"},{icon:"▧",label:"Инфраструктура",id:"assets"},{icon:"⌘",label:"Регламенты",id:"catalog"},{icon:"✦",label:"Квалификации",id:"qualifications"},{icon:"◆",label:"Удостоверения",id:"certifications"},{icon:"⇄",label:"Операции",id:"operations"},{icon:"▤",label:"Отчёты",id:"reports"},{icon:"≡",label:"Аудит",id:"audit"},{icon:"⚙",label:"Управление",id:"admin"}],
};

export function CityApp() {
  const [session, setSession] = useState<Session | null>(null);
  const [showLogin, setShowLogin] = useState(false);
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [demoRole, setDemoRole] = useState<Role>("dispatcher");
  useEffect(() => { const timer = window.setTimeout(() => setSession(loadSession()), 0); return () => window.clearTimeout(timer); }, []);
  if (!session && !showLogin) return <Landing onLogin={() => { setAuthMode("login"); setShowLogin(true); }} onRegister={() => { setAuthMode("register"); setShowLogin(true); }} onDemo={(role) => { setDemoRole(role); setSession({ accessToken: "demo", refreshToken: "", expiresAt: 0, user: { user_id: "demo", email: "demo@city.local", roles: [role], permissions: [], is_active: true, email_verified: true } }); }} />;
  if (!session) return <AuthScreen initialMode={authMode} onBack={() => setShowLogin(false)} onSuccess={(next) => { saveSession(next); setSession(next); }} />;
  const role = session.accessToken === "demo" ? normalizeRole([demoRole]) : normalizeRole(session.user?.roles);
  return <DashboardV2 session={session} role={role} setDemoRole={setDemoRole} onExit={() => { if(session.accessToken!=="demo")void api(config.endpoints.logout,{},"POST",session.accessToken).catch(()=>undefined);saveSession(null);setSession(null);setShowLogin(false); }} />;
}

function Landing({ onLogin, onRegister, onDemo }: { onLogin: () => void; onRegister: () => void; onDemo: (role: Role) => void }) {
  return <main className="landing">
    <nav className="landing-nav"><a className="brand" href="#top"><span>Г</span>Город рядом</a><div className="landing-links"><a href="#how">Как это работает</a><a href="#services">Возможности</a><button className="text-button" onClick={onLogin}>Войти</button><button className="nav-register" onClick={onRegister}>Регистрация</button><button className="primary small" onClick={() => onDemo("dispatcher")}>Открыть демо</button></div></nav>
    <section className="hero" id="top"><div className="hero-copy"><div className="eyebrow">Единая цифровая городская служба</div><h1>Город слышит.<br/><em>Службы действуют.</em></h1><p>Сообщайте о проблемах, следите за исполнением и наблюдайте, как город становится лучше — в одном понятном пространстве.</p><div className="hero-actions"><button className="primary" onClick={() => onDemo("user")}>Сообщить о проблеме <b>→</b></button><button className="ghost" onClick={() => onDemo("dispatcher")}>Посмотреть живую карту</button></div><div className="trust"><span>● Сервисы на связи</span><span>Среднее время реакции <b>18 мин</b></span></div></div>
      <div className="hero-visual"><div className="orb one"/><div className="orb two"/><div className="preview-card"><div className="preview-top"><span>Сейчас в городе</span><b className="live">● LIVE</b></div><div className="mini-map"><i className="road r1"/><i className="road r2"/><i className="road r3"/><button className="pin p1">!</button><button className="pin p2">•</button><button className="car">▰</button><i className="route"/></div><div className="preview-stats"><div><b>24</b><span>активных заявки</span></div><div><b>11</b><span>бригад на линии</span></div><div><b>94%</b><span>выполнено вовремя</span></div></div></div><div className="floating-note"><span>✓</span><div><b>Бригада назначена</b><small>Прибудет через 12 минут</small></div></div></div>
    </section>
    <section className="features" id="services"><div><span>01</span><h3>Всё видно</h3><p>Заявки, машины и маршруты на одной карте в реальном времени.</p></div><div><span>02</span><h3>Каждый на своём месте</h3><p>Отдельные рабочие пространства для жителей, бригад и служб.</p></div><div><span>03</span><h3>Ничего не теряется</h3><p>История действий, SLA и уведомления сопровождают заявку до результата.</p></div></section>
    <section className="process" id="how"><div className="eyebrow">Просто для жителя. Точно для служб.</div><h2>От сообщения до результата<br/>без лишних звонков</h2><div className="process-row"><article><b>1</b><h3>Отметьте проблему</h3><p>Укажите точку на карте, добавьте описание и фотографию.</p></article><article><b>2</b><h3>Мы найдём исполнителя</h3><p>Диспетчер увидит ближайшую подходящую бригаду и маршрут.</p></article><article><b>3</b><h3>Следите за ходом работ</h3><p>Статусы и уведомления покажут, что происходит прямо сейчас.</p></article></div></section>
    <footer><a className="brand" href="#top"><span>Г</span>Город рядом</a><p>Цифровые городские службы — ближе, понятнее, быстрее.</p><div className="footer-auth"><button className="ghost" onClick={onRegister}>Зарегистрироваться</button><button className="primary small" onClick={onLogin}>Войти в систему</button></div></footer>
  </main>;
}

function AuthScreen({ initialMode, onBack, onSuccess }: { initialMode: "login" | "register"; onBack: () => void; onSuccess: (s: Session) => void }) {
  const [email, setEmail] = useState(""); const [password, setPassword] = useState(""); const [passwordRepeat, setPasswordRepeat] = useState(""); const [username, setUsername] = useState(""); const [error, setError] = useState(""); const [message, setMessage] = useState(""); const [loading, setLoading] = useState(false); const [mode,setMode]=useState<"login"|"register"|"forgot"|"reset"|"verify">(initialMode); const [token,setToken]=useState("");
  async function submit(e: FormEvent) { e.preventDefault(); setLoading(true); setError(""); try { const login = await api<{access_token:string;refresh_token:string;access_expires_at_unix:number}>(config.endpoints.login,{email,password,client_id:"city-web"}); const user = await api<CurrentUser>(config.endpoints.me,undefined,"GET",login.access_token); onSuccess({ accessToken:login.access_token,refreshToken:login.refresh_token,expiresAt:login.access_expires_at_unix,user }); } catch (e) { setError(e instanceof Error ? e.message : "Не удалось войти"); } finally { setLoading(false); } }
  async function register(e: FormEvent) { e.preventDefault(); setError(""); setMessage(""); if(password!==passwordRepeat){setError("Пароли не совпадают");return} setLoading(true); try { await api(config.endpoints.register,{email,password,username}); setMessage("Аккаунт создан. Теперь войдите с указанными данными."); setMode("login"); setPassword(""); setPasswordRepeat(""); } catch(e) { setError(e instanceof Error?e.message:"Не удалось зарегистрироваться"); } finally { setLoading(false); } }
  async function recover(e:FormEvent){e.preventDefault();setLoading(true);setError("");try{if(mode==="forgot"){await api(config.endpoints.requestPasswordReset,{email});setMode("reset")}else if(mode==="reset"){await api(config.endpoints.resetPassword,{token,new_password:password});setMode("login");setToken("");setPassword("")}else if(mode==="verify"){await api(config.endpoints.verifyEmail,{token});setMode("login");setToken("")}}catch(e){setError(e instanceof Error?e.message:"Операция не выполнена")}finally{setLoading(false)}}
  const heading=mode==="login"?"Вход в систему":mode==="register"?"Создание аккаунта":mode==="forgot"?"Восстановление пароля":mode==="reset"?"Новый пароль":"Подтверждение email";
  return <main className="auth-page"><button className="back" onClick={onBack}>← На главную</button><form className="auth-card" onSubmit={mode==="login"?submit:mode==="register"?register:recover}><a className="brand" href="#"><span>Г</span>Город рядом</a><div><div className="eyebrow auth-eyebrow">Учётная запись</div><h2>{heading}</h2><p>{mode==="login"?"Используйте учётную запись городских сервисов.":mode==="register"?"Зарегистрируйтесь как житель, чтобы создавать обращения и следить за их выполнением.":mode==="forgot"?"Укажите email — сервис отправит ссылку с токеном.":"Введите токен, полученный в письме."}</p></div>{mode==="register"&&<label>Имя пользователя<input value={username} onChange={e=>setUsername(e.target.value)} placeholder="Не менее 3 символов" minLength={3} maxLength={100} required/></label>}{["login","register","forgot"].includes(mode)&&<label>Электронная почта<input type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="name@example.ru" required/></label>}{["reset","verify"].includes(mode)&&<label>Токен<input value={token} onChange={e=>setToken(e.target.value)} required/></label>}{["login","register","reset"].includes(mode)&&<label>{mode==="login"?"Пароль":"Новый пароль"}<input type="password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="Не менее 8 символов" minLength={8} required/></label>}{mode==="register"&&<label>Повторите пароль<input type="password" value={passwordRepeat} onChange={e=>setPasswordRepeat(e.target.value)} placeholder="Повторите пароль" minLength={8} required/></label>}{error&&<div className="form-error">{error}</div>}{message&&<div className="form-success">{message}</div>}<button className="primary" disabled={loading}>{loading?"Выполняем…":mode==="login"?"Войти":mode==="register"?"Зарегистрироваться":mode==="forgot"?"Отправить письмо":mode==="reset"?"Сменить пароль":"Подтвердить"}</button><div className="auth-links">{mode==="login"?<><button type="button" onClick={()=>setMode("forgot")}>Забыли пароль?</button><button type="button" onClick={()=>setMode("verify")}>Подтвердить email</button></>:<button type="button" onClick={()=>setMode("login")}>Вернуться ко входу</button>}</div>{mode==="login"&&<div className="auth-register-callout"><span>Ещё нет аккаунта?</span><button type="button" onClick={()=>{setError("");setMessage("");setMode("register")}}>Зарегистрироваться</button></div>}<small>{mode==="register"?"После регистрации назначается роль «Житель». Рабочие роли создаёт администратор.":"Роль и доступ определяются сервером после входа."}</small></form></main>;
}

export function LegacyDashboard({ session, role, setDemoRole, onExit }: {session:Session;role:Role;setDemoRole:(r:Role)=>void;onExit:()=>void}) {
  const [section, setSection] = useState("overview"); const [tickets, setTickets] = useState<Ticket[]>([]); const [vehicles, setVehicles] = useState<Position[]>([]); const [selected, setSelected] = useState<string>(); const [loading, setLoading] = useState(true); const [notice, setNotice] = useState("");
  const demo = session.accessToken === "demo"; const [renderedAt] = useState(() => Date.now() / 1000);
  useEffect(() => { let active=true; (async()=>{ try { if(demo){setTickets(demoTickets);setVehicles(demoVehicles);return;} const result=await api<{tickets:Ticket[]}>(config.endpoints.ticketsList,{limit:100,offset:0,sort_by:"created_at",sort_order:"desc"},"POST",session.accessToken); if(active)setTickets(result.tickets||[]); } catch(e){if(active)setNotice(e instanceof Error?e.message:"Ошибка загрузки");} finally{if(active)setLoading(false);} })(); return()=>{active=false}; },[demo,session.accessToken]);
  const activeTickets=tickets.filter(t=>!["DONE","CANCELED"].includes(t.status)); const selectedTicket=tickets.find(t=>t.id===selected)||activeTickets[0];
  const title = role === "dispatcher" ? "Ситуационный центр" : role === "worker" ? "Рабочая смена" : role === "admin" ? "Управление городом" : "Добрый день";
  return <div className="app-shell"><aside><a className="brand inverse" href="#"><span>Г</span><b>Город<br/>рядом</b></a><nav>{navByRole[role].map(item=><button key={item.id} className={section===item.id?"active":""} onClick={()=>setSection(item.id)}><i>{item.icon}</i><span>{item.label}</span></button>)}</nav><div className="aside-bottom"><button><i>?</i><span>Поддержка</span></button><button onClick={onExit}><i>↗</i><span>Выйти</span></button></div></aside>
    <main className="workspace"><header><div><small>{roleNames[role]} · Москва</small><h1>{title}</h1></div><div className="header-actions"><button className="icon-btn" aria-label="Поиск">⌕</button><button className="icon-btn" aria-label="Уведомления">◌</button><div className="avatar">{session.user?.email?.slice(0,2).toUpperCase()||"ГР"}</div></div></header>
      {demo&&<div className="demo-bar"><span>Демонстрационный режим</span><div>{(["user","worker","dispatcher","admin"] as Role[]).map(r=><button className={r===role?"active":""} onClick={()=>setDemoRole(r)} key={r}>{roleNames[r]}</button>)}</div></div>}
      {notice&&<div className="notice">{notice}<button onClick={()=>setNotice("")}>×</button></div>}
      <section className="kpis"><article><span>Активные заявки</span><b>{activeTickets.length}</b><small className="up">↑ 8% за сегодня</small></article><article><span>Бригады на линии</span><b>{vehicles.length||11}<em> / 14</em></b><small>3 свободны</small></article><article><span>Среднее время реакции</span><b>18 <em>мин</em></b><small className="up">↓ 4 мин к среднему</small></article><article><span>В рамках SLA</span><b>94<em>%</em></b><small>2 требуют внимания</small></article></section>
      <section className="dashboard-grid"><div className="map-card"><div className="card-head"><div><h2>{section==="tickets"?"Инциденты":"Оперативная карта"}</h2><p>Заявки, маршруты и городские бригады</p></div><div className="segmented"><button className="active">Все</button><button>Заявки</button><button>Бригады</button></div></div><CityMap tickets={activeTickets} vehicles={vehicles} selected={selected} onSelect={setSelected}/></div>
        <div className="feed-card">
          <div className="card-head"><div><h2>Требуют внимания</h2><p>{activeTickets.length} инцидентов · {vehicles.length} машин</p></div><button className="link" onClick={()=>setSection("tickets")}>Все →</button></div>
          <div className="ticket-list">{loading?<p>Загружаем данные…</p>:activeTickets.slice(0,4).map(t=><button key={t.id} className={selected===t.id?"selected":""} onClick={()=>setSelected(t.id)}><span className={`priority ${t.priority.toLowerCase()}`}/><div><b>{t.title}</b><small>{t.address}</small><div><em className={`status ${t.status.toLowerCase()}`}>{statusNames[t.status]||t.status}</em><time>{Math.max(1,Math.round((renderedAt-t.created_at)/60))} мин назад</time></div></div></button>)}</div>
          <VehicleGroups vehicles={vehicles} tickets={activeTickets} selected={selected} onSelect={setSelected}/>
          {selectedTicket&&<div className="quick-action"><div><span>Выбрана заявка</span><b>{selectedTicket.title}</b></div><button onClick={()=>setNotice(demo?"В демо действия не отправляются":"Команда подготовлена")}>{role==="dispatcher"?"Назначить бригаду":role==="worker"?"Начать работу":"Открыть"}</button></div>}
        </div>
      </section>
      <section className="bottom-grid"><div className="activity"><div className="card-head"><div><h2>Последние события</h2><p>Обновления в реальном времени</p></div><span className="live">● LIVE</span></div><ul><li><i className="mint">✓</i><div><b>Бригада №14 приняла заявку</b><small>Повреждение водопровода · 3 мин назад</small></div></li><li><i className="peach">⌖</i><div><b>Построен новый маршрут</b><small>Расчётное прибытие через 12 минут</small></div></li><li><i className="lilac">◌</i><div><b>Получена новая заявка</b><small>Не работает освещение · 8 мин назад</small></div></li></ul></div><div className="sla-card"><div className="card-head"><div><h2>Исполнение SLA</h2><p>За текущие сутки</p></div><button className="link">Подробнее →</button></div><div className="ring"><div><b>94%</b><span>в срок</span></div></div><div className="sla-legend"><span><i className="ok"/>Выполнено <b>46</b></span><span><i className="warn"/>Под риском <b>3</b></span><span><i className="bad"/>Нарушено <b>1</b></span></div></div></section>
    </main></div>;
}

const extraNavigation = { icon: "⌁", label: "Зоны бригад", id: "zones" };
const managementNavigation = { icon: "⚙", label: "Управление", id: "management" };
const pageTitles: Record<string, string> = { overview: "Ситуационный центр", map: "Живая карта", tickets: "Заявки и инциденты", brigades: "Городские бригады", zones: "Зоны обслуживания", analytics: "Аналитика", sla: "Контроль SLA", assets:"Городская инфраструктура", catalog:"Регламенты и категории", qualifications:"Квалификации", certifications:"Удостоверения и допуски", operations:"Операционный контроль", reports: "Отчёты", audit: "Журнал аудита", profile: "Профиль", notifications: "Уведомления", create: "Новая заявка", admin: "Управление", structure: "Структура" };

function DashboardV2({ session, role, setDemoRole, onExit }: {session:Session;role:Role;setDemoRole:(r:Role)=>void;onExit:()=>void}) {
  const [section, setSection] = useState("overview");
  const [searchOpen,setSearchOpen]=useState(false);
  const [searchQuery,setSearchQuery]=useState("");
  const [accountName,setAccountName]=useState(session.accessToken==="demo"?`Демо: ${roleNames[role]}`:(session.user?.email?.split("@")[0]||"Профиль"));
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [vehicles, setVehicles] = useState<Position[]>([]);
  const [selected, setSelected] = useState<string>();
  const [notice, setNotice] = useState("");
  const [zones, setZones] = useState<BrigadeZoneRecord[]>([]);
  const [dispatcherDepartmentId,setDispatcherDepartmentId]=useState(role==="dispatcher"?(session.user?.department_id||(session.accessToken==="demo"?"dep-roads":"")):"");
  const [overviewMetrics,setOverviewMetrics]=useState<{avg_response_seconds:number}>({avg_response_seconds:0});
  const [slaMetrics,setSlaMetrics]=useState<{breach_rate:number;response_warnings:number;resolution_warnings:number}>({breach_rate:0,response_warnings:0,resolution_warnings:0});
  const demo = session.accessToken === "demo";
  useEffect(()=>{if(demo)return;let active=true;api<{user_profile?:{full_name?:string}}>(config.endpoints.profile,undefined,"GET",session.accessToken).then(result=>{if(active&&result.user_profile?.full_name)setAccountName(result.user_profile.full_name)}).catch(()=>undefined);return()=>{active=false}},[demo,session.accessToken]);
  useEffect(() => {
    let active = true;
    (async () => {
      try {
        let departmentId="";
        if(role==="dispatcher"){
          if(demo)departmentId="dep-roads";
          else if(session.user?.department_id)departmentId=session.user.department_id;
          else{
            const resolved=await api<{department_id:string;can_operate:boolean}>(config.endpoints.workingDepartment,{user_id:session.user?.user_id},"POST",session.accessToken);
            if(!resolved.can_operate||!resolved.department_id)throw new Error("У диспетчера нет активного рабочего департамента");
            departmentId=resolved.department_id;
          }
        }
        if(active)setDispatcherDepartmentId(departmentId);
        if (demo) {
          const demoBrigades=departmentId?defaultBrigades.filter(item=>item.department_id===departmentId):defaultBrigades;
          const brigadeIds=new Set(demoBrigades.map(item=>item.id));
          publishBrigades(demoBrigades);
          setTickets(departmentId?demoTickets.filter(item=>item.department_id===departmentId):demoTickets);
          setVehicles(departmentId?demoVehicles.filter(item=>brigadeIds.has(item.brigade_id)):demoVehicles);
          setOverviewMetrics({avg_response_seconds:1080}); setSlaMetrics({breach_rate:6,response_warnings:2,resolution_warnings:0}); return;
        }
        if(role==="user"){
          const ticketResult=await api<{tickets:Ticket[]}>(config.endpoints.ticketsList,{limit:100,offset:0,sort_by:"created_at",sort_order:"desc"},"POST",session.accessToken);
          publishBrigades([]);if(active){setTickets(ticketResult.tickets||[]);setVehicles([]);setZones([]);setOverviewMetrics({avg_response_seconds:0});setSlaMetrics({breach_rate:0,response_warnings:0,resolution_warnings:0})}return;
        }
        if(role==="worker"){
          const [ticketResult,brigadeResult]=await Promise.all([api<{tickets:Ticket[]}>(config.endpoints.ticketsList,{limit:100,offset:0,sort_by:"created_at",sort_order:"desc"},"POST",session.accessToken),api<{brigade:BrigadeRecord}>(config.endpoints.brigadeByUser,{user_id:session.user?.user_id,only_active:true},"POST",session.accessToken).catch(()=>undefined)]);
          const ownBrigades=brigadeResult?.brigade?[brigadeResult.brigade]:[];
          let ownVehicles:Position[]=[];
          if(brigadeResult?.brigade){
            const brigadeId=brigadeResult.brigade.id,historyTo=new Date(),historyFrom=new Date(historyTo.getTime()-7*24*60*60*1000);
            const [currentResult,historyResult]=await Promise.all([
              api<{locations:Record<string,{position?:Position}>}>(config.endpoints.locationsBatch,{brigade_ids:[brigadeId],allow_stale:true},"POST",session.accessToken).catch(()=>({locations:{}})),
              api<{positions:Position[]}>(config.endpoints.locationsHistory,{brigade_id:brigadeId,from:historyFrom.toISOString(),to:historyTo.toISOString(),limit:1000,offset:0,order:"desc"},"POST",session.accessToken).catch(()=>({positions:[]})),
            ]);
            const latestByVehicle=new Map<string,Position>();
            [...Object.values(currentResult.locations||{}).flatMap(item=>item.position?[item.position]:[]),...(historyResult.positions||[])].forEach(position=>{const previous=latestByVehicle.get(position.vehicle_id);if(!previous||Number(position.recorded_at)>=Number(previous.recorded_at))latestByVehicle.set(position.vehicle_id,position)});
            ownVehicles=Array.from(latestByVehicle.values());
          }
          const workerTickets=ticketResult.tickets||[];
          const responseTimes=workerTickets
            .filter(ticket=>ticket.brigade_id===brigadeResult?.brigade?.id&&Number(ticket.assigned_at)>Number(ticket.created_at))
            .map(ticket=>Number(ticket.assigned_at)-Number(ticket.created_at));
          const avgResponseSeconds=responseTimes.length?responseTimes.reduce((sum,value)=>sum+value,0)/responseTimes.length:0;
          publishBrigades(ownBrigades);if(active){setTickets(workerTickets);setVehicles(ownVehicles);setZones([]);setOverviewMetrics({avg_response_seconds:avgResponseSeconds});setSlaMetrics({breach_rate:0,response_warnings:0,resolution_warnings:0})}return;
        }
        const departmentFilter=departmentId?{department_id:departmentId}:{};
        const [ticketResult, brigadeResult, analyticsResult, slaResult] = await Promise.all([
          api<{tickets:Ticket[]}>(config.endpoints.ticketsList, { limit: 100, offset: 0, sort_by: "created_at", sort_order: "desc",...departmentFilter }, "POST", session.accessToken),
          api<{brigades:BrigadeRecord[]}>(config.endpoints.brigadesList, { limit: 100, offset: 0,...departmentFilter }, "POST", session.accessToken),
          api<{avg_response_seconds:number}>(config.endpoints.analyticsOverview, { filter:departmentFilter }, "POST", session.accessToken),
          api<{breach_rate:number;response_warnings:number;resolution_warnings:number}>(config.endpoints.analyticsSlaSummary, { filter:departmentFilter }, "POST", session.accessToken),
        ]);
        const brigades = (brigadeResult.brigades || []).filter(item=>!departmentId||item.department_id===departmentId);
        publishBrigades(brigades);
        let positions: Position[] = [];
        if (brigades.length) {
          const historyTo=new Date(),historyFrom=new Date(historyTo.getTime()-7*24*60*60*1000);
          const [locationResult,historyResults] = await Promise.all([
            api<{locations:Record<string,{position?:Position}>}>(config.endpoints.locationsBatch, { brigade_ids: brigades.map(item => item.id), allow_stale: true }, "POST", session.accessToken),
            Promise.all(brigades.map(async brigade=>{try{const result=await api<{positions:Position[]}>(config.endpoints.locationsHistory,{brigade_id:brigade.id,from:historyFrom.toISOString(),to:historyTo.toISOString(),limit:1000,offset:0,order:"desc"},"POST",session.accessToken);return result.positions||[]}catch{return []}})),
          ]);
          const latestByVehicle=new Map<string,Position>();
          [...Object.values(locationResult.locations||{}).flatMap(item=>item.position?[item.position]:[]),...historyResults.flat()].forEach(position=>{const previous=latestByVehicle.get(position.vehicle_id);if(!previous||Number(position.recorded_at)>=Number(previous.recorded_at))latestByVehicle.set(position.vehicle_id,position)});
          positions=Array.from(latestByVehicle.values());
        }
        const zoneResults = await Promise.all(brigades.map(async brigade => {
          const result = await api<{zones:Array<{id:string;brigade_id:string;name:string;priority:number;geo_json:string}>}>(config.endpoints.brigadeZonesList, { brigade_id: brigade.id, active: true }, "POST", session.accessToken);
          return result.zones || [];
        }));
        const loadedZones = zoneResults.flat().flatMap(zone => {
          try {
            const geometry = JSON.parse(zone.geo_json), ring = geometry.coordinates?.[0] || [];
            return [{ id: zone.id, brigade_id: zone.brigade_id, name: zone.name, priority: zone.priority, points: ring.slice(0, -1).map(([lon, lat]:[number,number]) => [lat, lon] as [number,number]) }];
          } catch { return []; }
        });
        if (active) { setTickets((ticketResult.tickets || []).filter(item=>!departmentId||item.department_id===departmentId)); setVehicles(positions); setZones(loadedZones); setOverviewMetrics(analyticsResult); setSlaMetrics(slaResult); }
      } catch (error) { if (active) setNotice(error instanceof Error ? error.message : "Ошибка загрузки"); }
    })();
    return () => { active = false; };
  }, [demo, role, session.accessToken, session.user?.department_id, session.user?.user_id]);
  useEffect(() => {
    if (demo) return;
    const separator = config.wsUrl.includes("?") ? "&" : "?";
    const socket = new WebSocket(`${config.wsUrl}${separator}access_token=${encodeURIComponent(session.accessToken)}`);
    socket.onmessage = event => {
      try {
        const incoming = JSON.parse(event.data) as { title?: string; body?: string; message?: string };
        const message = [incoming.title, incoming.body || incoming.message].filter(Boolean).join(": ");
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
  const activeTickets = tickets.filter(ticket => !["DONE", "CANCELED"].includes(ticket.status));
  const onlineVehicles = operationalVehicles(vehicles);
  const activeBrigades = loadBrigades().filter(brigade=>operationalStatuses.has(brigade.status));
  const scopedSession:Session=dispatcherDepartmentId&&session.user?{...session,user:{...session.user,department_id:dispatcherDepartmentId}}:session;
  const navigation = [...navByRole[role], ...(role === "dispatcher" ? [managementNavigation] : []), ...(["dispatcher", "admin"].includes(role) ? [extraNavigation] : [])];
  const normalizedSearch=searchQuery.trim().toLocaleLowerCase("ru-RU");
  const searchTickets=normalizedSearch?tickets.filter(ticket=>[ticket.id,ticket.title,ticket.address].some(value=>value.toLocaleLowerCase("ru-RU").includes(normalizedSearch))).slice(0,6):[];
  const searchSections=normalizedSearch?navigation.filter(item=>item.label.toLocaleLowerCase("ru-RU").includes(normalizedSearch)).slice(0,5):[];
  const accountInitials=accountName.split(/[\s._-]+/).filter(Boolean).map(part=>part[0]).join("").slice(0,2).toLocaleUpperCase("ru-RU")||"П";
  return <div className="app-shell"><aside><a className="brand inverse" href="#"><span>Г</span></a><nav>{navigation.map(item => <button key={item.id} className={section === item.id ? "active" : ""} onClick={() => setSection(item.id)}><i>{item.icon}</i><span>{item.label}</span></button>)}</nav><div className="aside-bottom"><button onClick={onExit}><i>↗</i><span>Выйти</span></button></div></aside>
    <main className={`workspace section-${section}`}><header><div><small>{roleNames[role]} · Москва</small><h1>{pageTitles[section] || "Городские сервисы"}</h1></div><div className="header-actions"><button className="header-action" aria-label="Открыть поиск" onClick={()=>setSearchOpen(true)}><svg aria-hidden="true" viewBox="0 0 24 24"><circle cx="11" cy="11" r="6"/><path d="m16 16 4 4"/></svg><b>Поиск</b></button><button className="header-action" aria-label="Открыть уведомления" onClick={()=>setSection("notifications")}><svg aria-hidden="true" viewBox="0 0 24 24"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/></svg><b>Уведомления</b></button><button className="account-button" aria-label="Открыть профиль" onClick={()=>setSection("profile")}><span className="avatar">{accountInitials}</span><span><b>{accountName}</b><small>{roleNames[role]}</small></span></button></div></header>
      {searchOpen&&<div className="header-search-backdrop" role="presentation" onMouseDown={event=>{if(event.target===event.currentTarget)setSearchOpen(false)}}><section className="header-search-dialog" role="dialog" aria-modal="true" aria-label="Поиск по системе"><button className="modal-close" aria-label="Закрыть поиск" onClick={()=>setSearchOpen(false)}>×</button><span className="eyebrow">Поиск по системе</span><h2>Что вы хотите найти?</h2><label className="header-search-input"><svg aria-hidden="true" viewBox="0 0 24 24"><circle cx="11" cy="11" r="6"/><path d="m16 16 4 4"/></svg><input type="search" value={searchQuery} onChange={event=>setSearchQuery(event.target.value)} placeholder="Заявка, адрес или раздел" autoFocus/></label>{normalizedSearch?<div className="header-search-results">{searchTickets.map(ticket=><button key={ticket.id} onClick={()=>{setSelected(ticket.id);setSection("map");setSearchOpen(false)}}><span>Заявка</span><b>{ticket.title}</b><small>{ticket.address}</small></button>)}{searchSections.map(item=><button key={item.id} onClick={()=>{setSection(item.id);setSearchOpen(false)}}><span>Раздел</span><b>{item.label}</b><small>Перейти в раздел</small></button>)}{!searchTickets.length&&!searchSections.length&&<p>Ничего не найдено. Попробуйте изменить запрос.</p>}</div>:<p className="header-search-hint">Начните вводить название заявки, адрес или раздел меню.</p>}</section></div>}
      {demo && <div className="demo-bar"><span>Демонстрационный режим</span><div>{(["user", "worker", "dispatcher", "admin"] as Role[]).map(item => <button className={item === role ? "active" : ""} onClick={() => { setDemoRole(item); setSection("overview"); }} key={item}>{roleNames[item]}</button>)}</div></div>}
      {notice && <div className="notice app-toast" role="status" aria-live="polite"><span>{notice}</span><button aria-label="Закрыть уведомление" onClick={() => setNotice("")}>×</button></div>}
      {section === "admin" || section === "management" ? <ManagementPage session={scopedSession} role={role} onNotice={setNotice}/> : section === "zones" ? <BrigadeZones vehicles={vehicles} session={scopedSession} role={role} zones={zones} onSaved={zone => setZones(current => [...current.filter(item => item.id !== zone.id), zone])} onDeleted={id=>setZones(current=>current.filter(item=>item.id!==id))} onNotice={setNotice}/> : section === "overview" || section === "map" ? <>
        {section === "overview" && <section className="kpis"><article><span>Активные заявки</span><b>{activeTickets.length}</b><small>По данным Ticket Service</small></article><article><span>Бригады на линии</span><b>{activeBrigades.length}</b><small>{onlineVehicles.length} {pluralRu(onlineVehicles.length,"машина","машины","машин")} {onlineVehicles.length===1?"передаёт":"передают"} координаты</small></article><article><span>Среднее время реакции</span><b>{Math.round((Number(overviewMetrics.avg_response_seconds)||0)/60)} <em>мин</em></b><small>{role==="worker"?"От создания до назначения заявок бригады":"По событиям Analytics Service"}</small></article><article><span>В рамках SLA</span><b>{Math.max(0,Math.round(100-(Number(slaMetrics.breach_rate)||0)))}<em>%</em></b><small>{(Number(slaMetrics.response_warnings)||0)+(Number(slaMetrics.resolution_warnings)||0)} требуют внимания</small></article></section>}
        <section className="dashboard-grid"><div className="map-card"><div className="card-head"><div><h2>Инфраструктурная карта Москвы</h2><p>Открытые городские данные, заявки, маршруты и машины</p></div></div><CityMap tickets={activeTickets} vehicles={onlineVehicles} selected={selected} session={scopedSession} onSelect={setSelected} onNotice={setNotice}/></div><div className="feed-card"><div className="card-head"><div><h2>Оперативная лента</h2><p>{activeTickets.length} {pluralRu(activeTickets.length,"инцидент","инцидента","инцидентов")} · {onlineVehicles.length} {pluralRu(onlineVehicles.length,"машина","машины","машин")}</p></div></div><TicketCards tickets={activeTickets} selected={selected} onSelect={setSelected}/><VehicleGroups vehicles={onlineVehicles} tickets={activeTickets} selected={selected} onSelect={setSelected}/></div></section>
      </> : <SectionPage section={section} tickets={tickets} vehicles={onlineVehicles} zones={zones} session={scopedSession} role={role} onTicketUpdate={ticket=>setTickets(current=>current.map(item=>item.id===ticket.id?ticket:item))} onTicketCreated={ticket=>setTickets(current=>[ticket,...current])} onNotice={setNotice} onOpenMap={id => { setSelected(id); setSection("map"); }} onOpenZones={() => setSection("zones")}/>}
    </main></div>;
}

function TicketCards({ tickets, selected, onSelect }: { tickets: Ticket[]; selected?: string; onSelect: (id: string) => void }) {
  return <div className="ticket-list">{tickets.slice(0,6).map(ticket => <button key={ticket.id} className={selected === ticket.id ? "selected" : ""} onClick={() => onSelect(ticket.id)}><span className={`priority ${ticket.priority.toLowerCase()}`}/><div><b>{ticket.title}</b><em className={`status ${ticket.status.toLowerCase()}`}>{statusNames[ticket.status] || ticket.status}</em></div></button>)}</div>;
}

function vehicleState(vehicle:Position,tickets:Ticket[]){
  const brigade=loadBrigades().find(item=>item.id===vehicle.brigade_id),job=tickets.find(ticket=>ticket.brigade_id===vehicle.brigade_id&&["ASSIGNED","IN_PROGRESS"].includes(ticket.status));
  if(brigade?.status==="ON_ROUTE"||(job&&Number(vehicle.speed_kmh)>3))return "В пути";
  if(brigade?.status==="ON_SITE")return "На месте";
  if(brigade?.status==="AVAILABLE")return "Свободна";
  if(brigade?.status==="BUSY"||job)return "Выполняет заявку";
  return "На линии";
}

function VehicleGroups({vehicles,tickets,selected,onSelect}:{vehicles:Position[];tickets:Ticket[];selected?:string;onSelect:(id:string)=>void}){
  const groups=Array.from(new Set(vehicles.map(vehicle=>vehicle.brigade_id))).map(brigadeId=>({brigadeId,vehicles:vehicles.filter(vehicle=>vehicle.brigade_id===brigadeId)}));
  return <div className="vehicle-list"><div className="list-caption">Машины по бригадам</div>{groups.map(group=>{const active=group.vehicles.some(vehicle=>vehicle.vehicle_id===selected);return <button key={group.brigadeId} className={active?"selected":""} onClick={()=>onSelect(group.vehicles[0].vehicle_id)}><i>▲</i><div><b>{brigadeDisplayName(group.brigadeId)}</b>{group.vehicles.map(vehicle=><span className="vehicle-feed-row" key={vehicle.vehicle_id}><small>{vehicleDisplayName(vehicle.vehicle_id)}</small><em>{vehicleState(vehicle,tickets)}</em></span>)}</div><span>⌖</span></button>})}</div>
}

function SectionPage({ section, tickets, vehicles, zones, session, role, onTicketUpdate, onTicketCreated, onNotice, onOpenMap, onOpenZones }: { section: string; tickets: Ticket[]; vehicles: Position[]; zones: BrigadeZoneRecord[]; session:Session; role:Role; onTicketUpdate:(ticket:Ticket)=>void; onTicketCreated:(ticket:Ticket)=>void; onNotice:(text:string)=>void; onOpenMap: (id: string) => void; onOpenZones: () => void }) {
  const [selectedBrigade, setSelectedBrigade] = useState<string>();
  if (section === "analytics") return <AnalyticsPage tickets={tickets} session={session} onNotice={onNotice}/>;
  if (section === "brigades") return <BrigadesPage tickets={tickets} vehicles={vehicles} zones={zones} onOpenMap={onOpenMap} onOpenZones={onOpenZones}/>;
  if (section === "sla") return <SLAPage session={session} tickets={tickets} role={role} onOpenMap={onOpenMap} onNotice={onNotice}/>;
  if (section === "tickets") return <TicketWorkspace tickets={tickets} session={session} role={role} onUpdate={onTicketUpdate} onMap={onOpenMap} onNotice={onNotice}/>;
  if (section === "create") return <CreateTicketPage session={session} onCreated={onTicketCreated} onNotice={onNotice}/>;
  if (section === "notifications") return <NotificationsPage session={session} onNotice={onNotice}/>;
  if (section === "profile") return <ProfilePage session={session} onNotice={onNotice}/>;
  if (section === "reports") return <ReportsPage session={session} tickets={tickets} role={role} onNotice={onNotice}/>;
  if (section === "audit") return <AuditPage session={session} onNotice={onNotice}/>;
  if (section === "assets") return <AssetsPage session={session} onNotice={onNotice}/>;
  if (section === "catalog") return <ServiceCatalogPage session={session} onNotice={onNotice}/>;
  if (section === "qualifications") return <QualificationsPage session={session} onNotice={onNotice}/>;
  if (section === "certifications") return <CertificationsPage session={session} onNotice={onNotice}/>;
  if (section === "operations") return <OperationsPage session={session} role={role} tickets={tickets} onNotice={onNotice}/>;
  if (section === "brigades") { const activeVehicle = vehicles.find(vehicle => vehicle.brigade_id === selectedBrigade); const jobs = tickets.filter(ticket => ticket.brigade_id === selectedBrigade && ["ASSIGNED", "IN_PROGRESS"].includes(ticket.status)); const brigadeZones = zones.filter(zone => zone.brigade_id === selectedBrigade); return <section className="content-page"><div className="page-toolbar"><div><h2>Бригады на линии</h2><p>Нажмите на карточку, чтобы открыть состав, заявки и территорию</p></div><button className="primary" onClick={onOpenZones}>Настроить зоны</button></div><div className={`brigades-layout ${activeVehicle ? "has-detail" : ""}`}><div className="brigade-grid">{vehicles.map(vehicle => { const job = tickets.find(ticket => ticket.brigade_id === vehicle.brigade_id && ["ASSIGNED", "IN_PROGRESS"].includes(ticket.status)); return <article className={selectedBrigade === vehicle.brigade_id ? "selected" : ""} key={vehicle.vehicle_id} onClick={() => setSelectedBrigade(vehicle.brigade_id)}><i>▲</i><div><span>НА ЛИНИИ</span><h3>Бригада {vehicle.brigade_id}</h3><p>{job ? job.title : "Свободна"}</p></div><button onClick={event => { event.stopPropagation(); onOpenMap(vehicle.vehicle_id); }}>На карте</button></article>;})}</div>{activeVehicle && <aside className="brigade-detail"><button className="detail-close" onClick={() => setSelectedBrigade(undefined)}>×</button><span className="eyebrow">Детальная информация</span><h2>Бригада {activeVehicle.brigade_id}</h2><div className="brigade-status">● На линии</div><dl><div><dt>Машина</dt><dd>{activeVehicle.vehicle_id}</dd></div><div><dt>Скорость</dt><dd>{Math.round(activeVehicle.speed_kmh)} км/ч</dd></div><div><dt>Курс</dt><dd>{Math.round(activeVehicle.heading)}°</dd></div><div><dt>Активных заявок</dt><dd>{jobs.length}</dd></div><div><dt>Зон обслуживания</dt><dd>{brigadeZones.length}</dd></div></dl><h3>Текущие задания</h3>{jobs.length ? jobs.map(job => <button className="brigade-job" key={job.id} onClick={() => onOpenMap(job.id)}><b>{job.title}</b><small>{job.address}</small><em>{statusNames[job.status] || job.status}</em></button>) : <p className="no-jobs">Бригада свободна и готова к назначению.</p>}<h3>Закреплённые зоны</h3>{brigadeZones.length ? brigadeZones.map(zone => <div className="brigade-zone" key={zone.id}><b>{zone.name}</b><small>Приоритет {zone.priority} · {zone.points.length} вершин</small></div>) : <p className="no-jobs">Зоны для этой бригады не назначены.</p>}</aside>}</div></section>; }
  const copy: Record<string, [string,string]> = { analytics:["Динамика обращений","Сводные показатели по районам и службам"], sla:["Исполнение SLA","Контроль сроков и обращений под риском"], reports:["Отчёты смены","Выполненные работы и затраченное время"], notifications:["Центр уведомлений","Изменения статусов и новые назначения"], profile:["Профиль сотрудника","Доступы, контакты и настройки"], create:["Сообщить о проблеме","Опишите ситуацию и отметьте место"], admin:["Управление системой","Роли, справочники и интеграции"] };
  const [title, subtitle] = copy[section] || [pageTitles[section] || "Раздел", "Рабочее пространство городских служб"];
  return <section className="content-page"><div className="page-toolbar"><div><h2>{title}</h2><p>{subtitle}</p></div></div><div className="empty-state"><span>◎</span><h3>{title}</h3><p>Раздел подключён к навигации. Здесь отображаются данные, доступные для роли «{pageTitles[section] || section}».</p></div></section>;
}
