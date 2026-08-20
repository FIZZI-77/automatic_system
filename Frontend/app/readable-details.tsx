import type { ReactNode } from "react";

type Details = Record<string, unknown>;

const labels: Record<string, string> = {
  id: "Идентификатор",
  ticket_id: "Заявка",
  ticket_sla: "Параметры SLA",
  ticket_sla_id: "Запись SLA",
  rule_id: "Регламент",
  department_id: "Департамент",
  category_id: "Категория заявки",
  brigade_id: "Бригада",
  route_id: "Маршрут",
  user_id: "Пользователь",
  actor_id: "Исполнитель",
  requested_by: "Инициатор",
  entity_id: "Объект",
  aggregate_id: "Связанный объект",
  asset_id: "Объект инфраструктуры",
  entity_type: "Тип объекта",
  event_id: "Событие",
  event_type: "Тип события",
  topic: "Источник события",
  action: "Действие",
  mode: "Режим назначения",
  status: "Статус",
  channel: "Канал доставки",
  subject: "Тема / получатель",
  body: "Сообщение",
  failure_reason: "Причина ошибки",
  error: "Ошибка",
  version: "Версия",
  revision: "Версия маршрута",
  attempts: "Количество попыток",
  priority: "Приоритет",
  risk_score: "Оценка риска",
  risk_level: "Уровень риска",
  failure_probability_90d: "Вероятность неисправности за 90 дней",
  probability: "Вероятность неисправности, %",
  score: "Оценка риска из 100",
  level: "Уровень риска",
  factors: "Факторы риска",
  recommended_action: "Рекомендация",
  calculated_at: "Время расчёта",
  active: "Активно",
  read: "Прочитано",
  response_breached: "Нарушен срок реакции",
  resolution_breached: "Нарушен срок выполнения",
  response_warning_sent: "Предупреждение о реакции отправлено",
  resolution_warning_sent: "Предупреждение о выполнении отправлено",
  response_deadline: "Срок реакции",
  resolution_deadline: "Срок выполнения",
  responded_at: "Ответ получен",
  completed_at: "Завершено",
  created_at: "Создано",
  updated_at: "Обновлено",
  occurred_at: "Время события",
  expires_at: "Действует до",
  next_attempt_at: "Следующая попытка",
  created_at_unix_ms: "Создано",
  updated_at_unix_ms: "Обновлено",
  expires_at_unix_ms: "Действует до",
  calculation: "Параметры маршрута",
  distance_meters: "Расстояние",
  duration_seconds: "Время в пути",
  geometry_geo_json: "Геометрия",
  latitude: "Широта",
  longitude: "Долгота",
  data: "Дополнительные данные",
  details: "Подробности",
  trace_id: "Трассировка",
  request_id: "Запрос",
};

const values: Record<string, string> = {
  AUTO: "Автоматически",
  AUTOMATIC: "Автоматически",
  MANUAL: "Вручную",
  ASSIGNED: "Назначено",
  PENDING: "Ожидает обработки",
  RESERVED: "Бригада зарезервирована",
  CONFIRMING: "Ожидает подтверждения",
  FAILED: "Ошибка",
  CANCELLED: "Отменено",
  EXPIRED: "Срок истёк",
  ACTIVE: "Активно",
  COMPLETED: "Завершено",
  PLANNED: "Запланировано",
  NEW: "Новая",
  IN_PROGRESS: "В работе",
  HIGH: "Высокий",
  MEDIUM: "Средний",
  LOW: "Низкий",
  EMERGENCY: "Экстренный",
  IN_APP: "В приложении",
  EMAIL: "Email",
  PUSH: "Push",
  SMS: "SMS",
  "RESOLUTION DEADLINE APPROACHING": "Срок выполнения заявки скоро истечёт",
  "RESOLUTION DEADLINE BREACHED": "Срок выполнения заявки нарушен",
  "RESPONSE DEADLINE APPROACHING": "Срок реакции на заявку скоро истечёт",
  "RESPONSE DEADLINE BREACHED": "Срок реакции на заявку нарушен",
};

function normalizedKey(key:string){return key.replace(/([a-zа-я0-9])([A-ZА-Я])/g,"$1_$2").replace(/[\s-]+/g,"_").toLowerCase()}

function fieldLabel(key: string) {
  const normalized=normalizedKey(key);
  if (labels[normalized]) return labels[normalized];
  const spaced = key.replace(/_/g, " ").replace(/([a-zа-я])([A-ZА-Я])/g, "$1 $2");
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

function isDateField(key: string) {
  const normalized=normalizedKey(key);
  return /(^|_)(created|updated|occurred|expires|completed|responded|calculated|deadline|attempt)_?(at|unix_ms)?$/i.test(normalized) || normalized.endsWith("_at") || normalized.endsWith("_unix_ms");
}

function dateValue(value: unknown) {
  let raw = value;
  if (typeof value === "object" && value !== null && "seconds" in value) raw = (value as { seconds?: unknown }).seconds;
  if (typeof raw === "string" && raw && !/^\d+$/.test(raw)) {
    const parsed = new Date(raw);
    return Number.isNaN(parsed.getTime()) ? null : parsed.toLocaleString("ru-RU");
  }
  const number = Number(raw);
  if (!Number.isFinite(number) || number <= 0) return null;
  return new Date(number > 10_000_000_000 ? number : number * 1000).toLocaleString("ru-RU");
}

function scalar(key: string, value: unknown): ReactNode {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "Да" : "Нет";
  if (isDateField(key)) return dateValue(value) || String(value);
  const normalized=normalizedKey(key);
  if (normalized === "distance_meters" && Number.isFinite(Number(value))) return `${Math.round(Number(value) / 10) / 100} км`;
  if (normalized === "duration_seconds" && Number.isFinite(Number(value))) return `${Math.max(1, Math.round(Number(value) / 60))} мин`;
  const source = String(value);
  return values[source.toUpperCase()] || source;
}

export function ReadableDetails({ data, className = "" }: { data: Details; className?: string }) {
  const sourceEntries = Object.entries(data).filter(([, value]) => value !== undefined && value !== null && value !== "");
  const presentKeys = new Set(sourceEntries.map(([key]) => normalizedKey(key)));
  const entries = sourceEntries.filter(([key]) => {
    const normalized = normalizedKey(key);
    if (!normalized.endsWith("_unix_ms")) return true;
    const canonical = normalized.replace(/_unix_ms$/, "");
    return !presentKeys.has(canonical);
  });
  if (!entries.length) return <p className="readable-details-empty">Дополнительных сведений нет.</p>;
  return <dl className={`readable-details ${className}`.trim()}>{entries.map(([key, value]) => {
    if (isDateField(key)) return <div className="readable-detail-row readable-detail-date" key={key}><dt>{fieldLabel(key)}</dt><dd>{scalar(key, value)}</dd></div>;
    if (Array.isArray(value)) return <div className="readable-detail-group" key={key}><dt>{fieldLabel(key)}</dt><dd>{value.length ? <ul>{value.map((item, index) => <li key={index}>{typeof item === "object" && item !== null ? <ReadableDetails data={item as Details} /> : scalar(key, item)}</li>)}</ul> : "—"}</dd></div>;
    if (typeof value === "object") return <div className="readable-detail-group" key={key}><dt>{fieldLabel(key)}</dt><dd><ReadableDetails data={value as Details} /></dd></div>;
    return <div className="readable-detail-row" key={key}><dt>{fieldLabel(key)}</dt><dd>{scalar(key, value)}</dd></div>;
  })}</dl>;
}
