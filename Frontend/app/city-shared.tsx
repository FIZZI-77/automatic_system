"use client";

import { Position, Role } from "./api";
import type { NavigationIconName } from "./navigation-icon";

export const roleNames: Record<Role, string> = {
  user: "Житель",
  worker: "Работник",
  dispatcher: "Диспетчер",
  admin: "Администратор",
};

export const statusNames: Record<string, string> = {
  NEW: "Новая",
  ASSIGNED: "Назначена",
  IN_PROGRESS: "В работе",
  DONE: "Завершена",
  CANCELED: "Отменена",
};

export const operationalStatuses = new Set([
  "ACTIVE",
  "AVAILABLE",
  "BUSY",
  "ON_ROUTE",
  "ON_SITE",
]);

const vehicleFreshnessSeconds = 120;

export function hasFreshPosition(vehicle: Position) {
  return (
    Number(vehicle.recorded_at) >= Date.now() / 1000 - vehicleFreshnessSeconds
  );
}

export function pluralRu(
  value: number,
  one: string,
  few: string,
  many: string,
) {
  const mod100 = value % 100,
    mod10 = value % 10;
  return mod100 >= 11 && mod100 <= 14
    ? many
    : mod10 === 1
      ? one
      : mod10 >= 2 && mod10 <= 4
        ? few
        : many;
}

export const navByRole: Record<
  Role,
  { icon: NavigationIconName; label: string; id: string }[]
> = {
  user: [
    { icon: "home", label: "Обзор", id: "overview" },
    { icon: "clipboard", label: "Мои заявки", id: "tickets" },
    { icon: "plus", label: "Сообщить", id: "create" },
    { icon: "bell", label: "Уведомления", id: "notifications" },
    { icon: "user", label: "Профиль", id: "profile" },
  ],
  worker: [
    { icon: "home", label: "Смена", id: "overview" },
    { icon: "clipboard", label: "Задания", id: "tickets" },
    { icon: "map", label: "Маршрут", id: "map" },
    { icon: "report", label: "Отчёты", id: "reports" },
    { icon: "bell", label: "Уведомления", id: "notifications" },
    { icon: "user", label: "Профиль", id: "profile" },
  ],
  dispatcher: [
    { icon: "home", label: "Ситуационный центр", id: "overview" },
    { icon: "map", label: "Живая карта", id: "map" },
    { icon: "clipboard", label: "Инциденты", id: "tickets" },
    { icon: "users", label: "Бригады", id: "brigades" },
    { icon: "clock", label: "SLA", id: "sla" },
    { icon: "checklist", label: "Операции", id: "operations" },
    { icon: "report", label: "Отчёты", id: "reports" },
    { icon: "bell", label: "Уведомления", id: "notifications" },
  ],
  admin: [
    { icon: "home", label: "Показатели", id: "overview" },
    { icon: "clipboard", label: "Заявки", id: "tickets" },
    { icon: "users", label: "Структура", id: "brigades" },
    { icon: "chart", label: "Аналитика", id: "analytics" },
    { icon: "clock", label: "SLA", id: "sla" },
    { icon: "building", label: "Инфраструктура", id: "assets" },
    { icon: "book", label: "Регламенты", id: "catalog" },
    { icon: "graduation", label: "Квалификации", id: "qualifications" },
    { icon: "badge", label: "Удостоверения", id: "certifications" },
    { icon: "checklist", label: "Операции", id: "operations" },
    { icon: "report", label: "Отчёты", id: "reports" },
    { icon: "history", label: "Аудит", id: "audit" },
    { icon: "bell", label: "Уведомления", id: "notifications" },
    { icon: "settings", label: "Управление", id: "admin" },
  ],
};

export const extraNavigation = { icon: "zones", label: "Зоны бригад", id: "zones" } as const;

export const managementNavigation = {
  icon: "settings",
  label: "Управление",
  id: "management",
} as const;

export const pageTitles: Record<string, string> = {
  overview: "Ситуационный центр",
  map: "Живая карта",
  tickets: "Заявки и инциденты",
  brigades: "Городские бригады",
  zones: "Зоны обслуживания",
  analytics: "Аналитика",
  sla: "Контроль SLA",
  assets: "Городская инфраструктура",
  catalog: "Регламенты и категории",
  qualifications: "Квалификации",
  certifications: "Удостоверения и допуски",
  operations: "Операционный контроль",
  reports: "Отчёты",
  audit: "Журнал аудита",
  profile: "Профиль",
  notifications: "Уведомления",
  create: "Новая заявка",
  admin: "Управление",
  management: "Управление",
  structure: "Структура",
};
