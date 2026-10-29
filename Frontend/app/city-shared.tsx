"use client";

import { Position, Role } from "./api";

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
  { icon: string; label: string; id: string }[]
> = {
  user: [
    { icon: "⌂", label: "Обзор", id: "overview" },
    { icon: "◎", label: "Мои заявки", id: "tickets" },
    { icon: "＋", label: "Сообщить", id: "create" },
    { icon: "◌", label: "Уведомления", id: "notifications" },
    { icon: "◇", label: "Профиль", id: "profile" },
  ],
  worker: [
    { icon: "⌂", label: "Смена", id: "overview" },
    { icon: "✓", label: "Задания", id: "tickets" },
    { icon: "⌖", label: "Маршрут", id: "map" },
    { icon: "▤", label: "Отчёты", id: "reports" },
    { icon: "◇", label: "Профиль", id: "profile" },
  ],
  dispatcher: [
    { icon: "⌂", label: "Ситуационный центр", id: "overview" },
    { icon: "⌖", label: "Живая карта", id: "map" },
    { icon: "◎", label: "Инциденты", id: "tickets" },
    { icon: "♜", label: "Бригады", id: "brigades" },
    { icon: "▥", label: "SLA", id: "sla" },
    { icon: "⇄", label: "Операции", id: "operations" },
    { icon: "▤", label: "Отчёты", id: "reports" },
    { icon: "◊", label: "Уведомления", id: "notifications" },
  ],
  admin: [
    { icon: "⌂", label: "Показатели", id: "overview" },
    { icon: "◎", label: "Заявки", id: "tickets" },
    { icon: "♜", label: "Структура", id: "brigades" },
    { icon: "▦", label: "Аналитика", id: "analytics" },
    { icon: "▥", label: "SLA", id: "sla" },
    { icon: "▧", label: "Инфраструктура", id: "assets" },
    { icon: "⌘", label: "Регламенты", id: "catalog" },
    { icon: "✦", label: "Квалификации", id: "qualifications" },
    { icon: "◆", label: "Удостоверения", id: "certifications" },
    { icon: "⇄", label: "Операции", id: "operations" },
    { icon: "▤", label: "Отчёты", id: "reports" },
    { icon: "≡", label: "Аудит", id: "audit" },
    { icon: "⚙", label: "Управление", id: "admin" },
  ],
};

export const extraNavigation = { icon: "⌁", label: "Зоны бригад", id: "zones" };

export const managementNavigation = {
  icon: "⚙",
  label: "Управление",
  id: "management",
};

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
