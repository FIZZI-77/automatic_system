"use client";

/* eslint-disable react-hooks/set-state-in-effect, react-hooks/exhaustive-deps */

import { FormEvent, useEffect, useState } from "react";

import { api, config, type Session } from "./api";

import {
  obtainPushToken,
  pushPermission,
  removePushToken,
  subscribeToForegroundMessages,
  type PushMessage,
} from "./firebase-messaging";

import { type ProtoTimestamp, type Notice } from "./service-shared";

type Notification = {
  id: string;
  title: string;
  body: string;
  event_type?: string;
  read?: boolean;
  read_at?: string | ProtoTimestamp;
  created_at?: string | number | ProtoTimestamp;
};

const notificationCopy: Record<string, { title: string; body: string }> = {
  "ticket.created": {
    title: "Заявка создана",
    body: "Мы получили заявку и передали её городской службе.",
  },
  "ticket.assigned": {
    title: "Бригада назначена",
    body: "Для выполнения заявки назначена ответственная бригада.",
  },
  "ticket.status_changed": {
    title: "Статус заявки изменён",
    body: "По вашей заявке появился новый статус.",
  },
  "ticket.completed": {
    title: "Заявка выполнена",
    body: "Работы по заявке завершены.",
  },
  "ticket.canceled": {
    title: "Заявка отменена",
    body: "Выполнение заявки было отменено.",
  },
  "ticket.completion_report.generated.v1": {
    title: "Отчёт готов",
    body: "Отчёт о выполнении заявки сформирован.",
  },
  "ticket.completion_report.failed.v1": {
    title: "Отчёт задерживается",
    body: "Не удалось сформировать отчёт. Система повторит попытку.",
  },
};

function notificationDate(value: Notification["created_at"]) {
  if (value == null) return "";
  if (typeof value === "object") {
    const seconds = Number(value.seconds);
    return Number.isFinite(seconds)
      ? new Date(seconds * 1000).toLocaleString("ru-RU")
      : "";
  }
  const numeric = typeof value === "number" ? value : Number(value);
  const date = Number.isFinite(numeric)
    ? new Date(numeric < 10_000_000_000 ? numeric * 1000 : numeric)
    : new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleString("ru-RU");
}

function userFacingNotification(item: Notification) {
  return (
    !item.event_type || Boolean(notificationCopy[item.event_type.toLowerCase()])
  );
}

function notificationTitle(item: Notification) {
  return (
    notificationCopy[item.event_type?.toLowerCase() || ""]?.title ||
    item.title ||
    "Обновление заявки"
  );
}

function notificationBody(item: Notification) {
  const fallback = notificationCopy[item.event_type?.toLowerCase() || ""]?.body;
  return item.body && !item.body.startsWith("Событие ")
    ? item.body
    : fallback || "По вашей заявке есть обновление.";
}

type PushState =
  "idle" | "enabling" | "enabled" | "denied" | "unsupported" | "error";

function pushDeviceStorageKey(session: Session): string {
  return `automatic-system:fcm-device:${session.user?.user_id || "current"}`;
}

function notificationFromPush(message: PushMessage): Notification {
  return {
    id: message.id,
    title: message.title,
    body: message.body,
    event_type: message.eventType,
    created_at: message.createdAt,
  };
}

export function NotificationsPage({
  session,
  onNotice,
}: {
  session: Session;
  onNotice: Notice;
}) {
  const demo = session.accessToken === "demo";
  const [items, setItems] = useState<Notification[]>([]);
  const [preferences, setPreferences] = useState({
    in_app_enabled: true,
    push_enabled: false,
    email_enabled: true,
    sms_enabled: false,
  });
  const [live, setLive] = useState(false);
  const [deviceId, setDeviceId] = useState("");
  const [pushState, setPushState] = useState<PushState>(() => {
    const permission = pushPermission();
    if (permission === "unsupported") return "unsupported";
    if (permission === "denied") return "denied";
    return permission === "granted" ? "enabling" : "idle";
  });
  const [pushError, setPushError] = useState("");
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [notificationQuery, setNotificationQuery] = useState("");

  useEffect(() => {
    if (demo) {
      setItems([
        {
          id: "demo-n1",
          title: "Бригада назначена",
          body: "Заявка принята в работу",
          created_at: new Date().toISOString(),
        },
      ]);
      return;
    }

    void (async () => {
      try {
        const [list, savedPreferences] = await Promise.all([
          api<{ notifications: Notification[] }>(
            config.endpoints.notifications,
            { unread_only: unreadOnly, limit: 100, offset: 0 },
            "POST",
            session.accessToken,
          ),
          api<{ preferences: typeof preferences }>(
            config.endpoints.notificationPreferencesGet,
            {},
            "POST",
            session.accessToken,
          ),
        ]);

        setItems(list.notifications || []);
        if (savedPreferences.preferences) {
          setPreferences(savedPreferences.preferences);
        }
      } catch (error) {
        onNotice(
          error instanceof Error
            ? error.message
            : "Не удалось загрузить уведомления",
        );
      }
    })();
  }, [demo, onNotice, session.accessToken, unreadOnly]);

  useEffect(() => {
    if (demo) return;

    const separator = config.wsUrl.includes("?") ? "&" : "?";
    const socket = new WebSocket(
      `${config.wsUrl}${separator}access_token=${encodeURIComponent(session.accessToken)}`,
    );

    socket.onopen = () => setLive(true);
    socket.onclose = () => setLive(false);
    socket.onmessage = (event) => {
      try {
        const notification = JSON.parse(event.data) as Notification;
        setItems((current) => [
          notification,
          ...current.filter((item) => item.id !== notification.id),
        ]);
      } catch {
        onNotice("Получено новое уведомление");
      }
    };

    return () => socket.close();
  }, [demo, onNotice, session.accessToken]);

  useEffect(() => {
    if (demo) return;

    let unsubscribe: (() => void) | undefined;
    void subscribeToForegroundMessages((message) => {
      const notification = notificationFromPush(message);
      setItems((current) => [
        notification,
        ...current.filter((item) => item.id !== notification.id),
      ]);
      onNotice(`${message.title}: ${message.body}`);
    })
      .then((stop) => {
        unsubscribe = stop;
      })
      .catch(() => undefined);

    return () => unsubscribe?.();
  }, [demo, onNotice]);

  useEffect(() => {
    if (demo || pushPermission() !== "granted") return;

    let active = true;
    void registerBrowserPush(false, false).catch(() => {
      if (active) setPushState("error");
    });

    return () => {
      active = false;
    };
  }, [demo, session.accessToken, session.user?.user_id]);

  async function registerBrowserPush(
    requestPermission: boolean,
    notify = true,
  ): Promise<void> {
    if (demo) return;

    setPushState("enabling");
    setPushError("");

    try {
      const token = await obtainPushToken(requestPermission);
      const result = await api<{ device: { id: string } }>(
        config.endpoints.notificationDevicesRegister,
        { token, platform: "WEB" },
        "POST",
        session.accessToken,
      );

      setDeviceId(result.device.id);
      localStorage.setItem(pushDeviceStorageKey(session), result.device.id);
      setPushState("enabled");

      if (requestPermission && !preferences.push_enabled) {
        const nextPreferences = { ...preferences, push_enabled: true };
        await api(
          config.endpoints.notificationPreferencesUpdate,
          nextPreferences,
          "POST",
          session.accessToken,
        );
        setPreferences(nextPreferences);
      }

      if (notify) onNotice("Push-уведомления подключены");
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Не удалось подключить уведомления";
      setPushError(message);
      setPushState(pushPermission() === "denied" ? "denied" : "error");
      if (notify) onNotice(message);
      throw error;
    }
  }

  async function disableBrowserPush(): Promise<void> {
    if (demo) return;

    try {
      const savedDeviceId =
        deviceId || localStorage.getItem(pushDeviceStorageKey(session));
      if (savedDeviceId) {
        await api(
          config.endpoints.notificationDevicesDelete,
          { device_id: savedDeviceId },
          "POST",
          session.accessToken,
        );
      }

      await removePushToken();
      localStorage.removeItem(pushDeviceStorageKey(session));
      setDeviceId("");
      setPushState("idle");

      if (preferences.push_enabled) {
        const nextPreferences = { ...preferences, push_enabled: false };
        await api(
          config.endpoints.notificationPreferencesUpdate,
          nextPreferences,
          "POST",
          session.accessToken,
        );
        setPreferences(nextPreferences);
      }

      onNotice("Push-уведомления отключены");
    } catch (error) {
      onNotice(
        error instanceof Error
          ? error.message
          : "Не удалось отключить уведомления",
      );
    }
  }

  async function read(id: string): Promise<void> {
    if (!demo) {
      await api(
        config.endpoints.notificationsRead,
        { notification_id: id },
        "POST",
        session.accessToken,
      );
    }
    setItems((value) =>
      value.map((item) =>
        item.id === id ? { ...item, read_at: new Date().toISOString() } : item,
      ),
    );
  }

  async function readAll(): Promise<void> {
    if (!demo) {
      await api(
        config.endpoints.notificationsReadAll,
        {},
        "POST",
        session.accessToken,
      );
    }
    setItems((value) =>
      value.map((item) => ({
        ...item,
        read_at: item.read_at || new Date().toISOString(),
      })),
    );
  }

  async function savePreferences(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const nextPreferences = {
      in_app_enabled: form.has("in_app_enabled"),
      push_enabled: form.has("push_enabled"),
      email_enabled: form.has("email_enabled"),
      sms_enabled: form.has("sms_enabled"),
    };

    if (!demo) {
      await api(
        config.endpoints.notificationPreferencesUpdate,
        nextPreferences,
        "POST",
        session.accessToken,
      );
    }
    setPreferences(nextPreferences);
    onNotice("Настройки уведомлений сохранены");
  }

  const visibleItems = items
    .filter(userFacingNotification)
    .filter((item) => !unreadOnly || (!item.read_at && !item.read))
    .filter(
      (item) =>
        !notificationQuery.trim() ||
        `${item.title} ${item.body || ""} ${item.id}`
          .toLocaleLowerCase("ru-RU")
          .includes(notificationQuery.trim().toLocaleLowerCase("ru-RU")),
    );
  const pushStatus = {
    idle: "Не подключены",
    enabling: "Подключение…",
    enabled: "Подключены к этому браузеру",
    denied: "Запрещены в браузере",
    unsupported: "Не поддерживаются браузером",
    error: pushError || "Ошибка подключения",
  }[pushState];

  return (
    <section className="content-page service-split-page">
      <div className="page-toolbar">
        <div>
          <h2>Центр уведомлений</h2>
          <p>
            <span className={`live-indicator ${live ? "connected" : ""}`}>
              ● {live ? "Онлайн-канал подключён" : "Онлайн-канал отключён"}
            </span>{" "}
            · важные обновления по вашим заявкам
          </p>
        </div>
        <button className="ghost" onClick={() => void readAll()}>
          Прочитать все
        </button>
      </div>
      <div className="service-filters">
        <label className="filter-search">
          Поиск
          <input
            value={notificationQuery}
            onChange={(event) => setNotificationQuery(event.target.value)}
            placeholder="Заголовок или текст уведомления"
          />
        </label>
        <label className="check-filter">
          <input
            type="checkbox"
            checked={unreadOnly}
            onChange={(event) => setUnreadOnly(event.target.checked)}
          />
          Только непрочитанные
        </label>
        <button
          onClick={() => {
            setUnreadOnly(false);
            setNotificationQuery("");
          }}
        >
          Сбросить
        </button>
      </div>
      <div className="service-split">
        <div className="notification-list">
          {visibleItems.length ? (
            visibleItems.map((item) => (
              <button
                key={item.id}
                className={item.read_at || item.read ? "read" : "unread"}
                onClick={() => void read(item.id)}
              >
                <i>●</i>
                <span>
                  <b>{notificationTitle(item)}</b>
                  <small>{notificationBody(item)}</small>
                </span>
                <time>{notificationDate(item.created_at)}</time>
              </button>
            ))
          ) : (
            <p className="service-empty">
              По выбранному фильтру уведомлений нет.
            </p>
          )}
        </div>
        <div>
          <form className="settings-card" onSubmit={savePreferences}>
            <h3>Каналы доставки</h3>
            {(
              [
                ["in_app_enabled", "В приложении"],
                ["push_enabled", "Push"],
                ["email_enabled", "Email"],
                ["sms_enabled", "SMS"],
              ] as const
            ).map(([key, label]) => (
              <label key={key}>
                <input
                  type="checkbox"
                  name={key}
                  checked={preferences[key]}
                  onChange={(event) =>
                    setPreferences((current) => ({
                      ...current,
                      [key]: event.target.checked,
                    }))
                  }
                />
                <span>{label}</span>
              </label>
            ))}
            <button className="primary">Сохранить</button>
          </form>
          <section
            className="settings-card device-card"
            aria-labelledby="push-device-title"
          >
            <h3 id="push-device-title">Push-уведомления</h3>
            <p className={`push-device-status ${pushState}`}>{pushStatus}</p>
            {pushState === "enabled" ? (
              <button
                type="button"
                className="danger-action"
                onClick={() => void disableBrowserPush()}
              >
                Отключить
              </button>
            ) : (
              <button
                type="button"
                className="ghost"
                disabled={
                  pushState === "enabling" || pushState === "unsupported"
                }
                onClick={() => void registerBrowserPush(true)}
              >
                {pushState === "enabling"
                  ? "Подключаем…"
                  : "Подключить браузер"}
              </button>
            )}
          </section>
        </div>
      </div>
    </section>
  );
}
