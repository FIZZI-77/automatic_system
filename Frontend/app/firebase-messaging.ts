import { getApp, getApps, initializeApp, type FirebaseOptions } from "firebase/app";
import {
  deleteToken,
  getMessaging,
  getToken,
  isSupported,
  onMessage,
  type MessagePayload,
} from "firebase/messaging";

export type PushMessage = {
  id: string;
  title: string;
  body: string;
  eventType?: string;
  createdAt: string;
};

const firebaseOptions: FirebaseOptions = {
  apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
  authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
  storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID,
};

const vapidKey = process.env.NEXT_PUBLIC_FIREBASE_VAPID_KEY;

function missingConfiguration(): string[] {
  return Object.entries({
    NEXT_PUBLIC_FIREBASE_API_KEY: firebaseOptions.apiKey,
    NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN: firebaseOptions.authDomain,
    NEXT_PUBLIC_FIREBASE_PROJECT_ID: firebaseOptions.projectId,
    NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID: firebaseOptions.messagingSenderId,
    NEXT_PUBLIC_FIREBASE_APP_ID: firebaseOptions.appId,
    NEXT_PUBLIC_FIREBASE_VAPID_KEY: vapidKey,
  })
    .filter(([, value]) => !value)
    .map(([name]) => name);
}

function serviceWorkerURL(): string {
  const parameters = new URLSearchParams();

  Object.entries(firebaseOptions).forEach(([name, value]) => {
    if (value) {
      parameters.set(name, String(value));
    }
  });

  return `/firebase-messaging-sw.js?${parameters.toString()}`;
}

async function messagingRegistration(): Promise<ServiceWorkerRegistration> {
  const registration = await navigator.serviceWorker.register(serviceWorkerURL(), {
    scope: "/",
  });

  await navigator.serviceWorker.ready;
  return registration;
}

async function configuredMessaging() {
  if (typeof window === "undefined") {
    throw new Error("Push-уведомления доступны только в браузере");
  }

  const missing = missingConfiguration();
  if (missing.length > 0) {
    throw new Error(`Не заданы параметры Firebase: ${missing.join(", ")}`);
  }

  if (!(await isSupported())) {
    throw new Error("Этот браузер не поддерживает push-уведомления");
  }

  const app = getApps().length > 0 ? getApp() : initializeApp(firebaseOptions);
  return getMessaging(app);
}

export function pushPermission(): NotificationPermission | "unsupported" {
  if (typeof window === "undefined" || !("Notification" in window)) {
    return "unsupported";
  }

  return Notification.permission;
}

export async function obtainPushToken(requestPermission: boolean): Promise<string> {
  const messaging = await configuredMessaging();
  let permission = Notification.permission;

  if (permission === "default" && requestPermission) {
    permission = await Notification.requestPermission();
  }

  if (permission !== "granted") {
    throw new Error(
      permission === "denied"
        ? "Уведомления запрещены в настройках браузера"
        : "Разрешение на уведомления не предоставлено",
    );
  }

  const registration = await messagingRegistration();
  const token = await getToken(messaging, {
    serviceWorkerRegistration: registration,
    vapidKey,
  });

  if (!token) {
    throw new Error("Firebase не вернул токен устройства");
  }

  return token;
}

export async function removePushToken(): Promise<void> {
  const messaging = await configuredMessaging();
  await deleteToken(messaging);
}

export async function subscribeToForegroundMessages(
  listener: (message: PushMessage) => void,
): Promise<() => void> {
  const messaging = await configuredMessaging();

  return onMessage(messaging, (payload) => listener(toPushMessage(payload)));
}

function toPushMessage(payload: MessagePayload): PushMessage {
  const data = payload.data ?? {};

  return {
    id: data.notification_id || payload.messageId || crypto.randomUUID(),
    title: payload.notification?.title || data.title || "Новое уведомление",
    body: payload.notification?.body || data.body || "В системе появилось обновление.",
    eventType: data.event_type,
    createdAt: new Date().toISOString(),
  };
}
