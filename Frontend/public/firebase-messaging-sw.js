self.addEventListener("notificationclick", (event) => {
  event.notification.close();

  const targetURL = new URL(
    event.notification.data?.url || "/?section=notifications",
    self.location.origin,
  ).href;

  event.waitUntil(
    clients.matchAll({ type: "window", includeUncontrolled: true }).then((windows) => {
      const existingWindow = windows.find((windowClient) =>
        windowClient.url.startsWith(self.location.origin),
      );

      if (existingWindow) {
        return existingWindow.navigate(targetURL).then(() => existingWindow.focus());
      }

      return clients.openWindow(targetURL);
    }),
  );
});

importScripts("https://www.gstatic.com/firebasejs/12.18.0/firebase-app-compat.js");
importScripts("https://www.gstatic.com/firebasejs/12.18.0/firebase-messaging-compat.js");

const parameters = new URL(self.location.href).searchParams;
const firebaseConfig = {
  apiKey: parameters.get("apiKey"),
  authDomain: parameters.get("authDomain"),
  projectId: parameters.get("projectId"),
  storageBucket: parameters.get("storageBucket"),
  messagingSenderId: parameters.get("messagingSenderId"),
  appId: parameters.get("appId"),
};

if (Object.values(firebaseConfig).every(Boolean)) {
  const firebaseSDK = self.firebase;
  firebaseSDK.initializeApp(firebaseConfig);

  firebaseSDK.messaging().onBackgroundMessage((payload) => {
    const data = payload.data || {};
    const title = payload.notification?.title || data.title || "Город рядом";

    self.registration.showNotification(title, {
      body: payload.notification?.body || data.body || "В системе появилось обновление.",
      icon: "/favicon.ico",
      badge: "/favicon.ico",
      data: {
        notificationId: data.notification_id,
        url: data.url || "/?section=notifications",
      },
      tag: data.notification_id || payload.messageId,
    });
  });
}
