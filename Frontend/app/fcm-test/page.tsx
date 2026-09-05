"use client";

import { useState } from "react";
import { initializeApp, getApps } from "firebase/app";
import { getMessaging, getToken } from "firebase/messaging";

const firebaseConfig = {
    apiKey: "AIzaSyAwRnAOApwimP_1_bsk4yRVH5ZbBtnAfhk",
    authDomain: "automatic-city-system.firebaseapp.com",
    projectId: "automatic-city-system",
    storageBucket: "automatic-city-system.firebasestorage.app",
    messagingSenderId: "659686870425",
    appId: "1:659686870425:web:8ecf0d709c8656a795d708",
    measurementId: "G-GX1GJ1RE2T"
};

const VAPID_KEY = "BH-3UDkqCZUf4mRwBC0CqelSsSh6K92pHZDHr5Re6sRU9CnDQsIQGi-bFT4JHQ_9aws7eXf03GHc6nKJfrorKDo";

export default function FCMTestPage() {
    const [token, setToken] = useState("");
    const [error, setError] = useState("");

    async function generateToken() {
        try {
            setError("");

            const permission = await Notification.requestPermission();

            if (permission !== "granted") {
                throw new Error("Разрешение на уведомления не предоставлено");
            }

            const registration = await navigator.serviceWorker.register(
                "/firebase-messaging-sw.js"
            );

            const app =
                getApps().length > 0
                    ? getApps()[0]
                    : initializeApp(firebaseConfig);

            const messaging = getMessaging(app);

            const currentToken = await getToken(messaging, {
                vapidKey: VAPID_KEY,
                serviceWorkerRegistration: registration,
            });

            if (!currentToken) {
                throw new Error("Firebase не вернул registration token");
            }

            setToken(currentToken);
            console.log("FCM TOKEN:", currentToken);
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
        }
    }

    return (
        <main style={{ padding: 40 }}>
            <h1>FCM test</h1>

            <button onClick={generateToken}>
                Получить FCM token
            </button>

            {token && (
                <>
                    <h2>Token</h2>
                    <textarea
                        value={token}
                        readOnly
                        rows={10}
                        style={{ width: "100%" }}
                    />
                </>
            )}

            {error && <pre>{error}</pre>}
        </main>
    );
}