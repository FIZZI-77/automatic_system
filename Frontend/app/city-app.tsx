"use client";

import { useEffect, useState } from "react";

import { useTheme } from "./use-theme";

import {
  api,
  config,
  loadSession,
  normalizeRole,
  Role,
  saveSession,
  SESSION_EXPIRED_EVENT,
  Session,
} from "./api";

import "./workspace-pages.css";

import "./i-moscow-theme.css";

import "./light-theme-balancing.css";

import { type AuthMode, AuthScreen } from "./auth-screen";

import { Landing } from "./landing-page";

import { DashboardV2 } from "./dashboard";

export function CityApp({
  initialAuthMode,
  initialToken,
}: { initialAuthMode?: AuthMode; initialToken?: string } = {}) {
  const [session, setSession] = useState<Session | null>(null);
  const [hydrated, setHydrated] = useState(false);
  const [showLogin, setShowLogin] = useState(Boolean(initialAuthMode));
  const [authMode, setAuthMode] = useState<AuthMode>(
    initialAuthMode || "login",
  );
  const [demoRole, setDemoRole] = useState<Role>("dispatcher");
  const [theme, toggleTheme] = useTheme();
  useEffect(() => {
    const handleSessionExpired = () => {
      setAuthMode("login");
      setShowLogin(true);
      setSession(null);
    };
    const timer = window.setTimeout(() => {
      setSession(loadSession());
      setHydrated(true);
    }, 0);
    window.addEventListener(SESSION_EXPIRED_EVENT, handleSessionExpired);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener(SESSION_EXPIRED_EVENT, handleSessionExpired);
    };
  }, []);
  if (!session && !showLogin)
    return (
      <Landing
        theme={theme}
        onToggleTheme={toggleTheme}
        interactive={hydrated}
        onLogin={() => {
          setAuthMode("login");
          setShowLogin(true);
        }}
        onRegister={() => {
          setAuthMode("register");
          setShowLogin(true);
        }}
        onDemo={(role) => {
          setDemoRole(role);
          setSession({
            accessToken: "demo",
            refreshToken: "",
            expiresAt: 0,
            user: {
              user_id: "demo",
              email: "demo@city.local",
              roles: [role],
              permissions: [],
              is_active: true,
              email_verified: true,
            },
          });
        }}
      />
    );
  if (!session)
    return (
      <>
        <button
          className="auth-theme-toggle landing-theme-toggle"
          aria-label={
            theme === "light" ? "Включить тёмную тему" : "Включить светлую тему"
          }
          onClick={toggleTheme}
        >
          {theme === "light" ? "◐ Тёмная" : "☀ Светлая"}
        </button>
        <AuthScreen
          initialMode={authMode}
          initialToken={initialToken}
          onBack={() => setShowLogin(false)}
          onSuccess={(next) => {
            saveSession(next);
            setSession(next);
          }}
        />
      </>
    );
  const role =
    session.accessToken === "demo"
      ? normalizeRole([demoRole])
      : normalizeRole(session.user?.roles);
  return (
    <DashboardV2
      theme={theme}
      onToggleTheme={toggleTheme}
      session={session}
      role={role}
      setDemoRole={setDemoRole}
      onExit={() => {
        if (session.accessToken !== "demo")
          void api(
            config.endpoints.logout,
            {},
            "POST",
            session.accessToken,
          ).catch(() => undefined);
        saveSession(null);
        setSession(null);
        setShowLogin(false);
      }}
    />
  );
}

export { LegacyDashboard } from "./legacy-dashboard";
