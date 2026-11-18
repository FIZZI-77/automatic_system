"use client";

/* eslint-disable jsx-a11y/anchor-is-valid */

import { FormEvent, useEffect, useRef, useState } from "react";

import { api, config, CurrentUser, Session } from "./api";

export type AuthMode = "login" | "register" | "forgot" | "reset" | "verify";

export function AuthScreen({
  initialMode,
  initialToken,
  onBack,
  onSuccess,
}: {
  initialMode: AuthMode;
  initialToken?: string;
  onBack: () => void;
  onSuccess: (s: Session) => void;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [passwordRepeat, setPasswordRepeat] = useState("");
  const [username, setUsername] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState<AuthMode>(initialMode);
  const [token, setToken] = useState(initialToken || "");
  const autoVerifyStarted = useRef(false);
  useEffect(() => {
    if (!initialToken || !["reset", "verify"].includes(initialMode)) return;
    window.history.replaceState(null, "", "/");
  }, [initialMode, initialToken]);
  useEffect(() => {
    if (initialMode !== "verify" || !initialToken || autoVerifyStarted.current)
      return;
    autoVerifyStarted.current = true;
    setLoading(true);
    setError("");
    void api(config.endpoints.verifyEmail, { token: initialToken })
      .then(() => {
        setMessage("Email подтверждён. Теперь можно войти.");
        setMode("login");
        setToken("");
      })
      .catch((requestError) =>
        setError(
          requestError instanceof Error
            ? requestError.message
            : "Не удалось подтвердить email",
        ),
      )
      .finally(() => setLoading(false));
  }, [initialMode, initialToken]);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const login = await api<{
        access_token: string;
        refresh_token: string;
        access_expires_at_unix: number;
      }>(config.endpoints.login, { email, password, client_id: "city-web" });
      const user = await api<CurrentUser>(
        config.endpoints.me,
        undefined,
        "GET",
        login.access_token,
      );
      onSuccess({
        accessToken: login.access_token,
        refreshToken: login.refresh_token,
        expiresAt: login.access_expires_at_unix,
        user,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось войти");
    } finally {
      setLoading(false);
    }
  }
  async function register(e: FormEvent) {
    e.preventDefault();
    setError("");
    setMessage("");
    if (password !== passwordRepeat) {
      setError("Пароли не совпадают");
      return;
    }
    setLoading(true);
    try {
      await api(config.endpoints.register, { email, password, username });
      setMessage("Аккаунт создан. Теперь войдите с указанными данными.");
      setMode("login");
      setPassword("");
      setPasswordRepeat("");
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Не удалось зарегистрироваться",
      );
    } finally {
      setLoading(false);
    }
  }
  async function recover(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      if (mode === "forgot") {
        await api(config.endpoints.requestPasswordReset, { email });
        setMode("reset");
      } else if (mode === "reset") {
        await api(config.endpoints.resetPassword, {
          token,
          new_password: password,
        });
        setMode("login");
        setToken("");
        setPassword("");
      } else if (mode === "verify") {
        await api(config.endpoints.verifyEmail, { token });
        setMode("login");
        setToken("");
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Операция не выполнена");
    } finally {
      setLoading(false);
    }
  }
  const heading =
    mode === "login"
      ? "Вход в систему"
      : mode === "register"
        ? "Создание аккаунта"
        : mode === "forgot"
          ? "Восстановление пароля"
          : mode === "reset"
            ? "Новый пароль"
            : "Подтверждение email";
  return (
    <main className="auth-page">
      <div className="auth-cubes" aria-hidden="true">
        <span className="auth-cube cube-one">
          <i />
          <i />
          <i />
          <i />
          <i />
          <i />
        </span>
        <span className="auth-cube cube-two">
          <i />
          <i />
          <i />
          <i />
          <i />
          <i />
        </span>
        <span className="auth-cube cube-three">
          <i />
          <i />
          <i />
          <i />
          <i />
          <i />
        </span>
      </div>
      <button className="back" onClick={onBack}>
        ← На главную
      </button>
      <form
        className="auth-card"
        onSubmit={
          mode === "login" ? submit : mode === "register" ? register : recover
        }
      >
        <a className="brand" href="#">
          <span>Г</span>Город рядом
        </a>
        <div>
          <div className="eyebrow auth-eyebrow">Учётная запись</div>
          <h2>{heading}</h2>
          <p>
            {mode === "login"
              ? "Используйте учётную запись городских сервисов."
              : mode === "register"
                ? "Зарегистрируйтесь как житель, чтобы создавать обращения и следить за их выполнением."
                : mode === "forgot"
                  ? "Укажите email — сервис отправит ссылку с токеном."
                  : "Введите токен, полученный в письме."}
          </p>
        </div>
        {mode === "register" && (
          <label>
            Имя пользователя
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Не менее 3 символов"
              minLength={3}
              maxLength={100}
              required
            />
          </label>
        )}
        {["login", "register", "forgot"].includes(mode) && (
          <label>
            Электронная почта
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="name@example.ru"
              required
            />
          </label>
        )}
        {["reset", "verify"].includes(mode) && (
          <label>
            Токен
            <input
              value={token}
              onChange={(e) => setToken(e.target.value)}
              required
            />
          </label>
        )}
        {["login", "register", "reset"].includes(mode) && (
          <label>
            {mode === "login" ? "Пароль" : "Новый пароль"}
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Не менее 8 символов"
              minLength={8}
              required
            />
          </label>
        )}
        {mode === "register" && (
          <label>
            Повторите пароль
            <input
              type="password"
              value={passwordRepeat}
              onChange={(e) => setPasswordRepeat(e.target.value)}
              placeholder="Повторите пароль"
              minLength={8}
              required
            />
          </label>
        )}
        {error && <div className="form-error">{error}</div>}
        {message && <div className="form-success">{message}</div>}
        <button className="primary" disabled={loading}>
          {loading
            ? "Выполняем…"
            : mode === "login"
              ? "Войти"
              : mode === "register"
                ? "Зарегистрироваться"
                : mode === "forgot"
                  ? "Отправить письмо"
                  : mode === "reset"
                    ? "Сменить пароль"
                    : "Подтвердить"}
        </button>
        <div className="auth-links">
          {mode === "login" ? (
            <>
              <button type="button" onClick={() => setMode("forgot")}>
                Забыли пароль?
              </button>
              <button type="button" onClick={() => setMode("verify")}>
                Подтвердить email
              </button>
            </>
          ) : (
            <button type="button" onClick={() => setMode("login")}>
              Вернуться ко входу
            </button>
          )}
        </div>
        {mode === "login" && (
          <div className="auth-register-callout">
            <span>Ещё нет аккаунта?</span>
            <button
              type="button"
              onClick={() => {
                setError("");
                setMessage("");
                setMode("register");
              }}
            >
              Зарегистрироваться
            </button>
          </div>
        )}
        <small>
          {mode === "register"
            ? "После регистрации назначается роль «Житель». Рабочие роли создаёт администратор."
            : "Роль и доступ определяются сервером после входа."}
        </small>
      </form>
    </main>
  );
}
