"use client";

/* eslint-disable react-hooks/set-state-in-effect, jsx-a11y/no-autofocus */

import { FormEvent, useEffect, useState } from "react";

import { api, config, type Role, type Session } from "./api";

import { type Notice, type Department } from "./service-shared";

type UserProfile = {
  id: string;
  user_id: string;
  full_name: string;
  phone?: string;
  preferred_contact_method?: string;
};

type WorkProfile = {
  id: string;
  department_id: string;
  position: string;
  status: string;
  employee_number?: string;
};

type WorkerBrigade = {
  id: string;
  name: string;
  specialization?: string;
  status: string;
};

type WorkerMembership = { role: string; availability_status: string };

type ScheduleItem = { day_of_week: number; starts_at: string; ends_at: string };

export function ProfilePage({
  session,
  role,
  onNotice,
}: {
  session: Session;
  role: Role;
  onNotice: Notice;
}) {
  const demo = session.accessToken === "demo";
  const [profile, setProfile] = useState<UserProfile>(),
    [work, setWork] = useState<WorkProfile>();
  const [department, setDepartment] = useState<Department>(),
    [brigade, setBrigade] = useState<WorkerBrigade>(),
    [membership, setMembership] = useState<WorkerMembership>(),
    [schedule, setSchedule] = useState<ScheduleItem[]>([]);
  const [passwordOpen, setPasswordOpen] = useState(false),
    [passwordBusy, setPasswordBusy] = useState(false),
    [passwordError, setPasswordError] = useState("");
  useEffect(() => {
    const hasWorkProfile = role === "worker" || role === "dispatcher";

    if (demo) {
      setProfile({
        id: "demo-profile",
        user_id: "demo",
        full_name: "Демонстрационный пользователь",
        preferred_contact_method: "EMAIL",
      });

      if (hasWorkProfile) {
        const positions: Record<"worker" | "dispatcher", string> = {
          worker: "Специалист выездной бригады",
          dispatcher: "Диспетчер",
        };
        setWork({
          id: "demo-work",
          department_id: "dep-roads",
          position: positions[role],
          status: "ACTIVE",
        });
        setDepartment({ id: "dep-roads", name: "Дорожное хозяйство" });
      } else {
        setWork(undefined);
        setDepartment(undefined);
      }
      return;
    }

    void (async () => {
      try {
        const result = await api<{ user_profile: UserProfile }>(
          config.endpoints.profile,
          undefined,
          "GET",
          session.accessToken,
        );
        setProfile(result.user_profile);

        if (!hasWorkProfile) return;

        const workResult = await api<{
          details: { work_profile: WorkProfile } | WorkProfile;
        }>(
          config.endpoints.workProfileByUser,
          { user_id: session.user?.user_id },
          "POST",
          session.accessToken,
        );
        const details = workResult.details;
        const nextWork =
          "work_profile" in details ? details.work_profile : details;
        setWork(nextWork);

        const [departmentResult, brigadeResult] = await Promise.all([
          api<{ department: Department }>(
            config.endpoints.departmentsGet,
            { id: nextWork.department_id },
            "POST",
            session.accessToken,
          ),
          api<{ brigade: WorkerBrigade; member: WorkerMembership }>(
            config.endpoints.brigadeByUser,
            { user_id: session.user?.user_id, only_active: true },
            "POST",
            session.accessToken,
          ).catch(() => undefined),
        ]);
        setDepartment(departmentResult.department);

        if (!brigadeResult?.brigade) return;

        setBrigade(brigadeResult.brigade);
        setMembership(brigadeResult.member);
        const scheduleResult = await api<{ schedule: ScheduleItem[] }>(
          config.endpoints.brigadeSchedulesList,
          { brigade_id: brigadeResult.brigade.id, active: true },
          "POST",
          session.accessToken,
        ).catch(() => ({ schedule: [] }));
        setSchedule(scheduleResult.schedule || []);
      } catch (error) {
        onNotice(
          error instanceof Error
            ? error.message
            : "Не удалось загрузить профиль",
        );
      }
    })();
  }, [demo, onNotice, role, session.accessToken, session.user?.user_id]);
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!profile) return;
    const form = new FormData(event.currentTarget),
      next = {
        ...profile,
        full_name: String(form.get("full_name")),
        phone: String(form.get("phone")) || undefined,
        preferred_contact_method: String(form.get("preferred_contact_method")),
      };
    if (!demo) {
      const result = await api<{ user_profile: UserProfile }>(
        config.endpoints.userProfilesUpdate,
        {
          id: profile.id,
          full_name: next.full_name,
          phone: next.phone,
          clear_phone: !next.phone,
          preferred_contact_method: next.preferred_contact_method,
        },
        "POST",
        session.accessToken,
      );
      setProfile(result.user_profile);
    } else setProfile(next);
    onNotice("Профиль сохранён");
  }
  async function changePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget,
      form = new FormData(formElement),
      newPassword = String(form.get("new_password")),
      confirmPassword = String(form.get("confirm_password"));
    setPasswordError("");
    if (newPassword !== confirmPassword) {
      setPasswordError("Новые пароли не совпадают");
      return;
    }
    setPasswordBusy(true);
    try {
      if (!demo)
        await api(
          config.endpoints.changePassword,
          {
            old_password: String(form.get("old_password")),
            new_password: newPassword,
            revoke_other_sessions: form.has("revoke"),
          },
          "POST",
          session.accessToken,
        );
      formElement.reset();
      setPasswordOpen(false);
      onNotice("Пароль изменён");
    } catch (error) {
      setPasswordError(
        error instanceof Error ? error.message : "Не удалось изменить пароль",
      );
    } finally {
      setPasswordBusy(false);
    }
  }
  async function sendVerification() {
    if (!demo)
      await api(
        config.endpoints.sendVerificationEmail,
        { email: session.user?.email },
        "POST",
        session.accessToken,
      );
    onNotice("Письмо для подтверждения отправлено");
  }
  async function logoutAll() {
    if (!demo) {
      const result = await api<{ revoked_count: number }>(
        config.endpoints.logoutAll,
        {},
        "POST",
        session.accessToken,
      );
      onNotice(`Завершено сессий: ${result.revoked_count}`);
    }
  }
  const workStatus: Record<string, string> = {
      ACTIVE: "Активен",
      ON_SHIFT: "На смене",
      AVAILABLE: "Доступен",
      INACTIVE: "Неактивен",
    },
    memberRoles: Record<string, string> = {
      LEAD: "Бригадир",
      TECHNICIAN: "Специалист",
      DRIVER: "Водитель",
    },
    availability: Record<string, string> = {
      AVAILABLE: "Доступен",
      UNAVAILABLE: "Занят",
      ON_LEAVE: "В отпуске",
    };
  const dayNames = ["", "Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"],
    scheduleText = schedule.length
      ? `${schedule.map((item) => dayNames[item.day_of_week]).join(", ")} · ${schedule[0].starts_at.slice(0, 5)}–${schedule[0].ends_at.slice(0, 5)}`
      : "Не задан";
  return (
    <section className="content-page service-form-page">
      <div className="page-toolbar">
        <div>
          <h2>Профиль</h2>
          <p>Контактные данные, безопасность и рабочий статус</p>
        </div>
      </div>
      {profile ? (
        <div className="profile-sections">
          <form className="service-form" onSubmit={save}>
            <div className="profile-summary">
              <i>
                {profile.full_name
                  .split(" ")
                  .map((x) => x[0])
                  .join("")
                  .slice(0, 2)}
              </i>
              <div>
                <h3>{profile.full_name}</h3>
                <p>{session.user?.email}</p>
              </div>
            </div>
            <div className="form-grid">
              <label className="wide">
                ФИО
                <input
                  name="full_name"
                  defaultValue={profile.full_name}
                  required
                />
              </label>
              <label>
                Телефон
                <input name="phone" defaultValue={profile.phone || ""} />
              </label>
              <label>
                Предпочтительный канал
                <select
                  name="preferred_contact_method"
                  defaultValue={profile.preferred_contact_method || "EMAIL"}
                >
                  <option value="EMAIL">Email</option>
                  <option value="PHONE">Телефон</option>
                  <option value="IN_APP">В приложении</option>
                </select>
              </label>
            </div>
            {work && (
              <dl className="profile-work">
                <div>
                  <dt>Должность</dt>
                  <dd>{work.position}</dd>
                </div>
                <div>
                  <dt>Рабочий статус</dt>
                  <dd>{workStatus[work.status] || work.status}</dd>
                </div>
                <div>
                  <dt>Департамент</dt>
                  <dd>{department?.name || "Загружается…"}</dd>
                </div>
                {brigade && (
                  <>
                    <div>
                      <dt>Бригада</dt>
                      <dd>{brigade.name}</dd>
                    </div>
                    <div>
                      <dt>Роль в бригаде</dt>
                      <dd>
                        {memberRoles[membership?.role || ""] ||
                          membership?.role ||
                          "Сотрудник"}
                      </dd>
                    </div>
                    <div>
                      <dt>Доступность</dt>
                      <dd>
                        {availability[membership?.availability_status || ""] ||
                          membership?.availability_status ||
                          "Не указана"}
                      </dd>
                    </div>
                    <div className="profile-schedule">
                      <dt>График бригады</dt>
                      <dd>{scheduleText}</dd>
                    </div>
                  </>
                )}
              </dl>
            )}
            <button className="primary">Сохранить изменения</button>
          </form>
          <aside className="service-form security-form">
            <h3>Безопасность</h3>
            <p>
              Управляйте паролем, подтверждением почты и активными сессиями.
            </p>
            <button
              type="button"
              className="primary security-password-button"
              onClick={() => {
                setPasswordError("");
                setPasswordOpen(true);
              }}
            >
              Изменить пароль
            </button>
            <div className="security-actions">
              <button type="button" onClick={() => void sendVerification()}>
                Подтвердить email
              </button>
              <button
                type="button"
                className="danger-action"
                onClick={() => void logoutAll()}
              >
                Завершить все сессии
              </button>
            </div>
          </aside>
        </div>
      ) : (
        <p className="service-empty">Профиль загружается…</p>
      )}
      {passwordOpen && (
        <div
          className="password-modal-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget && !passwordBusy)
              setPasswordOpen(false);
          }}
        >
          <form
            className="password-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="password-modal-title"
            onSubmit={changePassword}
          >
            <button
              type="button"
              className="modal-close"
              aria-label="Закрыть"
              onClick={() => setPasswordOpen(false)}
              disabled={passwordBusy}
            >
              ×
            </button>
            <span className="eyebrow">Безопасность аккаунта</span>
            <h2 id="password-modal-title">Изменить пароль</h2>
            <p>Введите текущий пароль и дважды укажите новый.</p>
            <label>
              Текущий пароль
              <input
                name="old_password"
                type="password"
                autoComplete="current-password"
                placeholder="Введите текущий пароль"
                required
                autoFocus
              />
            </label>
            <label>
              Новый пароль
              <input
                name="new_password"
                type="password"
                autoComplete="new-password"
                placeholder="Не менее 8 символов"
                minLength={8}
                required
              />
            </label>
            <label>
              Повторите новый пароль
              <input
                name="confirm_password"
                type="password"
                autoComplete="new-password"
                placeholder="Введите новый пароль ещё раз"
                minLength={8}
                required
              />
            </label>
            {passwordError && (
              <div className="password-error" role="alert">
                {passwordError}
              </div>
            )}
            <label className="check">
              <input name="revoke" type="checkbox" defaultChecked /> Завершить
              другие активные сессии
            </label>
            <div className="password-modal-actions">
              <button
                type="button"
                className="ghost"
                onClick={() => setPasswordOpen(false)}
                disabled={passwordBusy}
              >
                Отмена
              </button>
              <button className="primary" disabled={passwordBusy}>
                {passwordBusy ? "Сохраняем…" : "Сохранить новый пароль"}
              </button>
            </div>
          </form>
        </div>
      )}
    </section>
  );
}
