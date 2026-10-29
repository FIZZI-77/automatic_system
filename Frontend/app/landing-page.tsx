"use client";

import { type Theme } from "./use-theme";

import { Role } from "./api";

export function Landing({
  theme,
  onToggleTheme,
  interactive,
  onLogin,
  onRegister,
  onDemo,
}: {
  theme: Theme;
  onToggleTheme: () => void;
  interactive: boolean;
  onLogin: () => void;
  onRegister: () => void;
  onDemo: (role: Role) => void;
}) {
  return (
    <main className={`landing theme-${theme}`} data-theme={theme}>
      <nav className="landing-nav">
        <a className="brand" href="#top">
          <span>Г</span>Город рядом
        </a>
        <div className="landing-links">
          <a href="#how">Как это работает</a>
          <a href="#services">Возможности</a>
          <button
            className="landing-theme-toggle"
            aria-label={
              theme === "light"
                ? "Включить тёмную тему"
                : "Включить светлую тему"
            }
            title={theme === "light" ? "Тёмная тема" : "Светлая тема"}
            onClick={onToggleTheme}
          >
            <span aria-hidden="true">{theme === "light" ? "◐" : "☀"}</span>
            <b>{theme === "light" ? "Тёмная" : "Светлая"}</b>
          </button>
          <button
            className="text-button"
            disabled={!interactive}
            onClick={onLogin}
          >
            Войти
          </button>
          <button
            className="nav-register"
            disabled={!interactive}
            onClick={onRegister}
          >
            Регистрация
          </button>
          <button
            className="primary small"
            disabled={!interactive}
            onClick={() => onDemo("dispatcher")}
          >
            Открыть демо
          </button>
        </div>
      </nav>
      <section className="hero" id="top">
        <div className="hero-copy">
          <div className="eyebrow">Единая цифровая городская служба</div>
          <h1>
            Город слышит.
            <br />
            <em>Службы действуют.</em>
          </h1>
          <p>
            Сообщайте о проблемах, следите за исполнением и наблюдайте, как
            город становится лучше — в одном понятном пространстве.
          </p>
          <div className="hero-actions">
            <button
              className="primary"
              disabled={!interactive}
              onClick={() => onDemo("user")}
            >
              Сообщить о проблеме <b>→</b>
            </button>
            <button
              className="ghost"
              disabled={!interactive}
              onClick={() => onDemo("dispatcher")}
            >
              Посмотреть живую карту
            </button>
          </div>
          <div className="trust">
            <span>● Сервисы на связи</span>
            <span>
              Среднее время реакции <b>18 мин</b>
            </span>
          </div>
        </div>
        <div className="hero-visual">
          <div className="orb one" />
          <div className="orb two" />
          <div className="preview-card">
            <div className="preview-top">
              <span>Сейчас в городе</span>
              <b className="live">● LIVE</b>
            </div>
            <div className="mini-map">
              <i className="road r1" />
              <i className="road r2" />
              <i className="road r3" />
              <button className="pin p1">!</button>
              <button className="pin p2">•</button>
              <button className="car">▰</button>
              <i className="route" />
            </div>
            <div className="preview-stats">
              <div>
                <b>24</b>
                <span>активных заявки</span>
              </div>
              <div>
                <b>11</b>
                <span>бригад на линии</span>
              </div>
              <div>
                <b>94%</b>
                <span>выполнено вовремя</span>
              </div>
            </div>
          </div>
          <div className="floating-note">
            <span>✓</span>
            <div>
              <b>Бригада назначена</b>
              <small>Прибудет через 12 минут</small>
            </div>
          </div>
        </div>
      </section>
      <section className="features" id="services">
        <div>
          <span>01</span>
          <h3>Всё видно</h3>
          <p>Заявки, машины и маршруты на одной карте в реальном времени.</p>
        </div>
        <div>
          <span>02</span>
          <h3>Каждый на своём месте</h3>
          <p>Отдельные рабочие пространства для жителей, бригад и служб.</p>
        </div>
        <div>
          <span>03</span>
          <h3>Ничего не теряется</h3>
          <p>
            История действий, SLA и уведомления сопровождают заявку до
            результата.
          </p>
        </div>
      </section>
      <section className="process" id="how">
        <div className="eyebrow">Просто для жителя. Точно для служб.</div>
        <h2>
          От сообщения до результата
          <br />
          без лишних звонков
        </h2>
        <div className="process-row">
          <article>
            <b>1</b>
            <h3>Отметьте проблему</h3>
            <p>Укажите точку на карте, добавьте описание и фотографию.</p>
          </article>
          <article>
            <b>2</b>
            <h3>Мы найдём исполнителя</h3>
            <p>Диспетчер увидит ближайшую подходящую бригаду и маршрут.</p>
          </article>
          <article>
            <b>3</b>
            <h3>Следите за ходом работ</h3>
            <p>Статусы и уведомления покажут, что происходит прямо сейчас.</p>
          </article>
        </div>
      </section>
      <footer>
        <a className="brand" href="#top">
          <span>Г</span>Город рядом
        </a>
        <p>Цифровые городские службы — ближе, понятнее, быстрее.</p>
        <div className="footer-auth">
          <button
            className="ghost"
            disabled={!interactive}
            onClick={onRegister}
          >
            Зарегистрироваться
          </button>
          <button
            className="primary small"
            disabled={!interactive}
            onClick={onLogin}
          >
            Войти в систему
          </button>
        </div>
      </footer>
    </main>
  );
}
