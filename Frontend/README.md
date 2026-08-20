# Город рядом — frontend

Ролевой веб-интерфейс для Automatic City Services. Роль пользователя всегда берётся из `GET /auth/me`; клиентское меню не заменяет серверную авторизацию.

## Запуск

1. Скопируйте `.env.example` в `.env.local` и укажите адрес Gateway.
2. Выполните `npm install` и `npm run dev`.
3. Откройте адрес из вывода dev-сервера.

Без входа доступен демонстрационный режим для жителя, работника, диспетчера и администратора. После входа используются реальные токены и API Gateway.

## Docker

Запуск production-сборки: `docker compose -f compose.yml up -d --build`.
Порт меняется через `FRONTEND_PORT`, адрес Gateway — через `NEXT_PUBLIC_API_BASE_URL`.

## Тестовые данные

После запуска основного `docker-compose.yml` связанный набор данных для всех экранов можно безопасно загрузить повторно:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/seed-demo-data.ps1
```

Тестовые учётные записи используют пароль `CityDemo123!`:

- `demo.admin@city.local`
- `demo.dispatcher@city.local`
- `demo.worker1@city.local`
- `demo.worker2@city.local`
- `demo.user@city.local`

Скрипт идемпотентен: фиксированные демонстрационные записи обновляются, а не размножаются при повторном запуске.

## Сквозные E2E-тесты

Playwright проверяет лендинг, регистрацию, вход всех ролей, ролевые меню, заявки, профиль, управление, SLA, аудит, аналитику, отчёты, адаптивность и контракты read-ручек API Gateway. Перед прогоном seed обновляется автоматически, после прогона изменённые тестами данные восстанавливаются.

```powershell
# Полный запуск Docker-стека, seed и всех тестов
powershell -ExecutionPolicy Bypass -File scripts/run-e2e.ps1

# Если контейнеры уже запущены
cd Frontend
npm run e2e

# Интерактивный режим и HTML-отчёт
npm run e2e:ui
npm run e2e:report
```

Переменные окружения: `E2E_BASE_URL`, `E2E_API_URL`, `E2E_DEMO_PASSWORD`, `E2E_SKIP_SEED=1`, `E2E_RESTORE_SEED=0`. Артефакты падений (trace, screenshot, video) сохраняются в `Frontend/test-results`, HTML-отчёт — в `Frontend/playwright-report`.

## Карта

Карта отображает координаты заявок, машин и активный маршрут без жёсткой привязки к поставщику. URL тайлов и WebSocket вынесены в окружение. В текущем интерфейсе фон отрисовывается локально, поэтому диспетчерский экран остаётся работоспособным даже без доступа к внешнему tile-серверу.
