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

## Push-уведомления

Для браузерных уведомлений заполните параметры `NEXT_PUBLIC_FIREBASE_*` из
`.env.example`. В сборке GitHub Actions им соответствуют переменные репозитория
`FIREBASE_WEB_API_KEY`, `FIREBASE_AUTH_DOMAIN`, `FIREBASE_PROJECT_ID`,
`FIREBASE_STORAGE_BUCKET`, `FIREBASE_MESSAGING_SENDER_ID`, `FIREBASE_APP_ID` и
`FIREBASE_WEB_VAPID_KEY`.

Пользователь подключает браузер в разделе «Уведомления». Фронтенд получает токен
FCM, регистрирует его через `/notifications/devices/register` и принимает
сообщения как в открытой вкладке, так и через Service Worker в фоне. Для работы
Service Worker приложение должно быть открыто через HTTPS или `localhost`.

## Тестовые данные

После запуска основного `docker-compose.yml` связанный набор данных для всех экранов можно безопасно загрузить повторно:

```powershell
$env:DEMO_PASSWORD = Read-Host "Demo password"
powershell -ExecutionPolicy Bypass -File scripts/seed-demo-data.ps1
```

Тестовые учётные записи используют пароль из `DEMO_PASSWORD`:

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

Для проверки запущенного Kubernetes-кластера используется отдельный API-only runner. Если `GatewayUrl` не указан, он сам поднимает временный `kubectl port-forward`. Без demo-пароля выполняется self-contained набор API-сценариев: позитивные сценарии, негативные проверки, JWT-sweep и сверка фактического состояния PostgreSQL/Citus, ClickHouse, Redis и MinIO. При передаче пароля дополнительно запускаются старые сценарии на постоянных demo-аккаунтах и seed тестовых данных.

```powershell
# Базовый прогон без demo-пароля (создает и удаляет тестовые данные)
powershell -ExecutionPolicy Bypass -File scripts/run-api-gateway-e2e.ps1 -SecuritySweepOnly -SkipSeed

# Авторизованные сценарии против кластера
$password = Read-Host "Demo password"
powershell -ExecutionPolicy Bypass -File scripts/run-api-gateway-e2e.ps1 -Password $password
```

Тесты `gateway-route-sweep.spec.ts` и `gateway-coverage.spec.ts` читают сгенерированный `API_Gateway/src/core/handlers/openapi.json`: новая операция требует позитивный сценарий с storage evidence (текущий inventory проверяет 202 операции), а защищённая операция попадает в проверки отсутствующего и повреждённого JWT. Storage-проверки выполняются через `kubectl exec`, сверяют фактическое состояние БД и удаляют созданные ими записи.

## Карта

Карта отображает координаты заявок, машин и активный маршрут без жёсткой привязки к поставщику. URL тайлов и WebSocket вынесены в окружение. В текущем интерфейсе фон отрисовывается локально, поэтому диспетчерский экран остаётся работоспособным даже без доступа к внешнему tile-серверу.

## Полный кластерный E2E API Gateway

Из `API_Gateway` набор можно запускать как обычный Go-тест. Он сам поднимает
временный `kubectl port-forward`, запускает Playwright API-сценарии и завершает
port-forward после проверки:

```powershell
$env:API_GATEWAY_E2E = '1'
$env:GOCACHE = 'C:\AuthomaticCityServices\.gocache'
go test -v ./e2e -run TestAPICluster -count=1
```

SMTP-конфигурация тестом не меняется. Позитивные сценарии отправки писем требуют
доступности настроенного SMTP-провайдера (в частности, отключённого мешающего VPN).
Они включаются параметром `-IncludeSMTP` у `scripts/run-api-gateway-e2e.ps1`.

## Управление интеграциями

Администратору в разделе «Управление» доступна вкладка «Интеграции» с карточками
предприятий и порталов. Можно зарегистрировать источник, ограничить его одним
департаментом, отключить/включить и обновить секрет. Карточка показывает
`client_id`, префикс секрета, департамент и время последнего использования.
Полный секрет после регистрации или ротации показывается один раз; интерфейс
позволяет скопировать и скрыть его. Список загружает первые 100 записей,
переключение страниц пока не реализовано.

Компонент: `Frontend/app/integration-management.tsx`; подключение:
`Frontend/app/management-page.tsx`. Четыре адреса API настраиваются через
`NEXT_PUBLIC_API_TICKET_INTEGRATIONS_REGISTER`,
`NEXT_PUBLIC_API_TICKET_INTEGRATIONS_LIST`,
`NEXT_PUBLIC_API_TICKET_INTEGRATIONS_SET_ACTIVE`,
`NEXT_PUBLIC_API_TICKET_INTEGRATIONS_ROTATE_SECRET`.
Сервер проверяет права независимо от видимости вкладки.

Для управления интеграциями добавлен кластерный сценарий с проверкой БД, прав,
активности, ротации секрета и идемпотентного повтора. Статические проверки
inventory, ESLint и TypeScript прошли 27 октября 2026; новый сценарий пока
не запускался в кластере из-за недоступного Kubernetes API текущего контекста.
