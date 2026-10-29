# Тестирование и нагрузка

## Модульные тесты и проверка гонок

CI выполняет `go test -race -count=1 ./...` для каждого Go module отдельно, вместе с `gofmt` и `go vet`.

## Интеграционные тесты

Подтверждённые отдельные CI integration paths:

- Analytics и ClickHouse;
- интеграционный набор Location;
- Frontend build и Playwright contract inventory.

## Клиентское приложение E2E

Playwright покрывает:

- главная страница, регистрация и вход;
- ролевые меню;
- заявки;
- профиль;
- управление;
- SLA;
- аудит;
- аналитика;
- отчёты;
- адаптивность;
- контракты чтения API Gateway.

Artifacts падений: trace, screenshot, video.

## Нагрузочный контур

`load-tests` использует k6 и, для прямого gRPC, ghz.

Ключевой принцип: нагрузка задаётся `constant-arrival-rate`, а не просто числом VU.

Ступень считается sustainable только если одновременно соблюдены:

- SLO задержки и ошибок;
- целевые показатели CPU/RAM;
- Kafka lag / queue / PgBouncer wait / backlog не растут;
- нет OOM/restarts.

Различаются три результата:

- **capacity** — максимальная устойчивая измеренная ступень;
- **knee** — объяснимое изменение наклона latency/throughput;
- **failure** — первая ступень, нарушившая ограничения.

В репозитории **не зашиты фиктивные benchmark numbers**. До реального запуска значения остаются `N/A / not measured`, а measured и extrapolated результаты сохраняются отдельно.

### Текущие сценарии

`gateway`, `gateway-authenticated-read`, `auth-login`, `auth-refresh`, `ticket-read`, `location`, `dispatch-preview`, `analytics`, `full`.

Записывающие destructive scenarios требуют явного `LOAD_TEST_ALLOW_DESTRUCTIVE=true`; production-like target name блокируется.

### Источники
- [Load testing README](https://github.com/FIZZI-77/automatic_system/blob/test/load-tests/README.md)
- [Frontend README](https://github.com/FIZZI-77/automatic_system/blob/test/Frontend/README.md)
- [CI workflow](https://github.com/FIZZI-77/automatic_system/blob/test/.github/workflows/ci.yml)
## Кластерные проверки API Gateway

Из корня репозитория:

```powershell
& .\scripts\run-api-gateway-e2e.ps1 -SkipSeed
# Существующий доступный адрес вместо временного port-forward:
& .\scripts\run-api-gateway-e2e.ps1 -GatewayUrl http://127.0.0.1:8081 -SkipSeed
# Отдельные SMTP-сценарии:
& .\scripts\run-api-gateway-e2e.ps1 -SkipSeed -IncludeSMTP
```

Требуются зависимости Frontend, `kubectl` с доступом к namespace
`automatic-system` и работающие сервисы/хранилища. По умолчанию runner открывает
временный port-forward `18081:8081`, включает API-only и storage assertions,
а затем завершает созданный процесс. Без demo-пароля используются временные
учетные записи; с паролем дополнительно включаются сценарии на demo-данных.
`-TestFile` выбирает конкретные spec-файлы. SMTP требует доступного провайдера.

Сценарии проверяют JWT/session lifecycle, CRUD и изменения состояния предметных
сервисов, PostgreSQL/Citus, Redis, ClickHouse, реальные объекты MinIO и WebSocket
уведомлений. Проверка наличия маршрута отдельно не доказывает его бизнес-поведение.

По коду на 27 октября 2026 OpenAPI содержит **202 операции: 191 с JWT и 11
публичных**. `gateway-coverage.spec.ts` проверяет этот состав; для операций
`list`, `set-active`, `rotate-secret` добавлен сценарий с проверкой списка,
состояния БД, прав обычного пользователя, отключения интеграции, ротации без
включения, отказа старому секрету и идемпотентного повтора с новым секретом.
JWT-sweep строится динамически по OpenAPI.

Два статических теста inventory, ESLint измененных spec-файлов и TypeScript
прошли 27 октября 2026. Новый сценарий обнаруживается runner, но кластерный
прогон не выполнен: Kubernetes API текущего контекста на `127.0.0.1:54025`
недоступен. Статическая проверка inventory не подтверждает сквозной результат.

Состав и команды: [API Gateway E2E coverage](https://github.com/FIZZI-77/automatic_system/blob/test/API_Gateway/e2e/COVERAGE.md).
