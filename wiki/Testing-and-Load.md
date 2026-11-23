# Тестирование и нагрузка

## Модульные тесты и проверка гонок

CI выполняет `go test -race -count=1 ./...` для каждого Go module отдельно, вместе с `gofmt` и `go vet`.

## Интеграционные тесты

Отдельные задачи CI охватывают репозитории периферийных сервисов, Analytics
с ClickHouse, Location с PostgreSQL и Redis, восстановление Dispatch и File,
исходящие события File и Notification, а также лабораторное восстановление
PostgreSQL до заданной точки. Сборка Frontend, браузерный smoke и Playwright
inventory выполняются в отдельной задаче.
[Конфигурация CI](https://github.com/FIZZI-77/automatic_system/blob/test/.github/workflows/ci.yml)

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

OpenAPI в ветке `test` на коммите `a74467c` содержит **203 HTTP-операции,
из них 192 с JWT и 11 публичных**. WebSocket `/notifications/ws` проверяется
отдельно. `gateway-coverage.spec.ts` сверяет инвентарь, включая
`/assets/incidents/list`. Для операций
`list`, `set-active`, `rotate-secret` добавлен сценарий с проверкой списка,
состояния БД, прав обычного пользователя, отключения интеграции, ротации без
включения, отказа старому секрету и идемпотентного повтора с новым секретом.
JWT-sweep строится динамически по OpenAPI.

23 ноября 2026 года прошли два статических теста inventory и локальные тесты
обработчиков Gateway. Сквозной прогон с хранилищами и реальным Gateway требует
доступного Kubernetes-контекста и в этой проверке не выполнялся.

Состав и команды: [API Gateway E2E coverage](https://github.com/FIZZI-77/automatic_system/blob/test/API_Gateway/e2e/COVERAGE.md).
