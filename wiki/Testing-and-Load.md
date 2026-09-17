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
