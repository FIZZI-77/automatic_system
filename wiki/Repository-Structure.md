# Структура репозитория

```text
automatic_system/
├── API_Gateway/
├── Auth_Service/
├── Profile_Service/
├── Department_Service/
├── Brigade_Service/
├── Ticket_Service/
├── Dispatch_Service/
├── Location_Service/
├── Routing_Service/
├── Asset_Service/
├── File_Service/
├── SLA_Service/
├── Notification_Service/
├── Audit_Service/
├── Analytics_Service/
├── Report_Service/
├── Transponder_Simulator/
├── Frontend/
├── docs/
├── k8s/
├── load-tests/
├── postman/
├── scripts/
├── .github/workflows/
├── docker-compose.yml
├── go.work
└── runtime.env.example
```

## Что где искать

| Задача | Основной каталог |
|---|---|
| HTTP API и HTTP↔gRPC mapping | `API_Gateway` |
| Бизнес-логика домена | `<Service>/src/core/service` |
| Persistence | `<Service>/src/core/repository` |
| Запуск сервиса | `<Service>/src/cmd/server` |
| Контракты / transport | proto/handler/client packages конкретного сервиса |
| Архитектурные доказательства | `docs/architecture` |
| Docker development | `docker-compose.yml` |
| Kubernetes | `k8s` |
| CI/CD | `.github/workflows/ci.yml` |
| Capacity / load | `load-tests` |
| E2E UI/API | `Frontend/e2e` |

## Рабочая область Go

Репозиторий использует `go.work`, но CI намеренно проверяет каждый модуль с `GOWORK=off`, чтобы ошибка одного сервиса не маскировалась как ошибка всех модулей.

[Открыть исходную ветку репозитория](https://github.com/FIZZI-77/automatic_system/tree/test)
