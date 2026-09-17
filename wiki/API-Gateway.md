# API-шлюз (API Gateway)

## Ответственность

Единая внешняя HTTP-точка. Преобразует JSON/HTTP в gRPC, проверяет identity и права, нормализует transport errors. Предметные данные не хранит.

## Ключевое поведение

- Middleware chain включает Request ID, idempotency metadata, Redis-backed rate limiting, structured request logging и JWT verification.
- Создаёт gRPC clients ко всем 15 backend domain services.
- Global limit: 300 requests/minute + burst 100; auth flows имеют отдельные более строгие limits.
- HTTP DTO живут в `models`, но не образуют самостоятельный persisted domain.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | Redis — rate limiting и live notification mechanics. |
| Синхронные взаимодействия | Auth, Profile, Department, Brigade, Ticket, Dispatch, Location, Routing, Asset, File, SLA, Notification, Audit, Analytics, Report. |
| Kafka | Gateway не является Kafka domain publisher. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/API_Gateway/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/API_Gateway/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
