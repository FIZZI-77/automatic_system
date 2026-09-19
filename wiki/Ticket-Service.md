# Сервис заявок (Ticket Service)

## Ответственность

Источник истины по заявке: ticket, category, status history, brigade assignment и work reports.

## Ключевое поведение

- Основной lifecycle: `NEW → ASSIGNED → IN_PROGRESS → DONE`; cancel разрешён из NEW/ASSIGNED/IN_PROGRESS.
- `DONE` и `CANCELED` — terminal application states.
- Access зависит от роли и ownership; worker работает с ticket своей brigade.
- Write operations поддерживают idempotency.
- Completion report request сохраняется вместе с outbox event; результат возвращается асинхронно.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL; Citus topology определяется deployment, а не business code. |
| Синхронные взаимодействия | В текущем `main.go` нет прямых gRPC clients Department/Brigade. |
| Kafka | Publisher: `tickets.events.v1`; consumers: `routing.events.v1`, `reports.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Ticket_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Ticket_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
