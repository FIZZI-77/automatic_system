# Сервис маршрутизации (Routing Service)

## Ответственность

Route calculation, distance/time matrix, brigade ranking и persisted route lifecycle.

## Ключевое поведение

- Routing engine — Valhalla.
- Повторный create для той же ticket+brigade может вернуть существующий open route; другая brigade для уже открытого route даёт conflict.
- Route states: `PLANNED`, `ACTIVE`, `COMPLETED`, `CANCELLED`.
- Изменения маршрута фиксируются вместе с outbox events.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL + Valhalla. |
| Синхронные взаимодействия | Valhalla external routing engine. |
| Kafka | Publisher: `routing.events.v1`; consumer: `tickets.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
