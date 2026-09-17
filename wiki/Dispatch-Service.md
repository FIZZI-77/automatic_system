# Сервис диспетчеризации (Dispatch Service)

## Ответственность

Workflow-координатор ручного и автоматического назначения бригады.

## Ключевое поведение

- Не владеет ticket/brigade/location/route aggregates; хранит собственную operation.
- Автоматический процесс: доступные бригады → свежие позиции → ранжирование маршрутов → резервирование кандидата → создание маршрута → назначение заявки.
- Использует version field для optimistic transitions.
- При частичной ошибке выполняет compensation: освобождение brigade и/или отмена route.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL. |
| Синхронные взаимодействия | Ticket, Brigade, Location, Routing. |
| Kafka | Publisher: `dispatch.events.v1`; consumer: `tickets.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Dispatch_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Dispatch_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
