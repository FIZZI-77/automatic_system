# Сервис подразделений (Department Service)

## Ответственность

Справочник подразделений и их lifecycle.

## Ключевое поведение

- Состояния: `ACTIVE`, `INACTIVE`, `ARCHIVED`.
- Создание/изменение/архивирование разрешены admin/dispatcher.
- Write transaction объединяет domain change, idempotency result и outgoing event.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL. |
| Синхронные взаимодействия | Прямых downstream gRPC clients в карте взаимодействий не отмечено. |
| Kafka | Publisher: `departments.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Department_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Department_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
