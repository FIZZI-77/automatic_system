# Сервис аудита (Audit Service)

## Ответственность

Неизменяемый журнал действий, построенный из domain events Kafka.

## Ключевое поведение

- Модель только для добавления записей.
- `UNIQUE(topic, event_id)` устраняет повтор одного event.
- PostgreSQL trigger запрещает UPDATE/DELETE existing audit entries.
- Сохраняются actor/entity/request/trace context и исходный event data.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL. |
| Синхронные взаимодействия | Нет обязательных domain synchronous dependencies. |
| Kafka | Consumer широкого набора domain topics; publisher отсутствует. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Audit_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Audit_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
