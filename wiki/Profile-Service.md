# Сервис профилей (Profile Service)

## Ответственность

Личный профиль и отдельный рабочий профиль: подразделение, должность, статус, certificates и professional skills.

## Ключевое поведение

- Проверяет account через Auth и активность department через Department.
- Verified certificate создаёт skill grants; revoke/expiry отзывает связанные grants.
- Write operations используют idempotency с документированным сроком 24 часа.
- Authorization разделяет self-service, admin, dispatcher, HR/qualification-verifier и internal reads.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL. |
| Синхронные взаимодействия | Auth и Department. |
| Kafka | Publisher: `profiles.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
