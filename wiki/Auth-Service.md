# Сервис аутентификации (Auth Service)

## Ответственность

Учетные записи, роли, sessions, access/refresh tokens, email verification, password reset.

## Ключевое поведение

- Passwords сохраняются только как bcrypt hash.
- Refresh и one-time tokens хранятся как SHA-256/base64url hash, а не в исходном виде.
- Access JWT подписывается RSA private key; документированное время access token — 15 минут.
- Write flows поддерживают idempotency; значимые изменения сохраняют outbox event в той же transaction.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL; SMTP для почтовых flows. |
| Синхронные взаимодействия | Создаёт client к Profile Service. |
| Kafka | Publisher: `auth.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
