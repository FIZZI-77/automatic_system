# Сервис уведомлений (Notification Service)

## Ответственность

Durable user notifications и channel deliveries.

## Ключевое поведение

- PostgreSQL — source of truth; live publisher используется поверх уже сохранённого notification.
- Ошибка live publish не отменяет DB record; после reconnect клиент может получить уведомление через List.
- Preferences управляют InApp/Push/Email/SMS delivery independently.
- FCM настраивается только при наличии соответствующего service account/key.
- `Consume` фильтрует события и создаёт уведомления только для разрешённого набора user-facing event types.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL + Redis + SMTP + optional FCM. |
| Синхронные взаимодействия | External providers; Gateway/Frontend читают notification API/live flow. |
| Kafka | Consumer многих `*.events.v1`; собственного Kafka publisher в текущем startup нет. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
