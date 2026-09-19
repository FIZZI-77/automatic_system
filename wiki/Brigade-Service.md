# Сервис бригад (Brigade Service)

## Ответственность

Бригады, участники, skills, schedules, service zones и operational readiness.

## Ключевое поведение

- При добавлении участника запрашивает Profile, получает canonical user/profile IDs и snapshot действующих skills.
- Один user/profile не должен одновременно состоять в нескольких активных membership records.
- Архивная бригада не изменяет composition, skills, schedule и zones.
- Хранит историю ключевых изменений и использует outbox.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL. |
| Синхронные взаимодействия | Profile и Department. |
| Kafka | Publisher: `brigades.events.v1`; consumers: `profiles.events.v1`, `routing.events.v1`, `tickets.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
