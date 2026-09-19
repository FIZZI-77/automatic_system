# Сервис SLA (SLA Service)

## Ответственность

Расчёт response/resolution deadlines, warnings, breaches и SLA history.

## Ключевое поведение

- Принимает ticket events.
- Rule может wildcard-ить department/category/priority; repository выбирает наиболее specific active match.
- Parallel deadline scanning использует `FOR UPDATE SKIP LOCKED`.
- Хранит текущее SLA state и transition history.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL. |
| Синхронные взаимодействия | Основной вход — Kafka event processing. |
| Kafka | Consumer: `tickets.events.v1`; publisher: `sla.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/SLA_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/SLA_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
