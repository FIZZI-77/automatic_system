# Сервис аналитики (Analytics Service)

## Ответственность

Event ingestion в ClickHouse и агрегированные operational/business показатели.

## Ключевое поведение

- Не изменяет ticket/brigade/route/asset aggregates.
- Unknown event version сохраняется, но не помечается `ProjectionEligible` для текущей v1 projection.
- Поддерживает overview, SLA, latency percentiles, dispatch failures/funnel, brigade workload, routing efficiency, queue age, capacity forecast и projection health.
- Capacity forecast внутри Analytics — аналитическая формула; фактическая инфраструктурная capacity проверяется load-test framework.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | ClickHouse. |
| Синхронные взаимодействия | Нет write-dependency на domain services. |
| Kafka | Consumer широкого набора domain topics; publisher отсутствует. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
