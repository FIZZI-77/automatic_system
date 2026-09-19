# Сервис объектов инфраструктуры (Asset Service)

## Ответственность

Реестр городской инфраструктуры: geometry, state history, incidents, repairs, inspections и maintenance plans.

## Ключевое поведение

- Spatial search выполняется через PostGIS.
- После incident/repair/inspection пересчитывается failure risk.
- Risk calculation — объяснимая rule/score formula, а не ML model.
- Domain changes публикуются через transactional outbox.
- При переходе риска в `CRITICAL` публикуется событие
  `asset.RISK_BECAME_CRITICAL`. Опциональный Kafka worker создаёт связанную
  заявку в Ticket Service, если настроены категория и системный заявитель.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL/PostGIS. |
| Синхронные взаимодействия | Опциональный gRPC-клиент Ticket Service для создания заявки по критическому риску. |
| Kafka | Publisher и внутренний consumer: `assets.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Asset_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Asset_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
