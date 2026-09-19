# Сервис местоположения (Location Service)

## Ответственность

Приём GPS, последнее положение, history, nearby search, geozones и signal-loss detection.

## Ключевое поведение

- Последняя позиция пишется синхронно в Redis.
- Новая non-duplicate position помещается в bounded history buffer и batch-пишется в PostGIS.
- Ошибка history buffer не откатывает уже принятое current location.
- Signal state change и event в Redis Stream фиксируются атомарно.
- Simulator может отправлять telemetry по HTTP; доменный API также доступен через gRPC.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | Redis + PostgreSQL/PostGIS. |
| Синхронные взаимодействия | Предоставляет данные Dispatch; сам не требует перечисленных domain gRPC clients. |
| Kafka | `locations.events.v1` публикуется через Redis Stream → Kafka. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Location_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Location_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
