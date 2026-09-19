# Симулятор транспондера (Transponder Simulator)

## Ответственность

Имитатор автомобильного GPS/transponder для проверки Location Service.

## Ключевое поведение

- Читает route из JSON и последовательно создаёт `VehiclePositionUpdated`.
- Отправляет telemetry в Location по HTTP; при пустом `TARGET_URL` печатает JSON в stdout.
- Поддерживает sequence number, retry, interval и loop route.
- Отдельной БД и service layer нет.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | Только config/route и in-memory state. |
| Синхронные взаимодействия | HTTP → Location Service. |
| Kafka | Сам напрямую Kafka не использует. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Transponder_Simulator/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Transponder_Simulator/README.md)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
