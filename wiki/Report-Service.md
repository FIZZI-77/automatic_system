# Сервис отчётов (Report Service)

## Ответственность

Асинхронное формирование PDF/XLSX/CSV analytics reports и completion documents.

## Ключевое поведение

- Жизненный цикл задания: `PENDING → PROCESSING → COMPLETED`; ошибка → `FAILED`; отмена → `CANCELED`.
- `ProcessNext` использует `FOR UPDATE SKIP LOCKED`, что допускает несколько workers.
- Данные берутся из Analytics; готовый artifact сохраняется через File.
- Completion report имеет отдельный event-driven path от Ticket.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL; готовые binary artifacts идут в File/S3. |
| Синхронные взаимодействия | Analytics и File. |
| Kafka | Consumer: `tickets.events.v1`; publisher: `reports.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Report_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Report_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
