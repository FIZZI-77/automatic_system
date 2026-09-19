# Файловый сервис (File Service)

## Ответственность

Метаданные файлов и безопасный доступ к S3-compatible object storage.

## Ключевое поведение

- Binary не проходит через gRPC: client загружает/скачивает его по presigned URL.
- Процесс: создание метаданных → PUT в S3 → подтверждение → связывание.
- Максимальный размер 25 MiB; README перечисляет JPEG/PNG/GIF/WebP/PDF/CSV/XLSX.
- Status включает `PENDING_UPLOAD`, `UPLOADED`, `LINKED`, `DELETED`, `QUARANTINED`.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL + S3-compatible storage/MinIO. |
| Синхронные взаимодействия | S3 API; Report использует File по gRPC. |
| Kafka | В текущем startup нет Kafka publisher и outbox. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/File_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/File_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
