# File Service

Сервис предоставляет только gRPC API, хранит метаданные в PostgreSQL и объекты в
S3-совместимом хранилище (MinIO локально). Бинарные данные не проходят через gRPC:
клиент получает presigned URL.

Поток загрузки:

1. `CreateUpload` — создать метаданные и получить upload URL.
2. `PUT <url>` — загрузить объект напрямую в S3/MinIO.
3. `ConfirmUpload` — проверить размер и MIME type.
4. `LinkFile` — связать файл с ресурсом (`ticket_report`, `user_profile`, `work_profile_certification`).
5. `GetDownloadURL` — получить download URL.

Идентификатор пользователя передаётся в `X-User-ID`, роли — в `X-User-Roles`.
Максимальный размер файла — 25 MiB. Разрешены JPEG, PNG, WebP, PDF, CSV и XLSX.

File Service не использует Kafka и outbox.
