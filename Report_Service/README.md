# Report Service

Асинхронно формирует PDF, XLSX и CSV по данным Analytics Service. PostgreSQL хранит задания и transactional outbox, готовый документ загружается и связывается с отчётом через File Service/S3.

Состояния: `PENDING -> PROCESSING -> COMPLETED` или `FAILED`; неудачное задание можно повторить, ожидающее — отменить. Worker использует `FOR UPDATE SKIP LOCKED`, поэтому несколько экземпляров безопасно разделяют очередь.

Секрет `DATABASE_URL` передаётся только через environment. Остальная конфигурация находится в `config.yaml`.
