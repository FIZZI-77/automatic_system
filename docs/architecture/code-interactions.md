# Карта взаимодействий по исходному коду

Эта карта описывает связи, найденные в точках запуска, обработчиках и
конфигурации сервисов текущего репозитория. Стрелка означает реализованный
вызов или настроенного читателя, а не подтверждение успешной работы в
запущенном кластере. Публикация событий зависит от наличия брокеров и
успешной работы фоновых обработчиков.

![Прямые связи](sync-interactions.svg)

![События Kafka](event-interactions.svg)

## Прямые вызовы

| Откуда | Куда | Основание |
|---|---|---|
| Frontend | API Gateway | [Предметные запросы клиента](../../Frontend/app/api.ts). |
| Frontend | Nominatim, Overpass API, Valhalla | [Геокодирование](../../Frontend/app/api/geocode/route.ts), [данные объектов](../../Frontend/app/api/moscow-infrastructure/route.ts), [маршрут](../../Frontend/app/api/valhalla-route/route.ts). Это серверные маршруты самого Frontend. |
| Браузер | S3-совместимое хранилище | Загрузка по подписанной ссылке, например [на экране заявки](../../Frontend/app/ticket-workspace.tsx). |
| API Gateway | Auth, Profile, Department, Brigade, Ticket, Dispatch, Location, Routing, Asset, File, SLA, Notification, Audit, Analytics, Report | [Создание 15 gRPC-клиентов](../../API_Gateway/src/cmd/server/main.go). |
| API Gateway | Ticket, Brigade и Profile при подготовке отчета о работе | [Обработчик отчета](../../API_Gateway/src/core/handlers/report.go); создание записи выполняет Ticket. Последующее формирование документа идет через событие Kafka, а не через прямой HTTP-вызов Report. |
| Auth | Profile | [Инициализация клиента](../../Auth_Service/src/cmd/server/main.go). |
| Profile | Auth, Department | [Проверки учетной записи и подразделения](../../Profile_Service/src/cmd/server/main.go). |
| Brigade | Profile, Department | [Инициализация клиентов](../../Brigade_Service/src/cmd/server/main.go). |
| Dispatch | Ticket, Brigade, Location, Routing | [Инициализация клиентов](../../Dispatch_Service/src/cmd/server/main.go). |
| Asset | Ticket при включенном worker критического риска | [Инициализация клиента](../../Asset_Service/src/cmd/server/main.go) и [создание заявки](../../Asset_Service/src/infrastructure/criticalticket/worker.go). Worker не запускается без `CRITICAL_RISK_TICKET_CATEGORY_ID` и `CRITICAL_RISK_TICKET_REQUESTER_ID`. |
| Report | Analytics, File | [Инициализация клиентов](../../Report_Service/src/cmd/server/main.go). |
| Transponder Simulator | Location по HTTP | [Передача координат](../../Transponder_Simulator/internal/simulator/sender.go); [HTTP-сервер Location](../../Location_Service/src/cmd/server/main.go). |

В коде [Ticket Service](../../Ticket_Service/src/cmd/server/main.go) не создает
gRPC-клиентов Department или Brigade. Эти связи в старой обзорной схеме были
показаны как прямые и потому не перенесены на новую карту.
У обработчика отчета шлюза есть поля для внутреннего HTTP-клиента Report, но
[текущий метод создания отчета](../../API_Gateway/src/core/handlers/report.go)
их не использует. Существование адреса в конфигурации не равно вызову.

## Хранилища и внешние системы

| Компонент | Используемая система | Основание |
|---|---|---|
| API Gateway | Redis для ограничения запросов и живых уведомлений | [Запуск шлюза](../../API_Gateway/src/cmd/server/main.go). |
| Auth | PostgreSQL, SMTP | [Запуск](../../Auth_Service/src/cmd/server/main.go), [отправка почты](../../Auth_Service/src/core/service/mail_service.go). |
| Profile | PostgreSQL | [Запуск](../../Profile_Service/src/cmd/server/main.go). |
| Department | PostgreSQL | [Запуск](../../Department_Service/src/cmd/server/main.go). |
| Brigade | PostgreSQL | [Запуск](../../Brigade_Service/src/cmd/server/main.go). |
| Ticket | PostgreSQL | [Запуск](../../Ticket_Service/src/cmd/server/main.go). Использование Citus задается развертыванием, а не этим кодом. |
| Dispatch | PostgreSQL | [Запуск](../../Dispatch_Service/src/cmd/server/main.go). |
| Location | PostgreSQL/PostGIS и Redis | [Запуск](../../Location_Service/src/cmd/server/main.go), [пространственные запросы](../../Location_Service/src/core/repository/geo_zone_repo.go). |
| Routing | PostgreSQL и Valhalla | [Запуск и создание клиента](../../Routing_Service/src/cmd/server/main.go). |
| Asset | PostgreSQL/PostGIS | [Запуск](../../Asset_Service/src/cmd/server/main.go), [пространственные запросы](../../Asset_Service/src/core/repository/asset_repository.go). |
| File | PostgreSQL и S3-совместимое хранилище | [Запуск и создание клиента](../../File_Service/src/cmd/server/main.go). |
| SLA | PostgreSQL | [Запуск](../../SLA_Service/src/cmd/server/main.go). |
| Notification | PostgreSQL, Redis, SMTP и FCM при наличии ключа | [Запуск и условная настройка FCM](../../Notification_Service/src/cmd/server/main.go). |
| Audit | PostgreSQL | [Запуск](../../Audit_Service/src/cmd/server/main.go). |
| Analytics | ClickHouse | [Подключение](../../Analytics_Service/src/cmd/server/main.go). |
| Report | PostgreSQL; File по gRPC и объектное хранилище по внутреннему HTTP для загрузки сформированного файла | [Запуск](../../Report_Service/src/cmd/server/main.go), [клиент файлов](../../Report_Service/src/infrastructure/fileclient/client.go). |

## Темы Kafka

Издатели определены по запускаемым передатчикам исходящих событий. Для Location
источник событий -- Redis Stream, а не таблица исходящих сообщений.

| Издатель | Тема | Основание |
|---|---|---|
| Auth | `auth.events.v1` | [Передатчик](../../Auth_Service/src/cmd/server/outbox.go). |
| Profile | `profiles.events.v1` | [Передатчик](../../Profile_Service/src/cmd/server/outbox.go). |
| Department | `departments.events.v1` | [Передатчик](../../Department_Service/src/cmd/server/outbox.go). |
| Brigade | `brigades.events.v1` | [Передатчик](../../Brigade_Service/src/cmd/server/outbox.go). |
| Ticket | `tickets.events.v1` | [Передатчик](../../Ticket_Service/src/cmd/server/outbox.go). |
| Dispatch | `dispatch.events.v1` | [Передатчик](../../Dispatch_Service/src/cmd/server/outbox.go). |
| Routing | `routing.events.v1` | [Передатчик](../../Routing_Service/src/cmd/server/outbox.go). |
| Location | `locations.events.v1` | [Передача Redis Stream в Kafka](../../Location_Service/src/cmd/server/main.go). |
| Asset | `assets.events.v1` | [Передатчик](../../Asset_Service/src/cmd/server/main.go). |
| SLA | `sla.events.v1` | [Передатчик](../../SLA_Service/src/cmd/server/main.go). |
| Report | `reports.events.v1` | [Передатчик и обработчик заявки](../../Report_Service/src/cmd/server/main.go). |
| File | `files.events.v1` | [Передатчик](../../File_Service/src/cmd/server/outbox.go), [транзакционный outbox](../../File_Service/scheme/20261116000100_create_event_outbox.sql). |
| Notification | `notifications.events.v1` | [Передатчик](../../Notification_Service/src/cmd/server/outbox.go), [транзакционный outbox](../../Notification_Service/scheme/20261116000100_create_event_outbox.sql). |

| Читатель | Темы | Основание |
|---|---|---|
| Brigade | `profiles.events.v1`, `routing.events.v1`, `tickets.events.v1` | [Запуск трех читателей](../../Brigade_Service/src/cmd/server/main.go). |
| Asset | `assets.events.v1` | [Читатель критического риска](../../Asset_Service/src/infrastructure/criticalticket/worker.go), включается настройками `applications.asset.criticalRiskTicket`. |
| Ticket | `routing.events.v1`, `reports.events.v1` | [Запуск двух читателей](../../Ticket_Service/src/cmd/server/main.go). |
| Dispatch, Routing, SLA, Report | `tickets.events.v1` | [Dispatch](../../Dispatch_Service/src/cmd/server/ticket_consumer.go), [Routing](../../Routing_Service/src/cmd/server/ticket_consumer.go), [SLA](../../SLA_Service/src/cmd/server/main.go), [Report](../../Report_Service/src/cmd/server/main.go). |
| Notification | `tickets`, `sla`, `dispatch`, `departments`, `brigades`, `locations`, `routing`, `files`, `reports` с суффиксом `.events.v1` | [Код читателя](../../Notification_Service/src/cmd/server/main.go), [настройка Kubernetes](../../k8s/helm/applications/templates/services/notification.yaml). |
| Audit и Analytics | `auth`, `tickets`, `departments`, `brigades`, `profiles`, `locations`, `routing`, `dispatch`, `sla`, `files`, `notifications`, `reports`, `assets` с суффиксом `.events.v1` | [Код Audit](../../Audit_Service/src/cmd/server/main.go), [его конфигурация](../../Audit_Service/config.yaml), [код Analytics](../../Analytics_Service/src/cmd/server/main.go), [ее конфигурация](../../Analytics_Service/config.yaml). |

File публикует `file.created`, `file.uploaded`, `file.linked`, `file.quarantined`
и `file.deleted` (включая удаление просроченной загрузки). Notification публикует
`notification.created`, `notification.read` и `notification.delivery.sent`,
`notification.delivery.failed`, `notification.delivery.dead`. Повторное прочтение,
удаление или привязка к тому же ресурсу новых событий не создаёт.

Триггеры PostgreSQL записывают outbox в той же транзакции, что и изменение
состояния. Передатчики запускаются вместе с сервисами и требуют `KAFKA_BROKERS`.
Миграции нужно применить перед запуском новой версии. Старые записи не порождают
событий задним числом. Доставка — at-least-once: после сбоя между подтверждением
Kafka и записью `sent_at` возможен повтор с тем же `event_id`. Audit и Analytics
уже исключают такие повторы. Событие содержит плоские поля `event_id`,
`event_type`, `event_version=1`, `occurred_at`, `entity_type`, `entity_id`;
Kafka key — ID файла или уведомления. Повторы сохраняют исходное время события.
Ошибки Kafka не удаляют события: передатчик повторяет отправку с задержкой
до 256 секунд, сохраняя попытки и последнюю ошибку в outbox.

События содержат идентификаторы и состояния, исключая имена и ключи файлов,
подписанные URL, тексты сообщений, контакты, токены устройств и ответы провайдеров.
Подписка Notification на файлы не означает создания пользовательского уведомления:
его обработчик по-прежнему пропускает типы вне списка пользовательских событий.
Analytics сохраняет файловые и уведомительные события в общем журнале;
предметные проекции и показатели применяются только к поддерживаемым типам.

Проверки атомарности, идемпотентности и восстановления передатчиков запускаются
с `OUTBOX_TEST_DATABASE_URL` командой `go test -tags=integration -v ./src/infrastructure/outboxrelay`
из File_Service и Notification_Service; в CI используется изолированный PostgreSQL.

## Границы карты

Схемы показывают прикладные вызовы и события. Метрики, трассировки, сетевые
прокси, диски, репликация баз и фактические состояния развертываний относятся к
[документации Kubernetes](../../k8s/README.md). Унаследованные рисунки draw.io
не использовались как доказательство стрелок этой карты.
