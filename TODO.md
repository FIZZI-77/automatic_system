# TODO

В этом файле хранится только ещё не реализованная работа. Описание уже готовых API Gateway, Auth, Department, Ticket, Brigade, Profile, Location и Routing Service удалено.

## Порядок разработки

1. Dispatch Service.
2. File Service.
3. SLA Service.
4. Notification Service.
5. Audit Service.
6. Analytics Service.
7. Report Service.
8. Asset / Infrastructure Service после стабилизации основного процесса.

## Оставшиеся сервисы

| Сервис | Хранилище | Основные входы | Основные выходы |
| --- | --- | --- | --- |
| Dispatch Service | PostgreSQL | `tickets.events.v1`, `departments.events.v1`, `brigades.events.v1`, `routing.events.v1` | `dispatch.events.v1` |
| File Service | PostgreSQL и S3/MinIO | запросы owner-сервисов | `files.events.v1` |
| SLA Service | PostgreSQL | `tickets.events.v1` | `sla.events.v1` |
| Notification Service | PostgreSQL и Redis | события доменных сервисов | `notifications.events.v1` при необходимости |
| Audit Service | PostgreSQL | все доменные события | нет |
| Analytics Service | ClickHouse | все доменные события | аналитические read-модели |
| Report Service | PostgreSQL и S3/MinIO | Analytics, SLA, Dispatch, File | `reports.events.v1` |

## Dispatch Service

- Владеть процессом назначения, но не основной сущностью заявки.
- Читать события Ticket, Department, Brigade и Routing.
- Учитывать департамент, категорию, зону, доступность, состав, навыки, текущую нагрузку, расстояние и ETA.
- Поддерживать ручное и автоматическое назначение.
- Резервировать бригаду атомарно и защищаться от двойного назначения.
- Поддерживать принятие, отказ, отмену, таймаут и переназначение.
- Реагировать на потерю сигнала бригады.
- Публиковать назначение, переназначение, отмену, принятие, отказ и истечение назначения через transactional outbox.
- Сделать consumer идемпотентным и устойчивым к duplicate/out-of-order событиям.

Целевая цепочка:

```text
Ticket
  -> Dispatch Service
    -> Brigade Service: кандидаты
    -> Location Service: текущие координаты
    -> Routing Service: маршрут и ETA
  -> Dispatch Service: резервирование и назначение
```

## File Service

- Хранить бинарные данные в MinIO для local/dev и S3/Object Storage для production.
- Хранить метаданные в PostgreSQL: владелец, ресурс, имя, MIME type, размер, checksum, object key, статус и timestamps.
- Генерировать presigned upload/download URL, не проксируя содержимое через Gateway или gRPC.
- Поддерживать состояния `PENDING_UPLOAD`, `UPLOADED`, `LINKED`, `DELETED`, `QUARANTINED`.
- Проверять право доступа через owner-сервис ресурса.
- Поддержать привязку к ticket, comment, profile, department и report.
- Публиковать создание, загрузку, привязку, удаление и карантин через outbox.
- Добавить проверку checksum, лимиты размера и content type.
- Позже добавить antivirus scan, thumbnails и lifecycle cleanup.

### Ticket attachments

- Добавить в Ticket Service API проверки права читать и прикреплять файл.
- Не хранить бинарные данные и object key в Ticket Service.
- Добавить связь заявки с `file_id` либо получать вложения из File Service по `resource_type/resource_id`.
- Покрыть upload, confirm, link, download и delete интеграционными тестами.

## SLA Service

- Читать события Ticket Service.
- Рассчитывать сроки реакции и выполнения по категории, приоритету и департаменту.
- Хранить активный SLA и историю переходов.
- Обрабатывать изменение приоритета, отмену и завершение заявки.
- Публиковать создание SLA, приближение дедлайна, нарушение и выполнение через outbox.
- Обеспечить идемпотентную обработку событий и безопасный периодический поиск дедлайнов.

## Notification Service

- Реализовать `NotificationDispatcher`, определяющий получателей, настройки и каналы.
- Разделить адаптеры на `PushSender`, `EmailSender` и `SMSSender`.
- Для push использовать FCM через отдельный адаптер.
- Хранить регистрации устройств и деактивировать невалидные токены.
- Хранить каждую доставку отдельно: канал, адресат, статус, provider ID, attempts, next attempt и last error.
- Поддерживать настройки пользователя, шаблоны, дедупликацию, exponential backoff и dead-letter state.
- Не помещать персональные или чувствительные данные в push payload.
- Читать события Ticket, Department, Brigade, Location, Routing, Dispatch, File и SLA.

## Audit Service

- Читать все доменные события.
- Хранить неизменяемую историю: actor, action, entity, before/after или безопасный diff, request ID, trace ID и timestamp.
- Не становиться синхронной зависимостью бизнес-сервисов.
- Обеспечить идемпотентную запись и политику хранения/архивации.

## Analytics Service

- Читать все доменные события и строить проекции в ClickHouse.
- Считать объём заявок, время реакции и выполнения, SLA, нагрузку, проблемные зоны и повторные инциденты.
- Поддерживать replay и пересборку read-моделей.
- Не влиять на выполнение транзакционных операций.

## Report Service

- Формировать PDF, XLSX и CSV по данным Analytics, SLA, Dispatch и других read-моделей.
- Поддерживать ручные и регламентные отчёты.
- Выполнять тяжёлые отчёты асинхронно.
- Сохранять результат через File Service или внутренний S3-контракт.
- Публиковать запрос, успешное формирование и ошибку через outbox.

## Незавершённые межсервисные интеграции

### Ticket Service и Brigade Service

- Резолвить `actor_brigade_id` на серверной стороне через Brigade Service.
- Разрешать участнику бригады менять и завершать только назначенную его бригаде заявку.
- Оставить `admin` и `dispatcher` привилегированными ролями.
- При назначении проверять существование, департамент и допустимый статус бригады.
- После появления Dispatch Service перенести оркестрацию назначения из Ticket Service в Dispatch Service.
- Добавить интеграционные и end-to-end тесты правил доступа и конкурентного назначения.

## Kafka и надёжность событий

- Стандартизировать envelope событий и версионирование топиков.
- Добавить единые правила schema evolution.
- Сделать всех consumers идемпотентными.
- Добавить retry topics и DLQ.
- Добавить мониторинг возраста outbox, числа попыток, consumer lag и DLQ.
- Добавить reconciliation там, где локальная проекция зависит от другого сервиса.

## Production readiness

- Вынести env каждого сервиса в typed config с полной проверкой при старте.
- Добавить стандартный gRPC health service и readiness зависимостей/миграций.
- Добавить gRPC panic recovery interceptors.
- Добавить Prometheus/OpenTelemetry metrics.
- Добавить OpenTelemetry tracing для цепочки Gateway -> gRPC -> DB/Kafka.
- Добавить Jaeger и централизованное хранение логов.
- После внедрения Istio добавить Kiali для визуализации service mesh и диагностики межсервисного трафика.
- Перенести Gateway rate limit из памяти в Redis.
- Добавить общий лимит размера HTTP body.
- Добавить CI для unit, integration, fuzz, race, lint, migration checks и Docker images.
- Проверять миграции вверх/вниз и совместимость rolling deployment.
- Перенести production secrets в secret manager/Kubernetes Secrets/CI secrets.
- Добавить резервное копирование и проверяемое восстановление PostgreSQL, Redis, ClickHouse и S3.
- Вынести повторяющиеся closer, request ID, access log, config и error helpers в общий модуль после стабилизации API.

## Инфраструктура следующих этапов

1. MinIO вместе с File Service.
2. ClickHouse вместе с Analytics Service.
3. Prometheus, Grafana, OpenTelemetry Collector и Jaeger.
4. Централизованные логи.
5. Kubernetes после стабилизации сервисов.
6. Istio только при необходимости mTLS, traffic splitting и mesh observability.
7. Kiali после Istio и Prometheus — для topology graph, проверки конфигурации mesh и анализа ошибок/задержек.

### Kiali

- Разворачивать Kiali только вместе с Istio: без service mesh он не является заменой Prometheus, Grafana, Jaeger или OpenTelemetry.
- Подключить Prometheus как обязательный источник метрик, Grafana и Jaeger — как внешние ссылки для перехода от графа сервисов к метрикам и трассировкам.
- Использовать Kiali для отображения связей Gateway -> gRPC-сервисы, RPS, latency, error rate, retry и состояния mTLS.
- Включить проверку `VirtualService`, `DestinationRule`, `Gateway`, authorization policies и других ресурсов Istio.
- Ограничить доступ через SSO/RBAC; не публиковать Kiali напрямую в интернет и не использовать анонимный доступ в production.
- Настроить отдельные представления и namespace-фильтры для dev, stage и production.
- Добавить health/readiness probes, resource limits, persistent settings и версионирование конфигурации через Helm/GitOps.
- Проверить на тестовом окружении сценарии canary release, traffic shifting, circuit breaking, retry и mTLS до включения в production.
- Не использовать Kiali как систему долгосрочного хранения: retention и alerts остаются в Prometheus/Grafana, трассировки — в Jaeger.

## Future: Asset / Infrastructure Service

В будущем добавить отдельный сервис городских объектов инфраструктуры. Идея: хранить не только заявки по адресу и координатам, а реестр конкретных объектов, за которые отвечают департаменты.

Примеры объектов:

- фонари;
- дороги и участки дорог;
- остановки;
- лавочки, урны, детские площадки;
- подъезды, дома и дворовые территории;
- контейнерные площадки;
- колодцы, люки, водостоки;
- светофоры;
- зеленые насаждения;
- инженерные объекты.

Рекомендуемые поля объекта:

- `id`
- `external_id` - идентификатор из внешнего источника, если объект импортирован из городской карты/открытых данных
- `department_id` - ответственный департамент
- `type` - тип объекта: `street_light`, `road_segment`, `bus_stop`, `yard`, `building`, etc.
- `name`
- `address`
- `district`
- `municipality`
- `geometry` - точка, линия или полигон в PostGIS
- `status` - `ACTIVE`, `DAMAGED`, `UNDER_REPAIR`, `DECOMMISSIONED`
- `last_repair_at`
- `created_at`
- `updated_at`

Цифровой паспорт объекта:

- хранить расширенную карточку объекта: тип, модель, серийный номер, год установки, срок службы, гарантийный срок;
- хранить владельца, ответственный департамент, обслуживающую организацию, подрядчика и зону ответственности;
- хранить нормативы обслуживания: плановый интервал осмотра, нормативный срок реакции, нормативный срок ремонта;
- хранить связанные документы: акты, фото, схемы, паспорта оборудования, гарантийные документы через будущий File Service;
- хранить жизненный цикл объекта: `PLANNED`, `INSTALLED`, `ACTIVE`, `DAMAGED`, `UNDER_REPAIR`, `NEEDS_REPLACEMENT`, `REPLACED`, `DECOMMISSIONED`.

Интеграция с заявками:

- добавить в Ticket Service опциональное поле `asset_id`;
- при создании заявки искать ближайший объект по координатам, адресу и типу проблемы;
- если объект найден, привязывать заявку к `asset_id`;
- если объект не найден, заявка продолжает жить только по `address`, `latitude`, `longitude`;
- Dispatch Service может назначать департамент и бригаду по объекту, зоне ответственности и типу проблемы.

Автообъединение заявок в инциденты:

- если несколько заявок приходят по одному объекту, адресу, району или близким координатам за короткий период, объединять их в один инфраструктурный инцидент;
- хранить связь `incident_id -> many ticket_id`;
- Dispatch Service должен назначать бригаду на инцидент, а не на каждую дублирующую заявку отдельно;
- повторные заявки жителей должны добавляться к существующему активному инциденту и обновлять его приоритет/масштаб;
- после закрытия инцидента закрывать или обновлять связанные заявки по единому результату.

История объекта:

- хранить полную эксплуатационную историю каждого объекта инфраструктуры;
- связывать объект со всеми заявками через `ticket.asset_id`;
- фиксировать инциденты: тип поломки, источник обнаружения, приоритет, район, погодный/сезонный контекст при необходимости;
- фиксировать ремонты: какая бригада выполняла работу, что было сделано, какие материалы/детали заменены, сколько занял ремонт;
- фиксировать осмотры и профилактику: плановые проверки, выявленные риски, рекомендации по замене;
- фиксировать изменения статуса объекта: `ACTIVE -> DAMAGED -> UNDER_REPAIR -> ACTIVE`, либо списание/замена;
- выявлять повторные поломки одного и того же объекта или одного типа оборудования.

Рекомендуемые таблицы истории:

- `asset_status_history` - история изменения состояния объекта;
- `asset_incidents` - факты поломок и аварий, связанные с объектом;
- `asset_repairs` - выполненные ремонтные работы;
- `asset_inspections` - осмотры, профилактика и диагностика;
- `asset_replacements` - замены объекта или важных компонентов.

Пример карточки объекта:

```text
Asset: MSK-LIGHT-10492
Type: street_light
Status: ACTIVE
District: Ясенево
Department: Городское освещение

History:
- 2026-01-12: ticket created, не горит фонарь
- 2026-01-13: repair completed, заменена лампа
- 2026-03-04: repeated incident, не горит фонарь
- 2026-03-05: repair completed, заменен блок питания
- 2026-05-22: planned inspection completed
```

Плановое обслуживание:

- создавать плановые задачи на осмотр, профилактику, диагностику и замену расходников;
- учитывать сезонные регламенты: проверка освещения перед зимой, очистка водостоков перед ливнями, обследование дорог после морозов;
- хранить расписание обслуживания по типу объекта, району, департаменту и подрядчику;
- создавать tickets/incidents автоматически, если плановый осмотр выявил проблему;
- считать просроченные профилактические работы как отдельный риск для объекта и департамента.

Риск-скоринг объекта:

- считать `risk_score` для каждого объекта на основе возраста, частоты поломок, повторяемости инцидентов, нарушений SLA и критичности объекта;
- повышать риск, если после ремонта быстро возникает повторная поломка;
- учитывать район, сезонность, тип оборудования, нагрузку и историю подрядчика;
- использовать риск для приоритизации профилактики, капитального ремонта или замены;
- формировать списки объектов: `needs_inspection`, `needs_repair`, `needs_replacement`, `critical_risk`.

Аналитика по объектам:

- сколько объектов конкретного типа сломалось за период;
- какие районы чаще всего создают заявки;
- какие объекты ломаются повторно;
- какие департаменты и бригады чаще нарушают SLA;
- среднее время реакции и ремонта по типу объекта, району и департаменту;
- где нужна профилактика или капитальная замена, а не разовый ремонт;
- сезонность поломок: снег, ливни, жара, гололед.

Потенциальные источники данных:

- OpenStreetMap: дороги, здания, остановки, POI, контуры объектов;
- data.mos.ru: городские справочники, объекты инфраструктуры, районы, муниципальные границы;
- ГАР/ФИАС: нормализация адресов;
- Роскадастр/кадастровые данные: здания, участки, зоны, если условия доступа позволяют импорт.

Целевая цепочка:

```text
Asset/Infrastructure Service
  -> Ticket Service: asset_id in ticket
  -> Dispatch Service: assignment by asset, department, zone
  -> SLA Service: SLA by asset type and priority
  -> Analytics Service: failures, repeat incidents, district statistics
  -> Report Service: department and city infrastructure reports
```

Потенциальные улучшения в бд:

```text
- За место INSERT, если идет вставка нескольких строк лучше использовать CopyFrom из pgx 
- Там где надо можно использовать upsert
- Сделать два пула, ReadPool и WritePool. чтобы записи на чтение трогали только реплики, а основную master ноду только на запись. 
- Добавить уровень логирования Debug или Info в pgxpool
```

## Масштабирование PostgreSQL: репликация и будущий шардинг

Зафиксированное архитектурное решение:

- `Ticket Service` в будущем шардировать по `department_id`, когда метрики подтвердят, что один PostgreSQL primary упирается в CPU, IOPS, размер данных или write throughput.
- До появления реальной необходимости в шардинге использовать для Ticket Service primary, standby, read replicas, партиционирование крупных таблиц и архивирование истории.
- `Auth Service`, `Department Service`, `Profile Service` и `Brigade Service` не шардировать без отдельного пересмотра архитектуры; масштабировать их PostgreSQL через репликацию.
- API Gateway собственной БД не имеет, поэтому репликация или шардинг ему не требуются.

План репликации:

- `Auth Service`: primary + synchronous standby для failover с минимальным риском потери пользователей, сессий и токенов; при необходимости отдельная asynchronous read replica.
- `Department Service`: primary + standby. Данных немного, поэтому шардинг не нужен; справочные чтения дополнительно распространять через Kafka-проекции.
- `Profile Service`: primary + standby + read replica для списков, поиска и профильных read-запросов.
- `Brigade Service`: primary + standby + read replica для поиска доступных бригад, зон, расписаний, состава и навыков.
- `Ticket Service`: сначала primary + synchronous standby + read replicas; позднее перейти к шардам.

Механизм PostgreSQL HA:

- использовать Patroni для управления PostgreSQL primary/standby, автоматического failover, promotion, switchover и защиты от split-brain;
- в Docker/VM-окружении использовать Patroni с кластером etcd или Consul как distributed configuration store;
- в Kubernetes использовать PostgreSQL Operator на базе Patroni либо оператор с эквивалентными HA-гарантиями;
- предоставить отдельные стабильные endpoints для записи и чтения: `postgres-primary` и `postgres-replicas`;
- использовать HAProxy или Kubernetes Services для маршрутизации к текущему primary и доступным replicas;
- использовать PgBouncer для пула соединений и быстрого переподключения после failover;
- Patroni не считать заменой backup/PITR, мониторинга, streaming replication или PgBouncer;
- регулярно проводить автоматизированные failover-тесты и проверять RPO, RTO, replication lag и восстановление соединений приложений.

Совместная работа с Istio:

- Patroni отвечает за роли PostgreSQL и failover, Istio — за сетевой трафик сервисов; Istio не заменяет Patroni, HAProxy или PgBouncer;
- PostgreSQL/Patroni pods по умолчанию держать вне service mesh (`sidecar.istio.io/inject: "false"`), если нет подтверждённой необходимости проксировать DB-трафик через Envoy;
- Go-сервисы могут оставаться внутри Istio mesh и подключаться к PgBouncer или стабильным Kubernetes Services;
- Patroni REST API и PostgreSQL health probes не должны блокироваться Istio mTLS или сетевыми политиками;
- после failover старые DB-соединения считаются недействительными: приложения должны переподключаться и безопасно повторять только идемпотентные операции.

Правила будущего шардинга Ticket Service:

- shard key: `department_id`;
- заявку и связанные данные хранить на одном шарде: `tickets`, status history, assignment history, attachment metadata, idempotency keys и outbox events;
- не использовать `ticket_id` как основной shard key, поскольку основные операционные выборки выполняются в границах департамента;
- для маршрутизации поддерживать единый алгоритм `department_id -> shard`;
- глобальные отчёты и межшардовую аналитику строить асинхронно через Kafka и отдельные read-модели/ClickHouse;
- межшардовые транзакции не вводить: согласованность между шардами и сервисами обеспечивать событиями, outbox/inbox и идемпотентными consumer'ами;
- миграцию департамента между шардами проектировать как отдельный управляемый процесс с двойной записью или временной остановкой изменений, верификацией и переключением маршрута.

Порядок внедрения:

1. Настроить backup, point-in-time recovery и регулярную проверку восстановления.
2. Развернуть PostgreSQL streaming replication под управлением Patroni и DCS-кластер etcd/Consul.
3. Добавить PgBouncer и стабильные write/read endpoints через HAProxy или Kubernetes Services.
4. Настроить автоматический failover и регулярно проверять его контролируемым отключением primary.
5. Разделить подключения приложений на `WRITE_DB` и `READ_DB`; транзакции и проверки актуального состояния всегда направлять в primary.
6. Добавить мониторинг replication lag, CPU, IOPS, locks, latency, размера таблиц и скорости роста.
7. Партиционировать по времени крупные history/outbox/inbox таблицы и настроить архивирование.
8. Добавить read replicas для Ticket, Profile и Brigade.
9. Начинать шардинг Ticket Service только по измеренным порогам и после нагрузочных тестов.
- Вести реестр городских объектов: освещение, дороги, остановки, здания, дворы и инженерные объекты.
- Хранить геометрию в PostGIS, ответственный департамент, технический паспорт, статус и нормативы обслуживания.
- Хранить историю статусов, инцидентов, ремонтов, осмотров и замен.
- Связывать заявки с `asset_id` и объединять повторные обращения по одному объекту в инцидент.
- Поддерживать плановое обслуживание и автоматическое создание заявок по результатам осмотров.
- Рассчитывать риск повторной поломки и приоритет профилактики.
- Интегрировать Asset с Ticket, Dispatch, SLA, File, Analytics и Report Service.
- Предусмотреть импорт из OpenStreetMap и городских открытых данных.
