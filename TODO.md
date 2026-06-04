# TODO

## Итоговая архитектура сервисов

| Сервис | Хранилище | gRPC | Что читает из событий | Что публикует | Outbox |
| --- | --- | --- | --- | --- | --- |
| API Gateway | нет | да | нет | нет | нет |
| Auth Service | PostgreSQL | да | опционально | `auth.events` | да, если публикует события |
| Department Service | PostgreSQL | да | опционально | `departments.events` | да |
| Ticket Service | PostgreSQL | да | опционально | `tickets.events` | да |
| Brigade Service | PostgreSQL | да | опционально | `brigades.events` | да |
| Location Service | Redis + SQL/PostGIS | да | опционально | `locations.events` | по ситуации |
| Routing Service | Redis + PostgreSQL/PostGIS, опционально OSRM/GraphHopper | да | `tickets.events`, `brigades.events`, `locations.events`, `dispatch.events` | `routing.events` | по ситуации |
| Dispatch Service | PostgreSQL | да | `tickets.events`, `departments.events`, `brigades.events`, `routing.events` | `dispatch.events` | да |
| File Service | PostgreSQL + S3/MinIO | да | опционально: `tickets.events`, `users/departments events` | `files.events` | да |
| Notification Service | PostgreSQL/Redis | опционально | `tickets.events`, `departments.events`, `brigades.events`, `dispatch.events`, `routing.events`, `files.events`, `sla.events` | `notifications.events` | по ситуации |
| Report Service | PostgreSQL + S3/MinIO, опционально ClickHouse read | да/опционально | `tickets.events`, `dispatch.events`, `sla.events`, `files.events`, analytics read-models | `reports.events` | да |
| Analytics Service | ClickHouse | нет/опционально | все доменные события | нет | нет |
| Audit Service | PostgreSQL | опционально | все доменные события | нет | нет |
| SLA Service | PostgreSQL | нет/опционально | `tickets.events` | `sla.events` | да |

## Рекомендуемый порядок разработки

1. Department Service.
2. Brigade Service.
3. Интеграция Ticket Service с правилами доступа через Department/Brigade.
4. Location Service.
5. Routing Service.
6. Dispatch Service.
7. File Service.
8. SLA Service.
9. Notification Service.
10. Audit Service.
11. Analytics Service.
12. Report Service.

## Инфраструктурный стек

Целевой стек:

```text
Go + gRPC
PostgreSQL + PostGIS
Redis
ClickHouse
S3/MinIO
Kafka
Traefik -> Istio
Docker -> Kubernetes
OpenTelemetry
Jaeger
Prometheus + Grafana
ELK
```

Роли компонентов:

- Go + gRPC: основная реализация микросервисов и внутренние синхронные вызовы.
- PostgreSQL: основное транзакционное хранилище доменных сервисов.
- PostGIS: геоданные, зоны ответственности, районы, пространственные запросы.
- Redis: кэш, оперативное состояние, текущие координаты, rate limit, временные блокировки.
- ClickHouse: аналитика, агрегаты, тяжелые read-запросы и отчеты.
- S3/MinIO: хранение файлов через File Service.
- Kafka: доменные события, интеграции, асинхронные реакции, аналитические потоки.
- Traefik: входной reverse proxy/API edge на раннем этапе.
- Istio: service mesh позже, после перехода на Kubernetes и роста числа сервисов.
- Docker: локальная разработка и ранняя сборка окружения.
- Kubernetes: целевая оркестрация сервисов.
- OpenTelemetry: единый стандарт инструментирования, контекст trace/span, сбор traces/metrics/logs.
- Jaeger: хранение и просмотр distributed tracing.
- Prometheus: сбор и хранение метрик.
- Grafana: dashboards и визуализация метрик/части логов/трейсов.
- ELK: централизованные логи, поиск по логам, расследование инцидентов.

OpenTelemetry не заменяет Jaeger, Prometheus или ELK. Он отвечает за то, как сервисы создают и передают наблюдаемость: trace context, spans, metrics, logs и baggage. Jaeger, Prometheus и ELK отвечают за хранение, поиск и визуализацию этих данных.

Рекомендуемый ввод по фазам:

1. Docker Compose, PostgreSQL, Redis, Kafka, MinIO, базовый Prometheus/Grafana.
2. OpenTelemetry tracing между API Gateway и основными gRPC-сервисами.
3. Jaeger для просмотра распределенных трейсов.
4. ELK для централизованных логов.
5. Kubernetes после стабилизации основных сервисов.
6. Istio после Kubernetes, когда появится реальная потребность в service mesh: mTLS, traffic splitting, retries, circuit breaking, observability на уровне mesh.

Правила для Kafka:

- Именовать топики версионно: `tickets.events.v1`, `brigades.events.v1`, `dispatch.events.v1`.
- Публиковать события факта, а не команды: `TicketCreated`, `BrigadeAssigned`, `SlaViolated`.
- Использовать outbox pattern в сервисах, которые публикуют доменные события.
- Добавить outbox relay: `PostgreSQL outbox_events -> Kafka topic`.
- Делать consumer idempotent: повторная обработка одного события не должна ломать состояние.
- Использовать retry topics и dead-letter topics для ошибок обработки.

## Общая доменная цепочка

```text
Ticket category/problem
  -> Department
    -> Brigade
      -> Dispatch assignment
        -> Location/Routing/SLA/Notification
```

Внешний синхронный слой:

```text
Client
  -> API Gateway
    -> Auth Service
    -> Department Service
    -> Ticket Service
    -> Brigade Service
    -> Location Service
    -> Routing Service
    -> Dispatch Service
```

Асинхронный слой событий:

```text
Auth/Ticket/Department/Brigade/Location/Routing/Dispatch/File/SLA
  -> domain events
    -> Notification Service
    -> Report Service
    -> Analytics Service
    -> Audit Service
    -> SLA Service
```

## Department Service

- Хранит отделы/городские службы: ЖКХ, дороги, электросети, водоканал и другие.
- Определяет владение категориями заявок или зонами ответственности.
- Может хранить связи с администраторами и диспетчерами отдела.
- Является родительской сущностью для Brigade Service: бригады принадлежат отделам.
- Публикует `departments.events` при создании, изменении, отключении отдела или изменении его зон ответственности.

## Brigade Service

- Хранит бригады, их принадлежность к отделам и состав участников.
- Дает надежный lookup `user_id -> brigade_id` для Ticket Service и Dispatch Service.
- Может хранить роли внутри бригады, специализации, активность и доступность.
- Публикует `brigades.events` при создании бригады, изменении состава, статуса или отдела.

## Ticket / Brigade access

- После реализации Brigade Service добавить надежный lookup `user_id -> brigade_id`.
- Для операций с заявками передавать или резолвить `actor_brigade_id` на серверной стороне.
- Пользователи с ролью бригады могут менять и завершать только заявки, назначенные на их бригаду:
  `ticket.brigade_id != nil && ticket.brigade_id == actor_brigade_id`.
- Роли `admin` и `dispatcher` остаются привилегированными и могут управлять заявками между разными бригадами.
- Не доверять `brigade_id`, пришедшему напрямую от клиента, для проверки доступа.

## Dispatch Service

- Читает `tickets.events`, `departments.events`, `brigades.events`, `routing.events`.
- Отвечает за назначение заявок на отделы и бригады.
- Может учитывать категорию заявки, зону, доступность бригад, специализацию и текущую нагрузку.
- Публикует `dispatch.events`: заявка назначена, переназначена, назначение отменено, назначение просрочено.
- Не должен владеть основной сущностью заявки, а только процессом диспетчеризации.

## SLA Service

- Читает `tickets.events`.
- Считает сроки реакции и выполнения по категории, приоритету, отделу или другим правилам.
- Публикует `sla.events`: SLA создан, приближается дедлайн, SLA нарушен, SLA выполнен.
- Может использоваться Notification Service для уведомлений о рисках и просрочках.

## Notification Service

- Читает события заявок, отделов, бригад, диспетчеризации и SLA.
- Отправляет уведомления пользователям, диспетчерам, администраторам и участникам бригад.
- Может использовать PostgreSQL для истории уведомлений и Redis для временных состояний, очередей или rate limit.
- Публикация `notifications.events` нужна по ситуации, например для аудита доставки.

## Location Service

- Хранит оперативные координаты в Redis.
- Для исторических или географических запросов использует SQL/PostGIS.
- Публикует `locations.events` по ситуации: обновление позиции, потеря сигнала, вход/выход из зоны.
- Полезен после появления Brigade Service и перед Routing/Dispatch Service, когда координаты начинают участвовать в назначениях.

## Routing Service

- Отвечает за подбор оптимальной свободной бригады с учетом географии и построение маршрута до точки заявки.
- Используется для экстренных и приоритетных заявок, где важны ETA, расстояние, зона ответственности и доступность бригады.
- Запрашивает кандидатов у Brigade Service: свободные бригады нужного отдела, специализации и допуска.
- Запрашивает текущие координаты у Location Service.
- Считает ETA, расстояние и маршрут до точки заявки.
- Может использовать OSRM для MVP, GraphHopper/Valhalla для более гибких сценариев или PostGIS/pgRouting для собственного контроля над графом дорог.
- Возвращает Dispatch Service лучшего кандидата, маршрут, расстояние, время прибытия и краткое объяснение выбора.
- Публикует `routing.events` по ситуации: маршрут построен, кандидат выбран, маршрут пересчитан, маршрут недоступен.
- Не должен владеть назначением заявки. Назначение остается ответственностью Dispatch Service.

Сценарий автоматического назначения:

```text
Emergency Ticket
  -> Dispatch Service
    -> Brigade Service: найти подходящие свободные бригады
    -> Location Service: получить текущие координаты
    -> Routing Service: посчитать ETA и маршрут
    -> Dispatch Service: назначить оптимальную бригаду
```

## File Service

- Является единым сервисом для файлов и вложений, а не дублируется внутри каждого доменного сервиса.
- Хранит бинарные файлы в S3-совместимом хранилище: MinIO для local/dev, S3/Object Storage для production.
- Хранит метаданные файлов в PostgreSQL: `file_id`, `resource_type`, `resource_id`, `uploaded_by`, `file_name`, `content_type`, `size_bytes`, `object_key`, `checksum`, `status`, timestamps.
- Генерирует presigned upload/download URL, чтобы файлы не проходили через API Gateway или gRPC-сервисы.
- Поддерживает статусы файла: `pending_upload`, `uploaded`, `linked`, `deleted`, `quarantined`.
- Может привязывать файл к разным сущностям: ticket, comment, profile, department, report.
- Не должен самостоятельно владеть бизнес-правилами доступа к доменной сущности.
- Для проверки доступа обращается к owner-сервису: например, для `resource_type = ticket` спрашивает Ticket Service, может ли пользователь читать заявку или прикреплять к ней файл.
- Публикует `files.events`: файл создан, загружен, привязан, удален, отправлен в карантин.
- Позже может отвечать за antivirus scan, thumbnails, lifecycle cleanup и лимиты загрузки.

Пример upload flow для вложения к заявке:

```text
Client
  -> API Gateway
    -> File Service: запросить upload URL для ticket attachment
      -> Ticket Service: проверить право прикрепить файл к заявке
      -> S3/MinIO: выдать presigned upload URL
```

Пример download flow:

```text
Client
  -> API Gateway
    -> File Service: запросить download URL
      -> Ticket Service: проверить право читать заявку
      -> S3/MinIO: выдать presigned download URL
```

Пример object key:

```text
tickets/{ticket_id}/{file_id}/{safe_file_name}
```

## Audit Service

- Читает все доменные события.
- Сохраняет неизменяемую историю важных действий: кто, что, когда и над какой сущностью сделал.
- Не должен быть синхронной зависимостью бизнес-сервисов.

## Analytics Service

- Читает все доменные события.
- Хранит аналитические данные в ClickHouse.
- Нужен для отчетов: количество заявок, скорость обработки, SLA, нагрузка отделов и бригад, проблемные зоны.
- Не должен влиять на выполнение основных бизнес-операций.

## Report Service

- Отвечает за формирование отчетов, выгрузок и документов: PDF, XLSX, CSV.
- Использует данные из Analytics Service/ClickHouse, доменных read-models или собственных проекций.
- Может сохранять готовые файлы через File Service или напрямую в S3/MinIO по внутреннему контракту.
- Поддерживает ручные отчеты по запросу пользователя и регламентные отчеты по расписанию.
- Примеры отчетов: заявки по отделам, нарушения SLA, нагрузка бригад, среднее время реакции, аварийные заявки, отчет по району, отчет по категории проблемы.
- Публикует `reports.events`: отчет запрошен, отчет сформирован, отчет не удалось сформировать, отчет скачан.
- Не должен быть частью Analytics Service: Analytics хранит и агрегирует данные, Report Service превращает их в документы и выгрузки.
- Для тяжелых отчетов должен работать асинхронно: принять запрос, поставить задачу, после готовности отдать ссылку на файл.

## Ticket attachments

- Реализовать через File Service после стабилизации базового ticket flow и правил доступа через Brigade Service.
- Ticket Service не должен хранить бинарные файлы и не должен напрямую работать с S3/MinIO.
- Ticket Service остается владельцем правил доступа к заявке.
- File Service хранит файл, метаданные и выдает presigned URL.
- Доступ к вложениям должен наследовать доступ к заявке: пользователь может загружать и скачивать файл только тогда, когда имеет доступ к связанной заявке.

## Profile Service и Brigade Service

### Полная логика Profile Service

Profile Service отвечает не за авторизацию, а за рабочий профиль сотрудника. Auth Service остается владельцем учетной записи, пароля, сессий и ролей доступа.

Расширенные сущности:

- `profiles` - основной профиль сотрудника.
- `profile_departments` - если сотрудник может состоять в нескольких департаментах.
- `profile_skills` - навыки и специализации сотрудника.
- `profile_certifications` - допуски, сертификаты, сроки действия.
- `profile_schedule` - регулярный график работы.
- `profile_absences` - отпуск, больничный, временная недоступность.
- `profile_status_history` - история изменения статуса.

Статусы профиля:

- `ACTIVE` - сотрудник активен.
- `INACTIVE` - временно не используется.
- `ON_SHIFT` - сотрудник на смене.
- `OFF_SHIFT` - сотрудник вне смены.
- `SUSPENDED` - заблокирован для операционной работы.

Расширенные методы:

- `CreateProfile`
- `GetProfileByID`
- `GetProfileByUserID`
- `ListProfiles`
- `ListProfilesByDepartment`
- `UpdateProfile`
- `DeactivateProfile`
- `AssignProfileToDepartment`
- `RemoveProfileFromDepartment`
- `ListProfileDepartments`
- `SetProfileStatus`
- `GetProfileStatusHistory`
- `AddProfileSkill`
- `RemoveProfileSkill`
- `ListProfileSkills`
- `AddProfileCertification`
- `RemoveProfileCertification`
- `ListProfileCertifications`
- `SetProfileSchedule`
- `GetProfileSchedule`
- `AddProfileAbsence`
- `RemoveProfileAbsence`
- `GetProfileAvailability`
- `CheckProfileCanJoinBrigade`

Доменные проверки:

- нельзя создать два профиля на один `user_id`;
- нельзя привязать профиль к несуществующему `department_id`;
- нельзя добавить сотрудника в бригаду, если профиль неактивен или заблокирован;
- нельзя добавить сотрудника в бригаду другого департамента без явной cross-department модели;
- нельзя считать сотрудника доступным, если он вне смены, в отпуске, на больничном или `SUSPENDED`;
- сертификаты и навыки должны учитываться при проверке допуска к типу работ.

События:

- `ProfileCreated`
- `ProfileUpdated`
- `ProfileDeactivated`
- `ProfileDepartmentChanged`
- `ProfileStatusChanged`
- `ProfileSkillAdded`
- `ProfileSkillRemoved`
- `ProfileAvailabilityChanged`

### Полная логика Brigade Service

Brigade Service отвечает за бригады как операционные единицы: состав, специализацию, принадлежность к департаменту, смены и доступность. Он не должен выбирать лучшую бригаду для заявки - это зона Dispatch Service.

Расширенные сущности:

- `brigades` - основная таблица бригад.
- `brigade_members` - состав бригады.
- `brigade_member_history` - история изменения состава.
- `brigade_skills` - специализации бригады.
- `brigade_schedule` - график работы бригады.
- `brigade_status_history` - история статусов.
- `brigade_zones` - зоны обслуживания, если нужны.
- `brigade_departments` - только если бригада может обслуживать несколько департаментов.

Статусы бригады:

- `ACTIVE` - бригада заведена и может использоваться.
- `INACTIVE` - временно не используется.
- `AVAILABLE` - доступна для назначения.
- `BUSY` - занята заявкой.
- `ON_ROUTE` - едет к заявке.
- `ON_SITE` - работает на месте.
- `OFFLINE` - недоступна.
- `ARCHIVED` - архивирована.

Роли участников:

- `LEAD` - старший бригады.
- `DRIVER` - водитель.
- `TECHNICIAN` - исполнитель/техник.
- `TRAINEE` - стажер, если нужен.

Расширенные методы:

- `CreateBrigade`
- `GetBrigadeByID`
- `ListBrigades`
- `ListBrigadesByDepartment`
- `UpdateBrigade`
- `DeactivateBrigade`
- `ArchiveBrigade`
- `AddBrigadeMember`
- `RemoveBrigadeMember`
- `ChangeBrigadeMemberRole`
- `ListBrigadeMembers`
- `GetBrigadeMemberHistory`
- `SetBrigadeStatus`
- `GetBrigadeStatusHistory`
- `AddBrigadeSkill`
- `RemoveBrigadeSkill`
- `ListBrigadeSkills`
- `SetBrigadeSchedule`
- `GetBrigadeSchedule`
- `SetBrigadeZone`
- `ListBrigadeZones`
- `GetAvailableBrigades`
- `CheckBrigadeCanHandleTicket`

Доменные проверки:

- нельзя создать две активные бригады с одинаковым названием в одном департаменте;
- нельзя создать бригаду с несуществующим `department_id`;
- нельзя добавить одного сотрудника в одну бригаду дважды;
- нельзя добавить неактивный или заблокированный профиль;
- нельзя добавить профиль из другого департамента, если бригада не cross-department;
- в активной бригаде должен быть минимум один участник;
- для некоторых типов работ можно требовать `LEAD`, `DRIVER` или конкретный skill/certification;
- `AVAILABLE` возможен только если бригада активна, на смене и имеет валидный состав;
- нельзя назначать бригаду на заявку другого департамента;
- нельзя назначать бригаду, если она `BUSY`, `OFFLINE`, `INACTIVE` или `ARCHIVED`.

События:

- `BrigadeCreated`
- `BrigadeUpdated`
- `BrigadeDeactivated`
- `BrigadeArchived`
- `BrigadeMemberAdded`
- `BrigadeMemberRemoved`
- `BrigadeMemberRoleChanged`
- `BrigadeStatusChanged`
- `BrigadeAvailabilityChanged`
- `BrigadeSkillAdded`
- `BrigadeSkillRemoved`

Граница ответственности:

- Brigade Service говорит, существует ли бригада, кто в составе, к какому департаменту относится, доступна ли она и может ли выполнить тип работ.
- Ticket Service хранит заявку, `department_id`, статус и назначенный `brigade_id`.
- Location Service хранит текущие координаты.
- Routing Service считает расстояние и маршрут.
- Dispatch Service выбирает лучшую бригаду и инициирует назначение.

Department Service должен оставаться справочником департаментов и владеть только таблицей `departments`. Он не должен хранить связи с пользователями, бригадами или услугами. Другие сервисы должны ссылаться на департамент через `department_id`.

### Profile Service

Profile Service должен владеть профилями пользователей/сотрудников и их привязкой к департаменту.

Рекомендуемые поля профиля:

- `id`
- `user_id` - ссылка на пользователя из Auth Service
- `department_id` - ссылка на Department Service
- `full_name`
- `phone`
- `position`
- `status`
- `created_at`
- `updated_at`

Рекомендуемые методы:

- `CreateProfile`
- `GetProfileByID`
- `GetProfileByUserID`
- `ListProfiles`
- `ListProfilesByDepartment`
- `UpdateProfile`
- `DeactivateProfile`

Если сотрудник может работать только в одном департаменте, достаточно поля `profiles.department_id`. Если сотрудник может состоять в нескольких департаментах, связь нужно хранить в Profile Service через таблицу `profile_departments`, а не в Department Service.

Перед записью `department_id` Profile Service должен синхронно проверять департамент через `DepartmentService.GetDepartmentByID` или использовать локальную read-model/cache по событиям `departments.events`.

### Brigade Service

Brigade Service должен владеть бригадами, составом бригад и их принадлежностью к департаменту.

Рекомендуемые поля бригады:

- `id`
- `department_id` - ссылка на Department Service
- `name`
- `status`
- `specialization`
- `created_at`
- `updated_at`

Рекомендуемые таблицы:

- `brigades` - основная таблица бригад
- `brigade_members` - участники бригады, ссылки на `profile_id` или `user_id`

Рекомендуемые методы:

- `CreateBrigade`
- `GetBrigadeByID`
- `ListBrigades`
- `ListBrigadesByDepartment`
- `UpdateBrigade`
- `DeactivateBrigade`
- `AddBrigadeMember`
- `RemoveBrigadeMember`
- `ListBrigadeMembers`

Если бригада принадлежит одному департаменту, достаточно поля `brigades.department_id`. Если бригада может обслуживать несколько департаментов, связь нужно хранить в Brigade Service через таблицу `brigade_departments`.

Ticket Service должен хранить `ticket.department_id` и опционально `ticket.brigade_id`. При назначении бригады нужно проверять, что бригада из Brigade Service относится к тому же `department_id`, что и заявка.

## Production readiness TODO

- Config validation: вынести чтение env в typed config для каждого сервиса, проверять обязательные поля на старте, задавать безопасные defaults.
- Health/readiness: добавить gRPC health checking для Auth/Ticket/Department/Brigade и readiness проверки DB/dependencies/migrations.
- Panic recovery: добавить gRPC recovery interceptor, чтобы panic в handler/service не ронял процесс.
- Metrics: добавить Prometheus/OpenTelemetry metrics для request count, latency histogram, error codes, DB pool stats и базовых business metrics.
- Distributed tracing: добавить OpenTelemetry traces для цепочек `API Gateway -> gRPC service -> DB`.
- Rate limiting: добавить rate limit в API Gateway для `login`, `register`, `refresh`, `request-password-reset`, `reset-password`.
- Rate limiting production: текущий Gateway rate limit можно держать in-memory на раннем этапе, но для нескольких реплик Gateway вынести лимиты в Redis/distributed limiter и сделать значения env-configurable.
- Request limits: ограничить размер HTTP body в API Gateway, особенно до реализации File/S3 attachments.
- CORS: добавить env-configurable CORS middleware для будущего frontend.
- DB pool tuning: настроить `SetMaxOpenConns`, `SetMaxIdleConns`, `SetConnMaxLifetime`, `SetConnMaxIdleTime` для каждого Postgres connection pool.
- Department tests: довести Department Service до уровня Auth/Ticket: validator, service, repository, integration tests.
- API Gateway tests: добавить tests для middleware, request_id propagation, gRPC error mapping и handlers с mock gRPC clients.
- Outbox relay: если outbox остается частью архитектуры, реализовать worker/relay, retry policy и error/dead-letter state.
- CI pipeline: добавить автоматический `go test`, lint, race tests, migration checks и сборку Docker images.
- Secrets management: для production заменить `.env` на secret manager/Kubernetes secrets/CI secrets.
- Shared package: позже вынести `closer`, `requestid`, `accesslog`, config helpers и error helpers в общий shared module, чтобы убрать дублирование между сервисами.

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
