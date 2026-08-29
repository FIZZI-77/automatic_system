# TODO

Этот файл содержит только незавершённую работу. Реализованные возможности
перечислены кратко, чтобы не смешивать текущее состояние с планом.

## Текущее состояние

- Реализованы доменные сервисы Auth, Profile, Department, Brigade, Ticket,
  Location, Routing, Dispatch, File, SLA, Notification, Audit, Analytics,
  Report и Asset.
- Frontend поддерживает рабочие пространства жителя, работника, диспетчера и
  администратора, карты, заявки, бригады, маршруты, уведомления, отчёты и
  паспорта объектов.
- Межсервисные операции используют gRPC, Kafka, transactional outbox,
  идемпотентные consumer-обработчики, retry и DLQ там, где они нужны текущим
  бизнес-процессам.
- Analytics Service получает доменные события Kafka и хранит read model в
  ClickHouse. Уже доступны обзор заявок, среднее время реакции/выполнения,
  SLA, дневная динамика, разбивки и базовая аналитика Asset Service.
- Kubernetes-стек включает Istio ingress/service mesh, NetworkPolicy,
  Prometheus, Grafana, OpenTelemetry Collector, Jaeger, Kiali,
  Elasticsearch, Filebeat и Kibana.
- PostgreSQL работает через PgBouncer и Patroni; Ticket Service использует
  Citus с `department_id` как ключом распределения. Настроены backup jobs и
  инфраструктурные dashboards.
- CI собирает сервисы, миграторы и ClickHouse init image, проверяет Kubernetes
  manifests и поддерживает dev/prod deployment с immutable SHA tags.
- Для локальной публичной демонстрации используется ngrok через Istio ingress;
  URL синхронизируется с Auth Service автоматически.

## Приоритет разработки

1. Расширить операционную аналитику Dispatch, Routing, Brigade и Ticket.
2. Завершить сквозные E2E и негативные сценарии для всех ролей и API.
3. Довести backup/restore, alerting, security и delivery до production-уровня.
4. Расширить reconciliation, импорт и прогнозную аналитику Asset Service.

## Analytics Service: операционная аналитика

### 1. Событийные контракты и качество данных

- Добавить в Dispatch Service transactional outbox и публикацию полного
  жизненного цикла в `dispatch.events.v1`:
  `dispatch.requested`, `dispatch.candidates_ranked`, `dispatch.reserved`,
  `dispatch.assigned`, `dispatch.failed`, `dispatch.expired` и
  `dispatch.canceled`.
- Передавать в Dispatch events: `operation_id`, `ticket_id`, `department_id`,
  `brigade_id`, `route_id`, `mode`, `status`, `failure_code`,
  `failure_reason`, `candidate_count`, `reachable_candidate_count`,
  `requested_at`, `reserved_at`, `assigned_at`, `occurred_at` и `trace_id`.
- Расширить Routing events полями `calculation_started_at`,
  `calculation_finished_at`, `calculation_duration_ms`, `engine`,
  `travel_mode`, `distance_meters`, `duration_seconds`, `success` и
  нормализованным `failure_code`.
- Проверить Brigade events и добавить недостающие данные для проекции текущего
  состава: `department_id`, `brigade_id`, `user_id`, статус участника,
  доступность, роль, начало/конец смены и `occurred_at`.
- Установить единые правила envelope для всех событий: стабильный `event_id`,
  `event_type`, `event_version`, `occurred_at`, `producer`, `trace_id` и
  идентификаторы агрегатов.
- Добавить schema/contract tests, которые гарантируют, что Analytics Service
  сможет извлечь поля из payload независимо от языка и регистра имён.
- Сохранять неизвестные версии событий, но не включать их в проекции до
  появления явного преобразователя; отслеживать их отдельной метрикой.

### 2. Обязательные показатели

- **Время назначения бригады**: считать от `ticket.created` или
  `dispatch.requested` до успешного `ticket.assigned`/`dispatch.assigned`.
  Отдавать average, median, p90, p95 и p99 по периоду, департаменту, категории,
  приоритету и режиму `MANUAL/AUTOMATIC`.
- Не смешивать время назначения с текущим `AvgResponseSeconds`: сохранить
  существующий показатель для обратной совместимости, но добавить отдельный
  `assignment_time` с однозначной формулой.
- **Нагрузка по бригадам**: активные `ASSIGNED/IN_PROGRESS` заявки, завершённые
  заявки за период, входящий поток, backlog, среднее число параллельных задач,
  время занятости и доля занятости относительно рабочего расписания.
- **Количество активных работников**: текущее число доступных работников и
  работников на смене; показывать общее значение, по департаментам и бригадам.
  Отдельно считать работников без активной бригады и бригады без достаточного
  состава.
- **Ошибки Dispatch**: количество и процент `FAILED/EXPIRED/CANCELED`, причины,
  стадия отказа, ручной/автоматический режим, затронутые департаменты и
  категории. Для каждой ошибки сохранять ссылку на `trace_id`.
- **Время построения маршрута**: average, median, p90, p95 и p99 по Routing
  Service, Valhalla, режиму движения и успешности. Не использовать ETA маршрута
  как длительность вычисления — это разные показатели.

### 3. Дополнительные полезные показатели

- Воронка назначения:
  `requested -> candidates found -> reserved -> route built -> assigned`, с
  conversion rate и временем между этапами.
- Доля заявок без подходящей бригады, без доступного маршрута и с истёкшей
  reservation; top причин по департаментам и категориям.
- Эффективность автоматического назначения: success rate, доля ручных
  переназначений после auto-dispatch и сравнение времени назначения с ручным
  режимом.
- Баланс нагрузки: максимальная/средняя нагрузка, коэффициент вариации и Gini
  по активным заявкам бригад. Это позволит увидеть, когда часть бригад
  перегружена, а часть простаивает.
- Время до выезда: от назначения до первого валидного движения машины или
  перехода заявки в `IN_PROGRESS`.
- Точность ETA: сравнивать прогноз Routing Service с фактическим временем
  прибытия, когда появится надёжное событие прибытия в геозону заявки.
- Частота перестроения и отмены маршрутов, доля недостижимых кандидатов,
  средняя длина маршрута и километры на одну завершённую заявку.
- Производительность бригад: completed per shift, среднее и p95 времени
  выполнения, SLA breach rate и повторные обращения по тому же объекту.
- Возраст очереди: average/p95 времени активных неназначенных заявок и buckets
  `0-5`, `5-15`, `15-30`, `30-60`, `60+` минут.
- Capacity forecast: почасовая/дневная сезонность входящих заявок и прогноз
  требуемого числа бригад по департаменту. Начать с прозрачной moving average,
  не вводить ML до накопления и проверки данных.

### 4. ClickHouse read models и API

- Добавить версионируемые проекции/materialized views для assignment funnel,
  brigade workload, active workers, dispatch failures и routing latency.
- Для текущего состояния бригад и работников использовать
  `argMax(..., occurred_at)`; для длительностей хранить исходные timestamps и
  агрегаты, чтобы можно было пересчитать percentiles.
- Добавить методы Analytics gRPC API и Gateway endpoints для новых показателей;
  поддержать фильтры периода, департамента, категории, приоритета, бригады,
  режима назначения и причины ошибки.
- Добавить frontend-блоки с drill-down до заявки/бригады и ссылкой на Jaeger по
  `trace_id`; пустые выборки показывать как «Нет данных», а не как нулевую
  производительность.
- Добавить freshness/lag indicators: время последнего события, consumer lag,
  долю ошибок проекции и число событий неизвестной версии.
- Реализовать replay в новую таблицу/версию проекции с атомарным переключением;
  проверить повторную обработку, дедупликацию и сверку итогов со source DB.
- Добавить unit tests для формул, ClickHouse integration tests и E2E от
  доменного события до Analytics API и frontend.

## Frontend и E2E

- Завершить Playwright-сценарий
  `житель -> диспетчер -> бригада -> маршрут -> отчёт/PDF -> завершение`.
- Проверить права и изоляцию департаментов для всех ролей, включая отсутствие
  worker-only запросов у обычного жителя.
- Добавить контрактные проверки всех публичных API Gateway routes.
- Добавить visual regression tests, keyboard/focus/ARIA проверки и основные
  адаптивные разрешения.
- Сделать детерминированный seed/cleanup и отдельный профиль окружения `e2e`.
- Для каждой критичной ручки проверять valid/invalid/forbidden/not-found/conflict,
  DB/Kafka/outbox/DLQ side effects, полный trace и наличие структурированных
  error/warn logs.

## Надёжность доменных сервисов

- Ticket retention: добавить E2E для `DONE/CANCELED -> ARCHIVED -> PURGED`,
  метрики воркеров и подтверждение удаления связанных объектов File Service.
- File Service: antivirus scan, thumbnails, lifecycle cleanup и интеграционные
  тесты upload/confirm/link/download/delete, включая сбои MinIO и компенсацию.
- SLA Service: reconciliation deadline state, метрики scanner lag/errors и E2E
  изменения приоритета, отмены, завершения и breach.
- Notification Service: production SMTP/SMS adapters и E2E восстановления
  WebSocket с доставкой пропущенных общих уведомлений.
- Audit Service: политика retention/archive и E2E контроля доступа к audit
  trail.
- Проверить retry/DLQ/replay каждого Kafka consumer на poison message,
  временной недоступности брокеров и смене лидера partition.

## Asset Service

- Усилить автоматическое сопоставление заявки с ближайшим объектом по
  координатам, адресу, категории проблемы и зоне ответственности.
- Реализовать объединение дублирующих заявок в инфраструктурный инцидент и
  единое назначение бригады на него.
- Автоматизировать расписания осмотров/обслуживания и создание заявки по
  выявленной проблеме.
- Калибровать `risk_score` на фактической истории; учитывать повторные поломки,
  SLA, возраст, сезонность и просроченную профилактику.
- Расширить аналитику объектов по типу, району, повторным поломкам, стоимости
  обслуживания, SLA и необходимости капитальной замены.
- Проверить импорт/reconciliation OSM и городских источников, нормализацию
  адресов и безопасный replay.

## Production hardening и эксплуатация

- Защитить публичные observability endpoints через SSO/RBAC и TLS; не
  публиковать Jaeger, Kibana, Grafana и Kiali через демонстрационный ngrok.
- Настроить и проверить retention/snapshot lifecycle/alerting для
  Elasticsearch, Jaeger, Prometheus и ClickHouse.
- Регулярно выполнять restore drills PostgreSQL/PITR, Redis, ClickHouse, MinIO
  и проверять RPO/RTO, а не только успешность backup jobs.
- Добавить alerts на Patroni failover, replication lag, Citus shard imbalance,
  PgBouncer saturation, Kafka under-replicated partitions/consumer lag,
  Redis failover и заполнение PVC.
- Проверить разделение read/write pools всех сервисов: транзакции и проверки
  актуального состояния направлять через PgBouncer primary, допускающие
  задержку чтения — через replicas.
- Добавить автоматические controlled-chaos тесты отказа pod, PostgreSQL primary,
  Kafka broker/leader, Redis primary, ClickHouse и MinIO с измерением RTO и
  проверкой отсутствия потери/дублирования бизнес-операций.
- Дополнить CI migration up/down/compatibility checks, race/fuzz coverage,
  dependency/container scanning и smoke после deployment.
- Перенести runtime secrets в внешний secret manager; ngrok оставить только
  инструментом локальной демонстрации.
- Зафиксировать версии внешних images вместо `latest`, добавить регулярный
  контролируемый dependency/image update process.

## Критерии готовности новой аналитики

- Формула каждого показателя документирована и покрыта тестами на граничных
  случаях, пропущенных/дублированных и пришедших не по порядку событиях.
- Average всегда сопровождается median и p95; для operational latency также
  доступен p99 и размер выборки.
- Все показатели фильтруются по времени и бизнес-разрезам без high-cardinality
  labels в Prometheus: бизнес-аналитика хранится в ClickHouse.
- Replay даёт тот же результат, что online processing, а расхождения со source
  DB видны в reconciliation отчёте.
- Dashboard показывает freshness и явно отличает «0» от «данные ещё не
  поступили».
- Dispatch failure и Routing latency можно открыть до конкретного trace в
  Jaeger и связанных структурированных логов.
