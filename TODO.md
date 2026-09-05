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
  SLA, дневная динамика, разбивки, базовая аналитика Asset Service и отдельные
  распределения времени назначения/расчёта маршрута (average, median, p90,
  p95, p99 и sample count).
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

- Dispatch Service публикует через transactional outbox в
  `dispatch.events.v1` жизненный цикл `dispatch.requested`,
  `dispatch.candidates_ranked`, `dispatch.reserved`, `dispatch.route_built`,
  `dispatch.assigned`, `dispatch.failed`, `dispatch.expired` и
  `dispatch.canceled`. Добавить Kafka integration/E2E с проверкой retry,
  исчерпания попыток и восстановления зависших `PROCESSING` событий.
- Базовый Dispatch payload содержит `operation_id`, `ticket_id`,
  `department_id`, `category_id`, `priority`, `brigade_id`, `route_id`, `mode`,
  `status`, `failure_code`, `failure_reason`, числа кандидатов, timestamps
  этапов, `occurred_at`, `trace_id` и явный `failure_stage`. Чистые contract
  tests покрывают все восемь типов, envelope и stage timestamps; PostgreSQL
  integration дополнительно проверяет транзакционность ключевых переходов.
- Routing events успешного и неуспешного расчёта содержат `calculation_started_at`,
  `calculation_finished_at`, `calculation_duration_ms`, `engine`,
  `travel_mode`, `distance_meters`, `duration_seconds`, `success`,
  нормализованный `failure_code` и единый envelope. Неуспешный первичный
  расчёт использует Ticket aggregate и не создаёт фиктивный Route.
- Brigade member/status/schedule events содержат `department_id`, `brigade_id`,
  `member_id`, `user_id`, статус участника, доступность, роль и `occurred_at`.
  Фактический lifecycle смен реализован отдельными transactional-outbox
  событиями `BrigadeShiftStarted/BrigadeShiftEnded`: первый переход в
  `AVAILABLE` открывает смену, возвраты из рабочих статусов её не дублируют,
  `OFFLINE/INACTIVE/ARCHIVED` закрывают. Плановое расписание в этих формулах не
  используется.
- Установить единые правила envelope для всех событий: стабильный `event_id`,
  `event_type`, `event_version`, `occurred_at`, `producer`, `trace_id` и
  идентификаторы агрегатов.
- Базовые contract tests Analytics проверяют извлечение полей Dispatch,
  Routing и Brigade из snake_case, CamelCase, имён с дефисами и вложенного
  `Data`; fixtures покрывают все текущие типы Dispatch/Routing/Brigade.
  Запускать их совместно с producer-модулями в CI.
- Analytics сохраняет неизвестные версии событий с
  `projection_eligible=false`, не включает их в проекции и считает метрикой
  `analytics_unknown_event_versions_total`. API и dashboard показывают их
  количество, freshness, ingestion p95 и расхождения raw/projection. Явный
  преобразователь добавлять вместе с первым реальным контрактом версии 2.

### 2. Обязательные показатели

- **Время назначения бригады**: базовое распределение от `dispatch.requested`
  (с fallback на `ticket.created`) до успешного назначения и группированные
  ряды по департаменту, категории, приоритету, режиму `MANUAL/AUTOMATIC` и
  бригаде реализованы в отдельном `assignment_time`.
- Существующий `AvgResponseSeconds` сохранён для обратной совместимости и не
  смешивается с `assignment_time`.
- **Нагрузка по бригадам**: ClickHouse read model считает по каждой бригаде
  текущие `ASSIGNED/IN_PROGRESS`, созданные, назначенные и завершённые заявки
  за период, а также общий backlog неназначенных `NEW`; публичные
  Analytics/Gateway API и frontend-блок реализованы. По фактическим сменам
  считаются смено-часы, busy hours, среднее число параллельных задач,
  completed per shift и utilization; плановое расписание не используется.
- **Количество активных работников**: ClickHouse read model считает активных и
  доступных участников бригад по последнему member event, всего, по
  департаментам и бригадам; публичные Analytics/Gateway API и frontend-блок
  реализованы. Работники на фактической смене считаются по открытому shift
  lifecycle на момент snapshot.
  Для работников без активной бригады добавить поток worker-профилей, а для
  недостаточного состава — явный норматив минимального состава бригады.
- **Ошибки Dispatch**: ClickHouse read model считает количество и процент
  `FAILED/EXPIRED/CANCELED` по отдельным `operation_id`, а также разбивки по
  нормализованным причине и стадии отказа; доступны фильтры периода,
  департамента, категории, приоритета, бригады, режима назначения и причины.
  Публичные Analytics/Gateway API, frontend-блок и drill-down списка операций
  со ссылкой на Jaeger по `trace_id` реализованы.
- **Время построения маршрута**: базовое распределение по измеренной длительности
  вызова движка реализовано отдельно от ETA, включая группированные ряды по
  движку, режиму движения, успешности и нормализованной причине ошибки.

### 3. Дополнительные полезные показатели

- Воронка назначения: ClickHouse read model реализует
  `requested -> candidates found -> reserved -> route built -> assigned`,
  conversion rate относительно предыдущего этапа и распределение времени
  перехода (average, median, p90, p95, p99, sample count); публичные
  Analytics/Gateway API и frontend-визуализация реализованы.
- Доля заявок без подходящей бригады, без доступного маршрута и с истёкшей
  reservation реализована в Dispatch failure read model относительно всех
  `dispatch.requested`; публичный ответ и frontend показывают top-10 причин по
  департаментам и категориям с долей внутри каждой причины.
- Эффективность автоматического назначения: ClickHouse read model и публичный
  Analytics/Gateway API сравнивают `AUTOMATIC` и `MANUAL` по requested,
  assigned, success rate и распределению времени назначения;
  frontend-визуализация реализована. Доля ручных переназначений намеренно
  помечена как недоступная: Ticket Service должен поддержать безопасный переход
  `ASSIGNED -> ASSIGNED` со сменой `brigade_id` и публиковать
  `ticket.reassigned` с old/new brigade, actor, reason и occurred_at.
- Баланс нагрузки реализован по активным заявкам бригад: максимальная и
  средняя нагрузка, стандартное отклонение, коэффициент вариации и Gini.
  В выборку входят эксплуатационные бригады без заявок, поэтому простой не
  теряется; метрики доступны через Analytics/Gateway API и frontend.
- Время до выезда реализовано от назначения до первого принятого движения
  машины (`speed >= 5 км/ч`, `accuracy <= 50 м`) или `IN_PROGRESS`.
- Точность ETA реализована по последнему прогнозу ревизии маршрута и первому
  принятому Location-событию в геозоне назначения: sample count, bias, MAE,
  p95 absolute error и доля в пределах пяти минут.
- Реализованы частота перестроения и отмены маршрутов, доля недостижимых
  кандидатов, средняя длина маршрута и километры на завершённую заявку.
- Производительность бригад реализует completed per shift, average/p95 времени
  выполнения, SLA breach rate и повторы по `asset_id`.
- Возраст очереди реализует average/p95 и buckets `0-5`, `5-15`, `15-30`,
  `30-60`, `60+` минут.
- Capacity forecast реализован прозрачной формулой на дневном среднем,
  почасовом пике и среднем времени выполнения; ML намеренно не используется.

### 4. ClickHouse read models и API

- Версионируемая `domain_events_projection_v1` и materialized view используются
  всеми operational read models; raw events остаются источником replay.
- Текущее состояние бригад и работников восстанавливается через
  `argMax(..., occurred_at)`; длительности считаются из исходных timestamps,
  поэтому percentiles можно пересчитать.
- Analytics gRPC, Gateway endpoints и фильтры бизнес-разрезов реализованы.
- Frontend-блоки, Dispatch drill-down и Jaeger trace link реализованы; наличие
  shift lifecycle и ETA samples отображается отдельно от нулевого значения.
- Dashboard показывает freshness, ingestion p95, raw/projection reconciliation
  и неизвестные версии; Prometheus экспортирует consumer lag/errors/duration.
- Analytics consumer обрабатывает один offset до результата, выполняет пять
  попыток с bounded backoff и публикует poison message в `<topic>.dlq`; commit
  происходит только после ClickHouse Store или успешного DLQ publish.
- Replay строит новую версию таблицы, сверяет unique/eligible/unknown counts,
  атомарно переключает её и дочитывает события окна переключения. Остаётся
  добавить внешнюю сверку итогов с source PostgreSQL в restore/reconciliation
  runbook.
- Unit tests формул, ClickHouse integration fixtures и Gateway/frontend API
  contract E2E добавлены. CI job поднимает ClickHouse 25.8, применяет схему и
  запускает integration suite; отдельный frontend job проверяет lint, build и
  компиляцию Playwright inventory. Browser E2E проверен на локальном
  Kubernetes-стенде с Gateway/Kafka/ClickHouse: 31 сценарий прошёл, три
  временно rate-limited сценария подтверждены отдельным повтором.

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

- Dispatch Service автоматически запускает `AutoDispatch` для новой заявки с
  приоритетом `EMERGENCY` по событию `ticket.created`: Kafka consumer имеет
  ручной commit, retry/DLQ, OTel propagation и идемпотентный `trigger_event_id`,
  а повторная доставка продолжает `PENDING/RESERVED/CONFIRMING` операцию.
  Добавить Kafka E2E
  `создание экстренной заявки -> поиск доступной бригады -> резервирование ->
  построение маршрута -> назначение`, включая падение процесса между этапами;
  ошибки поиска и назначения уже сохраняются в lifecycle Dispatch с
  `failure_stage`, `failure_code` и `trace_id`.
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


Разнести Helm application на разные сервисы для улучшения читаемости конфгов

ETCD в кубере перевести на прометеус, т.к он на прямую поддерживает его

Если не настроено в кликхаус сделать напрямую через коннектор сбор данных в кафке