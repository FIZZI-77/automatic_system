# Analytics Service

## Общее описание и общий принцип работы

`Analytics_Service` принимает предметные события из Kafka, сохраняет их в
ClickHouse и предоставляет агрегированные показатели. Он не изменяет заявки,
бригады, маршруты или объекты. Основное хранилище `domain_events` содержит
нормализованные поля и исходное содержимое события, а материализованное
представление наполняет проекцию версии 1.

Последовательность обработки:

1. Потребитель Kafka преобразует сообщение в `models.Event`.
2. `Consume` заменяет отсутствующую версию на 1.
3. Версия 1 получает `ProjectionEligible=true`. Неизвестная версия хранится,
   но не должна участвовать в текущих расчетах.
4. Репозиторий записывает событие в ClickHouse.
5. Репозитории чтения применяют `models.Filter` и рассчитывают показатели.
6. Прикладной слой измеряет время запроса, записывает результат в журнал и
   возвращает модель без дополнительного преобразования.

Фильтр поддерживает период, подразделение, категорию, приоритет, бригаду,
способ назначения, код ошибки и успешность. Важные формулы, реализованные
репозиториями:

- доля неуспешных назначений:
  `(FAILED + EXPIRED + CANCELED) / requested * 100`;
- активная заявка имеет последнее состояние `ASSIGNED` или `IN_PROGRESS`;
- неназначенная очередь содержит `NEW` без `brigade_id`;
- необходимое число бригад:
  `ceil(peak_hourly_incoming * average_resolution_seconds / 3600)`;
- ошибка ожидаемого прибытия: фактический вход в геозону минус последнее
  предсказанное время.

## Модели

Ниже перечислены все структуры из `models/models.go`. Объединенные объявления
Go раскрыты так, чтобы назначение каждого поля было видно отдельно.

### Событие и отбор данных

| Структура | Поля и назначение |
|---|---|
| `Event` | `ID` — идентификатор события; `Type` — вид события; `Topic` — исходный раздел Kafka; `Payload` — разобранное содержимое; `Timestamp` — время события; `Version` — версия формата; `ProjectionEligible` — пригодность для текущей проекции. |
| `Filter` | `From`, `To` — границы периода; `DepartmentID` — подразделение; `CategoryID` — категория; `Priority` — приоритет; `BrigadeID` — бригада; `AssignmentMode` — способ назначения; `FailureCode` — код сбоя; `Success` — успешность. Все поля необязательны. |

### Общие показатели и объекты

| Структура | Поля и назначение |
|---|---|
| `Overview` | `Created` — создано; `Completed` — завершено; `Canceled` — отменено; `Active` — активно; `CompletionRate` — доля завершения; `AvgResponseSeconds` — среднее время реакции; `AvgResolutionSeconds` — среднее время решения. |
| `SLA` | `ResponseWarnings`, `ResponseBreaches` — предупреждения и нарушения времени реакции; `ResolutionWarnings`, `ResolutionBreaches` — предупреждения и нарушения времени решения; `Completed` — завершенные заявки; `BreachRate` — доля нарушений. |
| `Breakdown` | `Key` — значение измерения; `Count` — количество; `Percent` — доля. |
| `Daily` | `Day` — день; `Created`, `Completed`, `Canceled` — дневные количества; `SLABreaches` — дневные нарушения срока обслуживания. |
| `AssetBreakdown` | `Key` — тип объекта или район; `Incidents` — аварии; `Repeated` — повторные случаи; `Repairs` — ремонты; `Critical` — критические случаи. |
| `AssetSummary` | `Created` — созданные события; `Incidents` — аварии; `Repeated` — повторные аварии; `Repairs` — ремонты; `Inspections` — осмотры; `Critical` — критические события; `ByType` и `ByDistrict` — разбивки по типу и району. |

### Распределения времени и сбои

| Структура | Поля и назначение |
|---|---|
| `LatencyDistribution` | `SampleCount` — число измерений; `AverageSeconds` — среднее; `MedianSeconds` — медиана; `P90Seconds`, `P95Seconds`, `P99Seconds` — соответствующие процентили в секундах. |
| `OperationalLatency` | `AssignmentTime` — время назначения; `RoutingCalculationTime` — длительность расчета маршрута, не время поездки; `Groups` — сравнение групп. |
| `OperationalLatencyGroup` | `Dimension` — измерение; `Key` — значение; `AssignmentTime` и `RoutingCalculationTime` — распределения группы. |
| `DispatchFailureBreakdown` | `Key` — этап или код; `Count` — число сбоев; `Percent` — доля среди неуспешных операций. |
| `DispatchFailureReasonSummary` | `Reason` — предметная причина; `Count` — число; `RequestRate` — доля от всех запросов назначения. |
| `DispatchFailureReasonDimension` | `Reason` — причина; `Key` — подразделение или категория; `Count` — число; `ReasonPercent` — доля внутри причины. |
| `DispatchFailureSummary` | `Requested` — запрошено; `Failed` — ошибочно; `Expired` — истекло; `Canceled` — отменено; `FailureRate` — общая доля неуспеха; `ByStage`, `ByCode` — технические разбивки; `BusinessReasons`, `ReasonsByDepartment`, `ReasonsByCategory` — предметные причины и их группы. |

### Нагрузка, сотрудники и воронка

| Структура | Поля и назначение |
|---|---|
| `BrigadeWorkloadItem` | `BrigadeID` — бригада; `Incoming` — входящие; `Assigned` — назначенные; `Completed` — завершенные; `Active` — текущие активные заявки. |
| `BrigadeWorkload` | `Incoming`, `Assigned`, `Completed`, `Active` — общие количества; `UnassignedBacklog` — неназначенная очередь; `BrigadeCount` — число бригад; `MaxActive`, `AverageActive` — максимум и среднее активных заявок; `StandardDeviation` — стандартное отклонение; `CoefficientOfVariation` — коэффициент вариации; `Gini` — коэффициент Джини; `Brigades` — показатели бригад. |
| `ActiveWorkerGroup` | `Dimension` — измерение; `Key` — значение; `ActiveMembers` — активные работники; `Available` — доступные; `OnShift` — находящиеся на смене. |
| `ActiveWorkers` | `ActiveMembers`, `Available`, `OnShift` — общие количества; `ByDepartment`, `ByBrigade` — группы по подразделениям и бригадам. |
| `AssignmentFunnelStage` | `Stage` — этап; `Count` — достигшие этапа операции; `ConversionFromPrevious` — переход от предыдущего этапа; `TransitionTime` — время перехода. |
| `AssignmentFunnel` | `Stages` — последовательность этапов назначения. |
| `DispatchModeEffectiveness` | `Mode` — способ назначения; `Requested` — запросы; `Assigned` — назначения; `SuccessRate` — доля успеха; `AssignmentTime` — время назначения. |
| `DispatchEffectiveness` | `Automatic` — автоматический режим; `Manual` — ручной режим; `ManualReassignmentAvailable` — доступность достоверного показателя переназначения, сейчас `false`. |

### Оперативные показатели и состояние проекции

| Структура | Поля и назначение |
|---|---|
| `QueueAgeBucket` | `Range` — интервал возраста; `Count` — число заявок. |
| `QueueAgeSummary` | `ActiveUnassigned` — активные неназначенные заявки; `Age` — распределение возраста; `Buckets` — интервальная разбивка. |
| `RoutingEfficiency` | `Routes` — маршруты; `Recalculations` — перестроения; `Cancellations` — отмены; `UnreachableCandidateRate` — доля недостижимых кандидатов; `AverageDistanceKM` — средняя длина; `KilometersPerCompletedTicket` — километры на завершенную заявку; `ETASampleCount` — число измерений прибытия; `ETAMeanAbsoluteErrorSeconds` — средняя абсолютная ошибка; `ETABiasSeconds` — знаковое смещение; `ETAP95AbsoluteErrorSeconds` — 95-й процентиль ошибки; `ETAWithinFiveMinutesRate` — доля ошибок не более пяти минут. |
| `CapacityForecast` | `ObservedDays` — дней наблюдения; `AverageDailyIncoming` — средний дневной поток; `ForecastNextDay` — прогноз; `PeakHourlyIncoming` — пиковый час; `RequiredBrigades` — расчетное число бригад; `Formula` — текст формулы. |
| `OperationalInsights` | `DepartureTime` — время до выезда; `QueueAge` — возраст очереди; `Routing` — эффективность маршрутов; `CapacityForecast` — прогноз потребности. |
| `ProjectionTopicHealth` | `Topic` — раздел; `TotalEvents` — все события; `UnknownVersionEvents` — неизвестные версии; `ProjectionEligibleRate` — доля пригодных; `LastOccurredAt` — последнее предметное время; `LastIngestedAt` — последнее время приема; `FreshnessSeconds` — отставание; `IngestionP95Seconds` — 95-й процентиль задержки приема. |
| `ProjectionHealth` | `TotalEvents` — все события; `UnknownVersionEvents` — неизвестные версии; `ProjectedEvents` — попавшие в проекцию; `MissingProjectionEvents` — отсутствующие в ней; `ProjectionEligibleRate` — доля пригодных; `ProjectionErrorRate` — доля расхождения; `LastOccurredAt`, `LastIngestedAt` — последние времена; `FreshnessSeconds`, `IngestionP95Seconds` — задержки; `Topics` — состояние разделов. |

### Операции назначения и работа бригад

| Структура | Поля и назначение |
|---|---|
| `DispatchOperationItem` | `OperationID` — операция; `TicketID` — заявка; `DepartmentID` — подразделение; `CategoryID` — категория; `BrigadeID` — бригада; `AssignmentMode` — способ назначения; `Status` — состояние; `FailureCode` — код сбоя; `FailureStage` — этап сбоя; `TraceID` — идентификатор трассировки; `RequestedAt` — начало; `UpdatedAt` — последнее изменение. |
| `BrigadePerformanceItem` | `BrigadeID` — бригада; `Completed` — завершено; `ExecutionTime` — время исполнения; `SLABreaches` — нарушения срока; `SLABreachRate` — их доля; `RepeatedAssetTickets` — повторные заявки по объектам; `ShiftCount` — смены; `ShiftHours` — часы смен; `BusyHours` — занятые часы; `AverageParallelTasks` — среднее число параллельных задач; `CompletedPerShift` — завершено на смену; `UtilizationRate` — загрузка. |
| `BrigadePerformance` | `Completed`, `SLABreaches`, `RepeatedAssetTickets` — общие количества; `ExecutionTime` — общее распределение; `SLABreachRate` — доля нарушений; `ShiftMetricsAvailable` — можно ли рассчитать смены; `ShiftCount` — число смен; `ShiftHours`, `BusyHours`, `AverageParallelTasks` — временные показатели; `CompletedPerShift`, `UtilizationRate` — производительность и загрузка; `Brigades` — показатели отдельных бригад. |

## Функции

### `NewAnalyticsServiceStruct`

Принимает общий набор репозиториев и журнал. Если журнал отсутствует, подставляет
`zap.NewNop()`. Раскладывает специализированные репозитории по полям сервиса.

### `Consume`

Принимает одно событие. Подставляет версию 1 вместо нуля, определяет пригодность
для проекции, записывает метрику и предупреждение для неизвестной версии,
сохраняет событие через `EventRepository.Store`. Ошибка записи возвращается
без подтверждения успешной обработки сообщения.

### `Overview`, `SLA` и `Daily`

`Overview` возвращает сводку заявок, `SLA` — предупреждения и нарушения
сроков, `Daily` — ряд по дням. Каждый метод передает фильтр одноименному
репозиторию, измеряет длительность и записывает размер или ключевой счетчик.

### `Breakdown`

Принимает фильтр, имя измерения `d` и предел `l`. Возвращает строки разбивки,
общее количество и ошибку репозитория. Прикладной слой не меняет проценты.

### `AssetSummary`

Передает фильтр и два дополнительных необязательных ограничения `t` и `d`
репозиторию объектов. Возвращает сводку и записывает число аварий.

### `OperationalLatency`

Передает фильтр и `groupBy` репозиторию. Возвращает распределения времени
назначения и вычисления маршрута, а также группы. В журнал записывает число
выборок обоих распределений.

### `DispatchFailures`

Возвращает итог операций назначения и разбивки причин. Для журнала число
неуспешных операций вычисляется как сумма `Failed + Expired + Canceled`.

### `BrigadeWorkload`

Возвращает состояние нагрузки и список бригад. Записывает общее число активных
заявок и количество элементов списка.

### `ActiveWorkers`

Возвращает активных, доступных и находящихся на смене сотрудников с группами по
подразделению и бригаде. Записывает два первых счетчика.

### `AssignmentFunnel`

Возвращает этапы воронки назначения и записывает их количество. Когорта
репозитория начинается с `dispatch.requested` внутри выбранного периода.

### `DispatchEffectiveness`

Сравнивает автоматические и ручные назначения. В журнал попадают количество
запросов и назначений автоматического режима.

### `OperationalInsights`

Возвращает время выезда, возраст очереди, показатели маршрутов и прогноз
потребности. Записывает размер очереди и число маршрутов.

### `ProjectionHealth`

Не принимает фильтр: оценивает все источники проекции. Возвращает свежесть,
задержки приема, неизвестные версии и расхождения исходной таблицы с проекцией.

### `DispatchOperations`

Передает фильтр и `limit` репозиторию и возвращает последние состояния
операций назначения. Записывает число возвращенных строк.

### `BrigadePerformance`

Возвращает общие и побригадные показатели выполнения, смен и нагрузки.
Записывает число завершенных заявок и бригад.

### `logQuery`

Добавляет к полям длительность выполнения. При ошибке пишет запись уровня
`Error` вместе с ошибкой и немедленно возвращается; при успехе пишет
`Info`. Функция не заменяет и не скрывает ошибку вызывающего метода.

### `NewService`

Создает внешнюю оболочку `Service`, встраивая реализацию
`AnalyticsService`.

## Структура БД

Схема хранится в ClickHouse. Она создается файлом `scheme/001_events.sql`.

### `analytics.domain_events` — исходные события

| Поле | Тип ClickHouse | Назначение |
|---|---|---|
| `topic` | `LowCardinality(String)` | Раздел Kafka. |
| `event_id` | `String` | Идентификатор события. |
| `event_type` | `LowCardinality(String)` | Вид события. |
| `entity_id` | `String` | Основная сущность события. |
| `ticket_id` | `String` | Заявка. |
| `department_id` | `String` | Подразделение. |
| `category_id` | `String` | Категория. |
| `asset_id` | `String` | Городской объект. |
| `brigade_id` | `String` | Бригада. |
| `shift_id` | `String` | Смена. |
| `user_id` | `String` | Пользователь. |
| `member_id` | `String` | Участник бригады. |
| `member_status` | `LowCardinality(String)` | Состояние участника. |
| `availability_status` | `LowCardinality(String)` | Доступность участника. |
| `member_role` | `LowCardinality(String)` | Роль участника. |
| `member_active` | `Nullable(Bool)` | Признак активности участника. |
| `route_id` | `String` | Маршрут. |
| `trace_id` | `String` | Идентификатор распределенной трассировки. |
| `priority` | `LowCardinality(String)` | Приоритет заявки. |
| `status` | `LowCardinality(String)` | Состояние сущности или операции. |
| `assignment_mode` | `LowCardinality(String)` | Способ назначения. |
| `failure_code` | `LowCardinality(String)` | Код сбоя. |
| `failure_stage` | `LowCardinality(String)` | Этап сбоя. |
| `success` | `Nullable(Bool)` | Признак успешности, если он известен. |
| `calculation_duration_ms` | `Nullable(Float64)` | Измеренная длительность вычисления маршрута в миллисекундах. |
| `candidate_count` | `Nullable(UInt64)` | Число найденных кандидатов. |
| `reachable_candidate_count` | `Nullable(UInt64)` | Число достижимых кандидатов. |
| `engine` | `LowCardinality(String)` | Использованный механизм маршрутизации. |
| `travel_mode` | `LowCardinality(String)` | Способ передвижения. |
| `latitude` | `Nullable(Float64)` | Широта исходной точки. |
| `longitude` | `Nullable(Float64)` | Долгота исходной точки. |
| `route_revision` | `Nullable(UInt32)` | Номер версии маршрута. |
| `distance_meters` | `Nullable(Float64)` | Длина маршрута в метрах. |
| `duration_seconds` | `Nullable(Float64)` | Ожидаемая длительность движения в секундах. |
| `speed_kmh` | `Nullable(Float64)` | Скорость в километрах в час. |
| `accuracy_meters` | `Nullable(Float64)` | Точность координат в метрах. |
| `destination_latitude` | `Nullable(Float64)` | Широта назначения. |
| `destination_longitude` | `Nullable(Float64)` | Долгота назначения. |
| `payload` | `String` | Исходное содержимое события в виде строки JSON. |
| `occurred_at` | `DateTime64(3, 'UTC')` | Предметное время события. |
| `event_version` | `UInt32` | Версия формата, по умолчанию 1. |
| `projection_eligible` | `Bool` | Пригодность для проекции версии 1. |
| `ingested_at` | `DateTime64(3, 'UTC')` | Время записи, по умолчанию `now64(3)`. |
| `version` | `UInt64` | Версия строки для устранения повторов в `ReplacingMergeTree`. |

Таблица использует `ReplacingMergeTree(version)`, разбивается на месяцы по
`occurred_at`, упорядочивается по `(topic, event_id)` и удаляет данные через
пять лет.

### `analytics.domain_events_projection_v1` — проекция версии 1

Таблица создается конструкцией `AS analytics.domain_events`. Поэтому ее схема
повторяет исходное хранилище, но приводится отдельно, чтобы структуру каждой
таблицы можно было читать независимо. Отдельные `ALTER TABLE ... ADD COLUMN IF
NOT EXISTS` обеспечивают совместимость уже существующей проекции с новыми
полями.

| Поле | Тип ClickHouse | Назначение |
|---|---|---|
| `topic` | `LowCardinality(String)` | Раздел Kafka исходного события. |
| `event_id` | `String` | Идентификатор события и часть ключа устранения повторов. |
| `event_type` | `LowCardinality(String)` | Вид предметного события. |
| `entity_id` | `String` | Основная сущность события. |
| `ticket_id` | `String` | Заявка, участвующая в расчете показателей. |
| `department_id` | `String` | Подразделение для отбора и группировки. |
| `category_id` | `String` | Категория заявки. |
| `asset_id` | `String` | Городской объект, связанный с заявкой. |
| `brigade_id` | `String` | Бригада. |
| `shift_id` | `String` | Смена бригады. |
| `user_id` | `String` | Пользователь. |
| `member_id` | `String` | Участник бригады. |
| `member_status` | `LowCardinality(String)` | Состояние участника. |
| `availability_status` | `LowCardinality(String)` | Доступность участника. |
| `member_role` | `LowCardinality(String)` | Роль участника. |
| `member_active` | `Nullable(Bool)` | Признак активности участника. |
| `route_id` | `String` | Маршрут. |
| `trace_id` | `String` | Идентификатор распределенной трассировки. |
| `priority` | `LowCardinality(String)` | Приоритет заявки. |
| `status` | `LowCardinality(String)` | Состояние сущности или операции. |
| `assignment_mode` | `LowCardinality(String)` | Способ назначения бригады. |
| `failure_code` | `LowCardinality(String)` | Код сбоя. |
| `failure_stage` | `LowCardinality(String)` | Этап, на котором произошел сбой. |
| `success` | `Nullable(Bool)` | Результат операции, если он передан событием. |
| `calculation_duration_ms` | `Nullable(Float64)` | Длительность вычисления маршрута в миллисекундах. |
| `candidate_count` | `Nullable(UInt64)` | Число найденных кандидатов. |
| `reachable_candidate_count` | `Nullable(UInt64)` | Число достижимых кандидатов. |
| `engine` | `LowCardinality(String)` | Механизм построения маршрута. |
| `travel_mode` | `LowCardinality(String)` | Способ передвижения. |
| `latitude` | `Nullable(Float64)` | Широта исходной точки. |
| `longitude` | `Nullable(Float64)` | Долгота исходной точки. |
| `route_revision` | `Nullable(UInt32)` | Версия маршрута. |
| `distance_meters` | `Nullable(Float64)` | Длина маршрута в метрах. |
| `duration_seconds` | `Nullable(Float64)` | Ожидаемая длительность движения в секундах. |
| `speed_kmh` | `Nullable(Float64)` | Скорость в километрах в час. |
| `accuracy_meters` | `Nullable(Float64)` | Точность координат в метрах. |
| `destination_latitude` | `Nullable(Float64)` | Широта назначения. |
| `destination_longitude` | `Nullable(Float64)` | Долгота назначения. |
| `payload` | `String` | Исходное содержимое события в виде строки JSON. |
| `occurred_at` | `DateTime64(3, 'UTC')` | Предметное время события. |
| `event_version` | `UInt32` | Версия формата события. |
| `projection_eligible` | `Bool` | Допустимо ли событие использовать в проекции версии 1. |
| `ingested_at` | `DateTime64(3, 'UTC')` | Время приема события аналитикой. |
| `version` | `UInt64` | Версия строки для `ReplacingMergeTree`. |

### `analytics.domain_events_projection_v1_mv` — материализованное представление

Это не самостоятельная таблица данных. Представление выполняет `SELECT * FROM
analytics.domain_events` и направляет новые строки в
`analytics.domain_events_projection_v1`. Начальное заполнение выполняется
отдельным `INSERT ... SELECT`; повтор безопасен для чтения с `FINAL` за счет
ключа `(topic, event_id)` и поля `version`.
