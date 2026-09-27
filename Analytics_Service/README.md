# Сервис аналитики (Analytics Service)

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

Имя функции открывает её реализацию в ветке `test`; структуры параметров и результатов описаны в конце README.

### func [NewAnalyticsServiceStruct](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L32)

```go
func NewAnalyticsServiceStruct(repo *repository.Repository, logger *zap.Logger) *AnalyticsServiceStruct
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [Repository](#type-repository).

Структуры: [AnalyticsServiceStruct](#type-analyticsservicestruct).

Принимает общий набор репозиториев и журнал. Если журнал отсутствует, подставляет
`zap.NewNop()`. Раскладывает специализированные репозитории по полям сервиса.

### func (*AnalyticsServiceStruct) [Consume](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L140)

```go
func (s *AnalyticsServiceStruct) Consume(c context.Context, e models.Event) error
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [Event](#type-event).

Структуры: [Event](#type-event).

Принимает одно событие. Подставляет версию 1 вместо нуля, определяет пригодность
для проекции, записывает метрику и предупреждение для неизвестной версии,
сохраняет событие через `EventRepository.Store`. Ошибка записи возвращается
без подтверждения успешной обработки сообщения.

### func (*AnalyticsServiceStruct) [Overview](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L158)

```go
func (s *AnalyticsServiceStruct) Overview(c context.Context, f models.Filter) (models.Overview, error)
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [Filter](#type-filter), [Overview](#type-overview).

Структуры: [Overview](#type-overview), [Filter](#type-filter).

`Overview` возвращает сводку заявок, `SLA` — предупреждения и нарушения
сроков, `Daily` — ряд по дням. Каждый метод передает фильтр одноименному
репозиторию, измеряет длительность и записывает размер или ключевой счетчик.

### func (*AnalyticsServiceStruct) [SLA](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L164)

```go
func (s *AnalyticsServiceStruct) SLA(c context.Context, f models.Filter) (models.SLA, error)
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [Filter](#type-filter), [SLA](#type-sla).

Структуры: [SLA](#type-sla), [Filter](#type-filter).

`Overview` возвращает сводку заявок, `SLA` — предупреждения и нарушения
сроков, `Daily` — ряд по дням. Каждый метод передает фильтр одноименному
репозиторию, измеряет длительность и записывает размер или ключевой счетчик.

### func (*AnalyticsServiceStruct) [Daily](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L176)

```go
func (s *AnalyticsServiceStruct) Daily(c context.Context, f models.Filter) ([]models.Daily, error)
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [Daily](#type-daily), [Filter](#type-filter).

Структуры: [Daily](#type-daily), [Filter](#type-filter).

`Overview` возвращает сводку заявок, `SLA` — предупреждения и нарушения
сроков, `Daily` — ряд по дням. Каждый метод передает фильтр одноименному
репозиторию, измеряет длительность и записывает размер или ключевой счетчик.

### func (*AnalyticsServiceStruct) [Breakdown](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L170)

```go
func (s *AnalyticsServiceStruct) Breakdown(c context.Context, f models.Filter, d string, l int32) ([]models.Breakdown, uint64, error)
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [Breakdown](#type-breakdown), [Filter](#type-filter).

Структуры: [Breakdown](#type-breakdown), [Filter](#type-filter).

Принимает фильтр, имя измерения `d` и предел `l`. Возвращает строки разбивки,
общее количество и ошибку репозитория. Прикладной слой не меняет проценты.

### func (*AnalyticsServiceStruct) [AssetSummary](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L134)

```go
func (s *AnalyticsServiceStruct) AssetSummary(c context.Context, f models.Filter, t, d *string) (models.AssetSummary, error)
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [AssetSummary](#type-assetsummary), [Filter](#type-filter).

Структуры: [AssetSummary](#type-assetsummary), [Filter](#type-filter).

Передает фильтр и два дополнительных необязательных ограничения `t` и `d`
репозиторию объектов. Возвращает сводку и записывает число аварий.

### func (*AnalyticsServiceStruct) [OperationalLatency](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L122)

```go
func (s *AnalyticsServiceStruct) OperationalLatency(c context.Context, f models.Filter, groupBy string) (models.OperationalLatency, error)
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [Filter](#type-filter), [OperationalLatency](#type-operationallatency).

Структуры: [OperationalLatency](#type-operationallatency), [Filter](#type-filter).

Передает фильтр и `groupBy` репозиторию. Возвращает распределения времени
назначения и вычисления маршрута, а также группы. В журнал записывает число
выборок обоих распределений.

### func (*AnalyticsServiceStruct) [DispatchFailures](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L116)

```go
func (s *AnalyticsServiceStruct) DispatchFailures(c context.Context, f models.Filter) (models.DispatchFailureSummary, error)
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [DispatchFailureSummary](#type-dispatchfailuresummary), [Filter](#type-filter).

Структуры: [Filter](#type-filter), [DispatchFailureSummary](#type-dispatchfailuresummary).

Возвращает итог операций назначения и разбивки причин. Для журнала число
неуспешных операций вычисляется как сумма `Failed + Expired + Canceled`.

### func (*AnalyticsServiceStruct) [BrigadeWorkload](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L110)

```go
func (s *AnalyticsServiceStruct) BrigadeWorkload(c context.Context, f models.Filter) (models.BrigadeWorkload, error)
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [BrigadeWorkload](#type-brigadeworkload), [Filter](#type-filter).

Структуры: [BrigadeWorkload](#type-brigadeworkload), [Filter](#type-filter).

Возвращает состояние нагрузки и список бригад. Записывает общее число активных
заявок и количество элементов списка.

### func (*AnalyticsServiceStruct) [ActiveWorkers](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L104)

```go
func (s *AnalyticsServiceStruct) ActiveWorkers(c context.Context, f models.Filter) (models.ActiveWorkers, error)
```

Типы: [ActiveWorkers](#type-activeworkers), [AnalyticsServiceStruct](#type-analyticsservicestruct), [Filter](#type-filter).

Структуры: [ActiveWorkers](#type-activeworkers), [Filter](#type-filter).

Возвращает активных, доступных и находящихся на смене сотрудников с группами по
подразделению и бригаде. Записывает два первых счетчика.

### func (*AnalyticsServiceStruct) [AssignmentFunnel](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L98)

```go
func (s *AnalyticsServiceStruct) AssignmentFunnel(c context.Context, f models.Filter) (models.AssignmentFunnel, error)
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [AssignmentFunnel](#type-assignmentfunnel), [Filter](#type-filter).

Структуры: [AssignmentFunnel](#type-assignmentfunnel), [Filter](#type-filter).

Возвращает этапы воронки назначения и записывает их количество. Когорта
репозитория начинается с `dispatch.requested` внутри выбранного периода.

### func (*AnalyticsServiceStruct) [DispatchEffectiveness](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L89)

```go
func (s *AnalyticsServiceStruct) DispatchEffectiveness(c context.Context, f models.Filter) (models.DispatchEffectiveness, error)
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [DispatchEffectiveness](#type-dispatcheffectiveness), [Filter](#type-filter).

Структуры: [DispatchEffectiveness](#type-dispatcheffectiveness), [Filter](#type-filter).

Сравнивает автоматические и ручные назначения. В журнал попадают количество
запросов и назначений автоматического режима.

### func (*AnalyticsServiceStruct) [OperationalInsights](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L80)

```go
func (s *AnalyticsServiceStruct) OperationalInsights(c context.Context, f models.Filter) (models.OperationalInsights, error)
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [Filter](#type-filter), [OperationalInsights](#type-operationalinsights).

Структуры: [OperationalInsights](#type-operationalinsights), [Filter](#type-filter).

Возвращает время выезда, возраст очереди, показатели маршрутов и прогноз
потребности. Записывает размер очереди и число маршрутов.

### func (*AnalyticsServiceStruct) [ProjectionHealth](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L71)

```go
func (s *AnalyticsServiceStruct) ProjectionHealth(c context.Context) (models.ProjectionHealth, error)
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [ProjectionHealth](#type-projectionhealth).

Структуры: [ProjectionHealth](#type-projectionhealth).

Не принимает фильтр: оценивает все источники проекции. Возвращает свежесть,
задержки приема, неизвестные версии и расхождения исходной таблицы с проекцией.

### func (*AnalyticsServiceStruct) [DispatchOperations](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L65)

```go
func (s *AnalyticsServiceStruct) DispatchOperations(c context.Context, f models.Filter, limit uint32) ([]models.DispatchOperationItem, error)
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [DispatchOperationItem](#type-dispatchoperationitem), [Filter](#type-filter).

Структуры: [Filter](#type-filter), [DispatchOperationItem](#type-dispatchoperationitem).

Передает фильтр и `limit` репозиторию и возвращает последние состояния
операций назначения. Записывает число возвращенных строк.

### func (*AnalyticsServiceStruct) [BrigadePerformance](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L56)

```go
func (s *AnalyticsServiceStruct) BrigadePerformance(c context.Context, f models.Filter) (models.BrigadePerformance, error)
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct), [BrigadePerformance](#type-brigadeperformance), [Filter](#type-filter).

Структуры: [BrigadePerformance](#type-brigadeperformance), [Filter](#type-filter).

Возвращает общие и побригадные показатели выполнения, смен и нагрузки.
Записывает число завершенных заявок и бригад.

### func (*AnalyticsServiceStruct) [logQuery](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/analytics_service.go#L182)

```go
func (s *AnalyticsServiceStruct) logQuery(name string, start time.Time, err error, fields ...zap.Field)
```

Типы: [AnalyticsServiceStruct](#type-analyticsservicestruct).

Добавляет к полям длительность выполнения. При ошибке пишет запись уровня
`Error` вместе с ошибкой и немедленно возвращается; при успехе пишет
`Info`. Функция не заменяет и не скрывает ошибку вызывающего метода.

### func [NewService](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/core/service/service.go#L30)

```go
func NewService(repo *repository.Repository, logger *zap.Logger) *Service
```

Типы: [Repository](#type-repository), [Service](#type-service).

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

## Структуры параметров и результатов

### type ActiveWorkers

```go
type ActiveWorkers struct {
	ActiveMembers uint64
	Available     uint64
	OnShift       uint64
	ByDepartment  []ActiveWorkerGroup
	ByBrigade     []ActiveWorkerGroup
}
```

### type AnalyticsServiceStruct

```go
type AnalyticsServiceStruct struct {
	events        repository.EventRepository
	overview      repository.OverviewRepository
	sla           repository.SLARepository
	breakdown     repository.BreakdownRepository
	daily         repository.DailyRepository
	assets        repository.AssetRepository
	latency       repository.OperationalLatencyRepository
	failures      repository.DispatchFailureRepository
	workload      repository.BrigadeWorkloadRepository
	workers       repository.ActiveWorkersRepository
	funnel        repository.AssignmentFunnelRepository
	effectiveness repository.DispatchEffectivenessRepository
	insights      repository.OperationalInsightsRepository
	health        repository.ProjectionHealthRepository
	operations    repository.DispatchOperationsRepository
	performance   repository.BrigadePerformanceRepository
	logger        *zap.Logger
}
```

### type AssetSummary

```go
type AssetSummary struct {
	Created     uint64
	Incidents   uint64
	Repeated    uint64
	Repairs     uint64
	Inspections uint64
	Critical    uint64
	ByType      []AssetBreakdown
	ByDistrict  []AssetBreakdown
}
```

### type AssignmentFunnel

```go
type AssignmentFunnel struct {
	Stages []AssignmentFunnelStage
}
```

### type Breakdown

```go
type Breakdown struct {
	Key     string
	Count   uint64
	Percent float64
}
```

### type BrigadePerformance

```go
type BrigadePerformance struct {
	Completed             uint64
	SLABreaches           uint64
	RepeatedAssetTickets  uint64
	ExecutionTime         LatencyDistribution
	SLABreachRate         float64
	ShiftMetricsAvailable bool
	ShiftCount            uint64
	ShiftHours            float64
	BusyHours             float64
	AverageParallelTasks  float64
	CompletedPerShift     float64
	UtilizationRate       float64
	Brigades              []BrigadePerformanceItem
}
```

### type BrigadeWorkload

```go
type BrigadeWorkload struct {
	Incoming               uint64
	Assigned               uint64
	Completed              uint64
	Active                 uint64
	UnassignedBacklog      uint64
	BrigadeCount           uint64
	MaxActive              uint64
	AverageActive          float64
	StandardDeviation      float64
	CoefficientOfVariation float64
	Gini                   float64
	Brigades               []BrigadeWorkloadItem
}
```

### type Daily

```go
type Daily struct {
	Day         time.Time
	Created     uint64
	Completed   uint64
	Canceled    uint64
	SLABreaches uint64
}
```

### type DispatchEffectiveness

```go
type DispatchEffectiveness struct {
	Automatic                   DispatchModeEffectiveness
	Manual                      DispatchModeEffectiveness
	ManualReassignmentAvailable bool
}
```

### type DispatchFailureSummary

```go
type DispatchFailureSummary struct {
	Requested           uint64
	Failed              uint64
	Expired             uint64
	Canceled            uint64
	FailureRate         float64
	ByStage             []DispatchFailureBreakdown
	ByCode              []DispatchFailureBreakdown
	BusinessReasons     []DispatchFailureReasonSummary
	ReasonsByDepartment []DispatchFailureReasonDimension
	ReasonsByCategory   []DispatchFailureReasonDimension
}
```

### type DispatchOperationItem

```go
type DispatchOperationItem struct {
	OperationID    string
	TicketID       string
	DepartmentID   string
	CategoryID     string
	BrigadeID      string
	AssignmentMode string
	Status         string
	FailureCode    string
	FailureStage   string
	TraceID        string
	RequestedAt    time.Time
	UpdatedAt      time.Time
}
```

### type Event

```go
type Event struct {
	ID                 string
	Type               string
	Topic              string
	Payload            map[string]any
	Timestamp          time.Time
	Version            uint32
	ProjectionEligible bool
}
```

### type Filter

```go
type Filter struct {
	From           *time.Time
	To             *time.Time
	DepartmentID   *string
	CategoryID     *string
	Priority       *string
	BrigadeID      *string
	AssignmentMode *string
	FailureCode    *string
	Success        *bool
}
```

### type OperationalInsights

```go
type OperationalInsights struct {
	DepartureTime    LatencyDistribution
	QueueAge         QueueAgeSummary
	Routing          RoutingEfficiency
	CapacityForecast CapacityForecast
}
```

### type OperationalLatency

```go
type OperationalLatency struct {
	AssignmentTime         LatencyDistribution
	RoutingCalculationTime LatencyDistribution
	Groups                 []OperationalLatencyGroup
}
```

### type Overview

```go
type Overview struct {
	Created              uint64
	Completed            uint64
	Canceled             uint64
	Active               uint64
	CompletionRate       float64
	AvgResponseSeconds   float64
	AvgResolutionSeconds float64
}
```

### type ProjectionHealth

```go
type ProjectionHealth struct {
	TotalEvents             uint64
	UnknownVersionEvents    uint64
	ProjectedEvents         uint64
	MissingProjectionEvents uint64
	ProjectionEligibleRate  float64
	ProjectionErrorRate     float64
	LastOccurredAt          time.Time
	LastIngestedAt          time.Time
	FreshnessSeconds        float64
	IngestionP95Seconds     float64
	Topics                  []ProjectionTopicHealth
}
```

### type Repository

```go
type Repository struct {
	EventRepository
	OverviewRepository
	SLARepository
	BreakdownRepository
	DailyRepository
	AssetRepository
	OperationalLatencyRepository
	DispatchFailureRepository
	BrigadeWorkloadRepository
	ActiveWorkersRepository
	AssignmentFunnelRepository
	DispatchEffectivenessRepository
	OperationalInsightsRepository
	ProjectionHealthRepository
	DispatchOperationsRepository
	BrigadePerformanceRepository
}
```

### type SLA

```go
type SLA struct {
	ResponseWarnings   uint64
	ResponseBreaches   uint64
	ResolutionWarnings uint64
	ResolutionBreaches uint64
	Completed          uint64
	BreachRate         float64
}
```

### type Service

```go
type Service struct{ AnalyticsService }
```
