# Сервис аналитики (Analytics Service)

## Ответственность

Event ingestion в ClickHouse и агрегированные operational/business показатели.

## Ключевое поведение

- Не изменяет ticket/brigade/route/asset aggregates.
- Unknown event version сохраняется, но не помечается `ProjectionEligible` для текущей v1 projection.
- Поддерживает overview, SLA, latency percentiles, dispatch failures/funnel, brigade workload, routing efficiency, queue age, capacity forecast и projection health.
- Capacity forecast внутри Analytics — аналитическая формула; фактическая инфраструктурная capacity проверяется load-test framework.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | ClickHouse. |
| Синхронные взаимодействия | Нет write-dependency на domain services. |
| Kafka | Consumer широкого набора domain topics; publisher отсутствует. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Полные сигнатуры и структуры параметров приведены в [справочнике функций Analytics Service](https://automaticsystem.youtrack.cloud/articles/ACS-A-30/Kod-i-funkcii-Analytics-Service).

### `NewAnalyticsServiceStruct`

```go
func NewAnalyticsServiceStruct(repo *repository.Repository, logger *zap.Logger) *AnalyticsServiceStruct
```

Принимает общий набор репозиториев и журнал. Если журнал отсутствует, подставляет
`zap.NewNop()`. Раскладывает специализированные репозитории по полям сервиса.

### `Consume`

```go
func (s *AnalyticsServiceStruct) Consume(c context.Context, e models.Event) error
```

Принимает одно событие. Подставляет версию 1 вместо нуля, определяет пригодность
для проекции, записывает метрику и предупреждение для неизвестной версии,
сохраняет событие через `EventRepository.Store`. Ошибка записи возвращается
без подтверждения успешной обработки сообщения.

### `Overview`, `SLA` и `Daily`

```go
func (s *AnalyticsServiceStruct) Overview(c context.Context, f models.Filter) (models.Overview, error)
```

```go
func (s *AnalyticsServiceStruct) SLA(c context.Context, f models.Filter) (models.SLA, error)
```

```go
func (s *AnalyticsServiceStruct) Daily(c context.Context, f models.Filter) ([]models.Daily, error)
```

`Overview` возвращает сводку заявок, `SLA` — предупреждения и нарушения
сроков, `Daily` — ряд по дням. Каждый метод передает фильтр одноименному
репозиторию, измеряет длительность и записывает размер или ключевой счетчик.

### `Breakdown`

```go
func (s *AnalyticsServiceStruct) Breakdown(c context.Context, f models.Filter, d string, l int32) ([]models.Breakdown, uint64, error)
```

Принимает фильтр, имя измерения `d` и предел `l`. Возвращает строки разбивки,
общее количество и ошибку репозитория. Прикладной слой не меняет проценты.

### `AssetSummary`

```go
func (s *AnalyticsServiceStruct) AssetSummary(c context.Context, f models.Filter, t, d *string) (models.AssetSummary, error)
```

Передает фильтр и два дополнительных необязательных ограничения `t` и `d`
репозиторию объектов. Возвращает сводку и записывает число аварий.

### `OperationalLatency`

```go
func (s *AnalyticsServiceStruct) OperationalLatency(c context.Context, f models.Filter, groupBy string) (models.OperationalLatency, error)
```

Передает фильтр и `groupBy` репозиторию. Возвращает распределения времени
назначения и вычисления маршрута, а также группы. В журнал записывает число
выборок обоих распределений.

### `DispatchFailures`

```go
func (s *AnalyticsServiceStruct) DispatchFailures(c context.Context, f models.Filter) (models.DispatchFailureSummary, error)
```

Возвращает итог операций назначения и разбивки причин. Для журнала число
неуспешных операций вычисляется как сумма `Failed + Expired + Canceled`.

### `BrigadeWorkload`

```go
func (s *AnalyticsServiceStruct) BrigadeWorkload(c context.Context, f models.Filter) (models.BrigadeWorkload, error)
```

Возвращает состояние нагрузки и список бригад. Записывает общее число активных
заявок и количество элементов списка.

### `ActiveWorkers`

```go
func (s *AnalyticsServiceStruct) ActiveWorkers(c context.Context, f models.Filter) (models.ActiveWorkers, error)
```

Возвращает активных, доступных и находящихся на смене сотрудников с группами по
подразделению и бригаде. Записывает два первых счетчика.

### `AssignmentFunnel`

```go
func (s *AnalyticsServiceStruct) AssignmentFunnel(c context.Context, f models.Filter) (models.AssignmentFunnel, error)
```

Возвращает этапы воронки назначения и записывает их количество. Когорта
репозитория начинается с `dispatch.requested` внутри выбранного периода.

### `DispatchEffectiveness`

```go
func (s *AnalyticsServiceStruct) DispatchEffectiveness(c context.Context, f models.Filter) (models.DispatchEffectiveness, error)
```

Сравнивает автоматические и ручные назначения. В журнал попадают количество
запросов и назначений автоматического режима.

### `OperationalInsights`

```go
func (s *AnalyticsServiceStruct) OperationalInsights(c context.Context, f models.Filter) (models.OperationalInsights, error)
```

Возвращает время выезда, возраст очереди, показатели маршрутов и прогноз
потребности. Записывает размер очереди и число маршрутов.

### `ProjectionHealth`

```go
func (s *AnalyticsServiceStruct) ProjectionHealth(c context.Context) (models.ProjectionHealth, error)
```

Не принимает фильтр: оценивает все источники проекции. Возвращает свежесть,
задержки приема, неизвестные версии и расхождения исходной таблицы с проекцией.

### `DispatchOperations`

```go
func (s *AnalyticsServiceStruct) DispatchOperations(c context.Context, f models.Filter, limit uint32) ([]models.DispatchOperationItem, error)
```

Передает фильтр и `limit` репозиторию и возвращает последние состояния
операций назначения. Записывает число возвращенных строк.

### `BrigadePerformance`

```go
func (s *AnalyticsServiceStruct) BrigadePerformance(c context.Context, f models.Filter) (models.BrigadePerformance, error)
```

Возвращает общие и побригадные показатели выполнения, смен и нагрузки.
Записывает число завершенных заявок и бригад.

### `logQuery`

```go
func (s *AnalyticsServiceStruct) logQuery(name string, start time.Time, err error, fields ...zap.Field)
```

Добавляет к полям длительность выполнения. При ошибке пишет запись уровня
`Error` вместе с ошибкой и немедленно возвращается; при успехе пишет
`Info`. Функция не заменяет и не скрывает ошибку вызывающего метода.

### `NewService`

```go
func NewService(repo *repository.Repository, logger *zap.Logger) *Service
```

Создает внешнюю оболочку `Service`, встраивая реализацию
`AnalyticsService`.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Analytics_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
