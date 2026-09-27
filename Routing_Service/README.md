# Сервис маршрутизации (Routing Service)

## Общее описание и общий принцип работы

`Routing Service` рассчитывает маршруты, строит матрицу расстояний и времени в пути, ранжирует бригады по времени прибытия и хранит маршрут, назначенный на заявку. Внешним механизмом расчета служит Valhalla. Сервис проверяет входные данные, приводит параметры к нормальной форме, вызывает `RoutingEngine` и сохраняет результат в PostgreSQL.

Создание маршрута проходит так:

1. Проверяются идентификаторы заявки и бригады, координаты, промежуточные точки и ограничения транспорта.
2. Если хранилище поддерживает поиск открытого маршрута, сервис ищет маршрут заявки со статусом `PLANNED` или `ACTIVE`.
3. Повторный запрос для той же заявки и бригады возвращает существующий маршрут. Попытка назначить другую бригаду завершается конфликтом.
4. Valhalla рассчитывает длину, продолжительность, участки, привязанные к дороге точки и кодированную линию маршрута.
5. Успешный результат сохраняется со статусом `PLANNED`, версией `1` и временными показателями расчета.
6. Изменение маршрута записывается вместе с событием в `outbox_events`; отдельный обработчик публикует событие в Kafka.
7. Ошибка Valhalla классифицируется и, если хранилище поддерживает операцию, записывается как событие неудачного расчета.

Допустимые переходы состояния: `PLANNED -> ACTIVE`, `PLANNED -> CANCELLED`, `ACTIVE -> COMPLETED` и `ACTIVE -> CANCELLED`. Завершенный или отмененный маршрут больше не меняет состояние.

## Модели

### Перечисления

| Тип | Значения | Назначение |
|---|---|---|
| `TravelMode` | `auto`, `truck`, `bicycle`, `pedestrian` | Способ передвижения, от которого зависит расчет. |
| `RouteStatus` | `PLANNED`, `ACTIVE`, `COMPLETED`, `CANCELLED` | Текущее состояние сохраненного маршрута. |

### `Point`

| Поле | Тип Go | Назначение |
|---|---|---|
| `Latitude` | `float64` | Широта от -90 до 90. |
| `Longitude` | `float64` | Долгота от -180 до 180. |

### `VehicleConstraints`

| Поле | Тип Go | Назначение |
|---|---|---|
| `HeightMeters` | `*float64` | Высота транспорта в метрах. |
| `WidthMeters` | `*float64` | Ширина транспорта в метрах. |
| `LengthMeters` | `*float64` | Длина транспорта в метрах. |
| `WeightTons` | `*float64` | Полная масса транспорта в тоннах. |
| `AxleLoadTons` | `*float64` | Нагрузка на ось в тоннах. |
| `HazardousMaterials` | `bool` | Признак перевозки опасных материалов. |

Все заданные числовые ограничения должны быть больше нуля.

### `RouteOptions`

| Поле | Тип Go | Назначение |
|---|---|---|
| `TravelMode` | `TravelMode` | Способ передвижения; пустое значение заменяется на `auto`. |
| `DepartureAt` | `*time.Time` | Необязательное время отправления. |
| `Alternatives` | `bool` | Требуется ли запросить альтернативные варианты. |
| `Vehicle` | `*VehicleConstraints` | Необязательные ограничения транспорта. |

### `RouteSummary`

| Поле | Тип Go | Назначение |
|---|---|---|
| `DistanceMeters` | `float64` | Полная длина маршрута в метрах. |
| `DurationSeconds` | `int64` | Расчетное время движения в секундах. |

### `RouteLeg`

| Поле | Тип Go | Назначение |
|---|---|---|
| `From` | `Point` | Начальная точка участка. |
| `To` | `Point` | Конечная точка участка. |
| `DistanceMeters` | `float64` | Длина участка в метрах. |
| `DurationSeconds` | `int64` | Время прохождения участка в секундах. |

### `CalculatedRoute`

| Поле | Тип Go | Назначение |
|---|---|---|
| `Summary` | `RouteSummary` | Итоговые длина и время маршрута. |
| `EncodedPolyline` | `string` | Линия маршрута в кодировке polyline6 для карты. |
| `Legs` | `[]RouteLeg` | Участки между исходной, промежуточными и конечной точками. |
| `SnappedPoints` | `[]Point` | Координаты, привязанные к доступным дорогам. |
| `Engine` | `string` | Название механизма расчета. |

### `Route`

| Поле | Тип Go | Назначение |
|---|---|---|
| `ID` | `string` | Уникальный идентификатор маршрута. |
| `TicketID` | `string` | Идентификатор заявки. |
| `BrigadeID` | `string` | Идентификатор назначенной бригады. |
| `Status` | `RouteStatus` | Текущее состояние маршрута. |
| `Origin` | `Point` | Точка начала движения. |
| `Destination` | `Point` | Место назначения. |
| `Waypoints` | `[]Point` | Промежуточные точки. |
| `Options` | `RouteOptions` | Параметры расчета. |
| `Calculation` | `CalculatedRoute` | Последний успешный результат. |
| `Revision` | `int32` | Версия маршрута; увеличивается при перерасчете. |
| `CreatedAt` | `time.Time` | Время создания. |
| `UpdatedAt` | `time.Time` | Время последнего изменения. |
| `CalculationStartedAt` | `*time.Time` | Начало последнего успешного расчета. |
| `CalculationFinishedAt` | `*time.Time` | Окончание последнего успешного расчета. |
| `CalculationDurationMillis` | `*float64` | Продолжительность расчета в миллисекундах. |
| `CalculationSuccess` | `*bool` | Признак успешного расчета. |

### `CalculationFailure`

| Поле | Тип Go | Назначение |
|---|---|---|
| `AggregateType` | `string` | Вид сущности: `ticket` или `route`. |
| `AggregateID` | `string` | Идентификатор сущности. |
| `TicketID` | `string` | Идентификатор заявки. |
| `BrigadeID` | `string` | Идентификатор бригады. |
| `RouteID` | `string` | Идентификатор маршрута, если он уже создан. |
| `Engine` | `string` | Название механизма маршрутизации. |
| `TravelMode` | `TravelMode` | Режим движения. |
| `FailureCode` | `string` | Нормализованный код причины. |
| `FailureReason` | `string` | Исходный текст ошибки. |
| `CalculationStartedAt` | `time.Time` | Начало неудачного расчета. |
| `CalculationFinishedAt` | `time.Time` | Окончание неудачного расчета. |
| `CalculationDurationMS` | `float64` | Продолжительность в миллисекундах. |

### Входные и выходные модели

| Структура | Поля | Назначение |
|---|---|---|
| `BuildRouteInput` | `Origin`, `Destination`, `Waypoints`, `Options` | Расчет одного маршрута без сохранения. |
| `BuildMatrixInput` | `Sources`, `Targets`, `Options` | Матрица между исходными и конечными точками; каждая сторона содержит от 1 до 100 точек. |
| `MatrixCell` | `SourceIndex`, `TargetIndex`, `DistanceMeters`, `DurationSeconds`, `Reachable` | Индексы пары, расстояние, время и доступность пути. |
| `Candidate` | `BrigadeID`, `Location` | Бригада и ее текущая координата. |
| `RankedCandidate` | `Candidate`, `Rank`, `DistanceMeters`, `ETASeconds`, `Reachable` | Бригада с местом, расстоянием и временем прибытия. |
| `RankCandidatesInput` | `Destination`, `Candidates`, `Options`, `Limit` | Место назначения, бригады, параметры и ограничение результата. |
| `CreateRouteInput` | `TicketID`, `BrigadeID`, `Origin`, `Destination`, `Waypoints`, `Options` | Данные для расчета и сохранения маршрута заявки. |
| `RecalculateRouteInput` | `ID`, `CurrentPosition` | Идентификатор маршрута и новая позиция бригады. |
| `ListRoutesInput` | `TicketID`, `BrigadeID`, `Status`, `Limit`, `Offset` | Условия отбора и постраничный вывод. |
| `ListRoutesResult` | `Routes`, `Total` | Страница маршрутов и полное число записей. |

## Функции

Имя функции открывает её реализацию в ветке `test`; структуры параметров и результатов описаны в конце README.

### func [New](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/src/core/service/routing_service.go#L23)

```go
func New(
    repo RouteRepository,
    engine RoutingEngine,
    logger *zap.Logger,
) *Service
```

Типы: [RouteRepository](#type-routerepository), [RoutingEngine](#type-routingengine), [Service](#type-service).

Структуры: [RouteRepository](#type-routerepository), [RoutingEngine](#type-routingengine).

Принимает `RouteRepository`, `RoutingEngine` и `*zap.Logger`, возвращает `*Service`. Если журнал отсутствует, подставляет `zap.NewNop()`, поэтому методы не проверяют журнал на `nil`.

### func [canTransition](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/src/core/service/status.go#L36)

```go
func canTransition(
    current models.RouteStatus,
    target models.RouteStatus,
) bool
```

Возвращает `true` только для четырех разрешенных переходов состояния, перечисленных в общем описании.

### func [routingEngineName](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/src/core/service/routing_service.go#L267)

```go
func routingEngineName(engine RoutingEngine) string
```

Типы: [RoutingEngine](#type-routingengine).

Структуры: [RoutingEngine](#type-routingengine).

Получает имя через необязательный метод `Name`, убирает пробелы и переводит его в нижний регистр. Для отсутствующего или пустого имени возвращает `unknown`.

### func [routingFailureCode](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/src/core/service/routing_service.go#L275)

```go
func routingFailureCode(err error) string
```

Возвращает `ENGINE_TIMEOUT` для превышения срока, `REQUEST_CANCELED` для отмены, `INVALID_REQUEST` для неверных данных и `ENGINE_ERROR` для остальных ошибок.

### func (Point) [Validate](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/models/validator.go#L10)

```go
func (p Point) Validate(field string) error
```

Типы: [Point](#type-point).

Проверяет диапазоны широты и долготы. Имя поля включается в ошибку, чтобы указать неверную точку. Возвращает `ErrInvalidArgument` при выходе широты за `[-90, 90]` или долготы за `[-180, 180]`.


### func (RouteOptions) [Normalize](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/models/validator.go#L20)

```go
func (o RouteOptions) Normalize() RouteOptions
```

Типы: [RouteOptions](#type-routeoptions).

Возвращает копию параметров и подставляет `TravelModeAuto`, если режим не указан. Остальные поля не меняет.


### func (RouteOptions) [Validate](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/models/validator.go#L27)

```go
func (o RouteOptions) Validate() error
```

Типы: [RouteOptions](#type-routeoptions).

Разрешает только поддерживаемые режимы движения и пустое значение. Затем проверяет каждое заданное ограничение транспорта: нулевые и отрицательные значения запрещены.


### func (*BuildRouteInput) [Validate](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/models/validator.go#L50)

```go
func (in *BuildRouteInput) Validate() error
```

Типы: [BuildRouteInput](#type-buildrouteinput).

Отклоняет отсутствующий запрос, проверяет исходную и конечную координаты, каждую промежуточную точку и параметры маршрута. Возвращает первую найденную ошибку.


### func (*BuildMatrixInput) [Validate](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/models/validator.go#L68)

```go
func (in *BuildMatrixInput) Validate() error
```

Типы: [BuildMatrixInput](#type-buildmatrixinput).

Требует хотя бы одну исходную и одну конечную точку. Каждая сторона ограничена 100 точками. Затем проверяет все координаты и параметры.


### func (*CreateRouteInput) [Validate](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/models/validator.go#L88)

```go
func (in *CreateRouteInput) Validate() error
```

Типы: [CreateRouteInput](#type-createrouteinput).

Отклоняет отсутствующий запрос, проверяет `TicketID` и `BrigadeID` как UUID, затем использует `BuildRouteInput.Validate` для остальных полей.


### func (*Service) [BuildRoute](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/src/core/service/routing_service.go#L38)

```go
func (s *Service) BuildRoute(
    ctx context.Context,
    in *models.BuildRouteInput,
) (*models.CalculatedRoute, error)
```

Типы: [BuildRouteInput](#type-buildrouteinput), [CalculatedRoute](#type-calculatedroute), [Service](#type-service).

1. Проверяет `BuildRouteInput`.
2. Подставляет режим `auto`, если он пуст.
3. Вызывает `RoutingEngine.BuildRoute`.
4. При ошибке пишет предупреждение и возвращает исходную ошибку.
5. При успехе возвращает `CalculatedRoute` без сохранения.


### func (*Service) [BuildMatrix](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/src/core/service/routing_service.go#L54)

```go
func (s *Service) BuildMatrix(
    ctx context.Context,
    in *models.BuildMatrixInput,
) ([]models.MatrixCell, error)
```

Типы: [BuildMatrixInput](#type-buildmatrixinput), [MatrixCell](#type-matrixcell), [Service](#type-service).

Проверяет запрос, нормализует режим и вызывает `RoutingEngine.BuildMatrix`. Возвращает список `MatrixCell` без сохранения.


### func (*Service) [RankCandidates](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/src/core/service/routing_service.go#L65)

```go
func (s *Service) RankCandidates(
    ctx context.Context,
    in *models.RankCandidatesInput,
) ([]models.RankedCandidate, error)
```

Типы: [RankCandidatesInput](#type-rankcandidatesinput), [RankedCandidate](#type-rankedcandidate), [Service](#type-service).

1. Требует непустой список бригад и корректное место назначения.
2. Проверяет непустой `BrigadeID` и координату каждой бригады.
3. Строит матрицу от всех бригад к одной точке заявки.
4. Переносит из соответствующей ячейки расстояние, время и доступность.
5. Стабильно сортирует: доступные маршруты раньше недоступных, затем меньшее время, затем меньшее расстояние.
6. Применяет положительный `Limit` и присваивает места начиная с единицы.


### func (*Service) [CreateRoute](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/src/core/service/routing_service.go#L125)

```go
func (s *Service) CreateRoute(
    ctx context.Context,
    in *models.CreateRouteInput,
) (*models.Route, error)
```

Типы: [CreateRouteInput](#type-createrouteinput), [Route](#type-route), [Service](#type-service).

1. Проверяет запрос.
2. Ищет открытый маршрут, если хранилище реализует `GetOpenRouteByTicket`.
3. Для той же бригады возвращает существующий маршрут; для другой возвращает `ErrConflict`.
4. Запоминает начало и вызывает `BuildRoute`.
5. При ошибке формирует `CalculationFailure` для сущности `ticket`; ошибка расчета объединяется с возможной ошибкой записи события.
6. При успехе создает UUID, устанавливает `PLANNED`, версию `1`, временные отметки и `CalculationSuccess=true`.
7. Копирует промежуточные точки в отдельный срез и вызывает `RouteRepository.CreateRoute`.


### func (*Service) [GetRoute](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/src/core/service/routing_service.go#L194)

```go
func (s *Service) GetRoute(
    ctx context.Context,
    id string,
) (*models.Route, error)
```

Типы: [Route](#type-route), [Service](#type-service).

Проверяет `id` как UUID и вызывает `RouteRepository.GetRoute`. Неверный формат не передается базе данных.


### func (*Service) [RecalculateRoute](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/src/core/service/routing_service.go#L204)

```go
func (s *Service) RecalculateRoute(
    ctx context.Context,
    in *models.RecalculateRouteInput,
) (*models.Route, error)
```

Типы: [RecalculateRouteInput](#type-recalculaterouteinput), [Route](#type-route), [Service](#type-service).

1. Проверяет запрос и текущую координату.
2. Загружает маршрут через `GetRoute`.
3. Строит новый путь от текущей позиции до прежнего назначения с прежними промежуточными точками и параметрами.
4. При ошибке формирует `CalculationFailure` для сущности `route`.
5. При успехе заменяет начало и расчет, увеличивает `Revision`, обновляет временные показатели и вызывает `UpdateCalculation`.


### func (*Service) [SetRouteStatus](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/src/core/service/status.go#L13)

```go
func (s *Service) SetRouteStatus(
    ctx context.Context,
    id string,
    target models.RouteStatus,
) (*models.Route, error)
```

Типы: [Route](#type-route), [Service](#type-service).

Проверяет UUID, загружает маршрут и проверяет переход через `canTransition`. Недопустимый переход возвращает `ErrConflict`; допустимый передается `UpdateStatus`.


### func (*Service) [ListRoutes](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/src/core/service/routing_service.go#L288)

```go
func (s *Service) ListRoutes(
    ctx context.Context,
    in *models.ListRoutesInput,
) (*models.ListRoutesResult, error)
```

Типы: [ListRoutesInput](#type-listroutesinput), [ListRoutesResult](#type-listroutesresult), [Service](#type-service).

При отсутствии запроса создает пустой фильтр. Неположительный `Limit` заменяет на `50`. Значение больше `500` и отрицательный `Offset` отклоняет. Затем вызывает хранилище.


### func (*Service) [recordCalculationFailure](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/src/core/service/routing_service.go#L257)

```go
func (s *Service) recordCalculationFailure(ctx context.Context, failure models.CalculationFailure) error
```

Типы: [CalculationFailure](#type-calculationfailure), [Service](#type-service).

Проверяет, реализует ли хранилище дополнительный метод `RecordCalculationFailure`. Если нет, завершает работу без ошибки; если да, передает ему сведения о сбое.


## Структура БД

### Таблица `routes`

Хранит последнюю версию маршрута. Частичный уникальный индекс разрешает только один маршрут `PLANNED` или `ACTIVE` на заявку.

| Поле | Тип PostgreSQL | Содержание и назначение |
|---|---|---|
| `id` | `uuid` | Первичный ключ; по умолчанию `gen_random_uuid()`. |
| `ticket_id` | `uuid` | Идентификатор заявки. |
| `brigade_id` | `uuid` | Идентификатор назначенной бригады. |
| `status` | `text` | Состояние из четырех допустимых значений. |
| `origin` | `jsonb` | Исходная координата. |
| `destination` | `jsonb` | Конечная координата. |
| `waypoints` | `jsonb` | Промежуточные точки; по умолчанию пустой массив. |
| `options` | `jsonb` | Параметры расчета. |
| `calculation` | `jsonb` | Последний успешный результат. |
| `revision` | `integer` | Версия, по умолчанию `1`; должна быть больше нуля. |
| `created_at` | `timestamptz` | Время создания. |
| `updated_at` | `timestamptz` | Время изменения. |

Индексы ускоряют поиск по `ticket_id`, `brigade_id` и `status` с сортировкой по времени. `routes_one_open_route_per_ticket_idx` обеспечивает единственность открытого маршрута.

### Таблица `outbox_events`

Хранит события для надежной публикации в Kafka.

| Поле | Тип PostgreSQL | Содержание и назначение |
|---|---|---|
| `id` | `uuid` | Первичный ключ события. |
| `aggregate_type` | `text` | Вид сущности; по умолчанию `route`. |
| `aggregate_id` | `uuid` | Идентификатор сущности. |
| `event_type` | `text` | Тип события. |
| `payload` | `jsonb` | Полезная нагрузка. |
| `status` | `text` | Состояние публикации; начальное значение `PENDING`. |
| `attempts` | `integer` | Число попыток отправки. |
| `next_attempt_at` | `timestamptz` | Время следующей разрешенной попытки. |
| `locked_at` | `timestamptz` | Время захвата обработчиком. |
| `sent_at` | `timestamptz` | Время успешной публикации. |
| `last_error` | `text` | Последняя ошибка отправки. |
| `created_at` | `timestamptz` | Время создания. |

### Таблица `ticket_inbox_events`

Хранит обработанные события заявок и предотвращает повторное применение сообщения Kafka.

| Поле | Тип PostgreSQL | Содержание и назначение |
|---|---|---|
| `event_id` | `uuid` | Первичный ключ и идентификатор события. |
| `event_type` | `text` | Тип события заявки. |
| `topic` | `text` | Раздел Kafka, из которого пришло сообщение. |
| `partition_id` | `integer` | Номер раздела Kafka. |
| `message_offset` | `bigint` | Позиция сообщения в разделе. |
| `payload` | `jsonb` | Полученные данные события. |
| `processed_at` | `timestamptz` | Время фиксации обработки. |

## Структуры параметров и результатов

### type BuildMatrixInput

```go
type BuildMatrixInput struct {
	Sources []Point
	Targets []Point
	Options RouteOptions
}
```

### type BuildRouteInput

```go
type BuildRouteInput struct {
	Origin      Point
	Destination Point
	Waypoints   []Point
	Options     RouteOptions
}
```

### type CalculatedRoute

```go
type CalculatedRoute struct {
	Summary         RouteSummary `json:"summary"`
	EncodedPolyline string       `json:"encoded_polyline"`
	Legs            []RouteLeg   `json:"legs"`
	SnappedPoints   []Point      `json:"snapped_points"`
	Engine          string       `json:"engine"`
}
```

### type CalculationFailure

```go
type CalculationFailure struct {
	AggregateType         string     `json:"aggregate_type"`
	AggregateID           string     `json:"aggregate_id"`
	TicketID              string     `json:"ticket_id"`
	BrigadeID             string     `json:"brigade_id"`
	RouteID               string     `json:"route_id,omitempty"`
	Engine                string     `json:"engine"`
	TravelMode            TravelMode `json:"travel_mode"`
	FailureCode           string     `json:"failure_code"`
	FailureReason         string     `json:"failure_reason"`
	CalculationStartedAt  time.Time  `json:"calculation_started_at"`
	CalculationFinishedAt time.Time  `json:"calculation_finished_at"`
	CalculationDurationMS float64    `json:"calculation_duration_ms"`
}
```

### type CreateRouteInput

```go
type CreateRouteInput struct {
	TicketID    string
	BrigadeID   string
	Origin      Point
	Destination Point
	Waypoints   []Point
	Options     RouteOptions
}
```

### type ListRoutesInput

```go
type ListRoutesInput struct {
	TicketID  *string
	BrigadeID *string
	Status    *RouteStatus
	Limit     int32
	Offset    int32
}
```

### type ListRoutesResult

```go
type ListRoutesResult struct {
	Routes []*Route
	Total  int64
}
```

### type MatrixCell

```go
type MatrixCell struct {
	SourceIndex     int32
	TargetIndex     int32
	DistanceMeters  float64
	DurationSeconds int64
	Reachable       bool
}
```

### type Point

```go
type Point struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}
```

### type RankCandidatesInput

```go
type RankCandidatesInput struct {
	Destination Point
	Candidates  []Candidate
	Options     RouteOptions
	Limit       int32
}
```

### type RankedCandidate

```go
type RankedCandidate struct {
	Candidate
	Rank           int32
	DistanceMeters float64
	ETASeconds     int64
	Reachable      bool
}
```

### type RecalculateRouteInput

```go
type RecalculateRouteInput struct {
	ID              string
	CurrentPosition Point
}
```

### type Route

```go
type Route struct {
	ID                        string          `json:"id"`
	TicketID                  string          `json:"ticket_id"`
	BrigadeID                 string          `json:"brigade_id"`
	Status                    RouteStatus     `json:"status"`
	Origin                    Point           `json:"origin"`
	Destination               Point           `json:"destination"`
	Waypoints                 []Point         `json:"waypoints"`
	Options                   RouteOptions    `json:"options"`
	Calculation               CalculatedRoute `json:"calculation"`
	Revision                  int32           `json:"revision"`
	CreatedAt                 time.Time       `json:"created_at"`
	UpdatedAt                 time.Time       `json:"updated_at"`
	CalculationStartedAt      *time.Time      `json:"calculation_started_at,omitempty"`
	CalculationFinishedAt     *time.Time      `json:"calculation_finished_at,omitempty"`
	CalculationDurationMillis *float64        `json:"calculation_duration_ms,omitempty"`
	CalculationSuccess        *bool           `json:"calculation_success,omitempty"`
}
```

### type RouteOptions

```go
type RouteOptions struct {
	TravelMode   TravelMode          `json:"travel_mode"`
	DepartureAt  *time.Time          `json:"departure_at,omitempty"`
	Alternatives bool                `json:"alternatives"`
	Vehicle      *VehicleConstraints `json:"vehicle,omitempty"`
}
```

### type RouteRepository

```go
type RouteRepository interface {
	CreateRoute(
		ctx context.Context,
		route *models.Route,
	) (*models.Route, error)
	GetRoute(ctx context.Context, id string) (*models.Route, error)
	UpdateCalculation(
		ctx context.Context,
		route *models.Route,
	) (*models.Route, error)
	UpdateStatus(
		ctx context.Context,
		id string,
		expectedStatus models.RouteStatus,
		status models.RouteStatus,
	) (*models.Route, error)
	ListRoutes(
		ctx context.Context,
		in *models.ListRoutesInput,
	) (*models.ListRoutesResult, error)
}
```

### type RoutingEngine

```go
type RoutingEngine interface {
	BuildRoute(
		ctx context.Context,
		in *models.BuildRouteInput,
	) (*models.CalculatedRoute, error)
	BuildMatrix(
		ctx context.Context,
		in *models.BuildMatrixInput,
	) ([]models.MatrixCell, error)
}
```

### type Service

```go
type Service struct {
	repo   RouteRepository
	engine RoutingEngine
	log    *zap.Logger
}
```
