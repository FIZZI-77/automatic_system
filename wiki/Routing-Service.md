# Сервис маршрутизации (Routing Service)

## Ответственность

Route calculation, distance/time matrix, brigade ranking и persisted route lifecycle.

## Ключевое поведение

- Routing engine — Valhalla.
- Повторный create для той же ticket+brigade может вернуть существующий open route; другая brigade для уже открытого route даёт conflict.
- Route states: `PLANNED`, `ACTIVE`, `COMPLETED`, `CANCELLED`.
- Изменения маршрута фиксируются вместе с outbox events.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL + Valhalla. |
| Синхронные взаимодействия | Valhalla external routing engine. |
| Kafka | Publisher: `routing.events.v1`; consumer: `tickets.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Полные сигнатуры и структуры параметров приведены в [справочнике функций Routing Service](https://automaticsystem.youtrack.cloud/articles/ACS-A-29/Kod-i-funkcii-Routing-Service).

### `New`

```go
func New(
    repo RouteRepository,
    engine RoutingEngine,
    logger *zap.Logger,
) *Service
```

Принимает `RouteRepository`, `RoutingEngine` и `*zap.Logger`, возвращает `*Service`. Если журнал отсутствует, подставляет `zap.NewNop()`, поэтому методы не проверяют журнал на `nil`.

### `Point.Validate`

```go
func (p Point) Validate(field string) error
```

```go
func (o RouteOptions) Validate() error
```

```go
func (in *BuildRouteInput) Validate() error
```

```go
func (in *BuildMatrixInput) Validate() error
```

```go
func (in *CreateRouteInput) Validate() error
```

Проверяет диапазоны широты и долготы. Имя поля включается в ошибку, чтобы указать неверную точку. Возвращает `ErrInvalidArgument` при выходе широты за `[-90, 90]` или долготы за `[-180, 180]`.

### `RouteOptions.Normalize`

```go
func (o RouteOptions) Normalize() RouteOptions
```

Возвращает копию параметров и подставляет `TravelModeAuto`, если режим не указан. Остальные поля не меняет.

### `RouteOptions.Validate`

Разрешает только поддерживаемые режимы движения и пустое значение. Затем проверяет каждое заданное ограничение транспорта: нулевые и отрицательные значения запрещены.

### `BuildRouteInput.Validate`

Отклоняет отсутствующий запрос, проверяет исходную и конечную координаты, каждую промежуточную точку и параметры маршрута. Возвращает первую найденную ошибку.

### `BuildMatrixInput.Validate`

Требует хотя бы одну исходную и одну конечную точку. Каждая сторона ограничена 100 точками. Затем проверяет все координаты и параметры.

### `CreateRouteInput.Validate`

Отклоняет отсутствующий запрос, проверяет `TicketID` и `BrigadeID` как UUID, затем использует `BuildRouteInput.Validate` для остальных полей.

### `Service.BuildRoute`

```go
func (s *Service) BuildRoute(
    ctx context.Context,
    in *models.BuildRouteInput,
) (*models.CalculatedRoute, error)
```

1. Проверяет `BuildRouteInput`.
2. Подставляет режим `auto`, если он пуст.
3. Вызывает `RoutingEngine.BuildRoute`.
4. При ошибке пишет предупреждение и возвращает исходную ошибку.
5. При успехе возвращает `CalculatedRoute` без сохранения.

### `Service.BuildMatrix`

```go
func (s *Service) BuildMatrix(
    ctx context.Context,
    in *models.BuildMatrixInput,
) ([]models.MatrixCell, error)
```

Проверяет запрос, нормализует режим и вызывает `RoutingEngine.BuildMatrix`. Возвращает список `MatrixCell` без сохранения.

### `Service.RankCandidates`

```go
func (s *Service) RankCandidates(
    ctx context.Context,
    in *models.RankCandidatesInput,
) ([]models.RankedCandidate, error)
```

1. Требует непустой список бригад и корректное место назначения.
2. Проверяет непустой `BrigadeID` и координату каждой бригады.
3. Строит матрицу от всех бригад к одной точке заявки.
4. Переносит из соответствующей ячейки расстояние, время и доступность.
5. Стабильно сортирует: доступные маршруты раньше недоступных, затем меньшее время, затем меньшее расстояние.
6. Применяет положительный `Limit` и присваивает места начиная с единицы.

### `Service.CreateRoute`

```go
func (s *Service) CreateRoute(
    ctx context.Context,
    in *models.CreateRouteInput,
) (*models.Route, error)
```

1. Проверяет запрос.
2. Ищет открытый маршрут, если хранилище реализует `GetOpenRouteByTicket`.
3. Для той же бригады возвращает существующий маршрут; для другой возвращает `ErrConflict`.
4. Запоминает начало и вызывает `BuildRoute`.
5. При ошибке формирует `CalculationFailure` для сущности `ticket`; ошибка расчета объединяется с возможной ошибкой записи события.
6. При успехе создает UUID, устанавливает `PLANNED`, версию `1`, временные отметки и `CalculationSuccess=true`.
7. Копирует промежуточные точки в отдельный срез и вызывает `RouteRepository.CreateRoute`.

### `Service.GetRoute`

```go
func (s *Service) GetRoute(
    ctx context.Context,
    id string,
) (*models.Route, error)
```

Проверяет `id` как UUID и вызывает `RouteRepository.GetRoute`. Неверный формат не передается базе данных.

### `Service.RecalculateRoute`

```go
func (s *Service) RecalculateRoute(
    ctx context.Context,
    in *models.RecalculateRouteInput,
) (*models.Route, error)
```

1. Проверяет запрос и текущую координату.
2. Загружает маршрут через `GetRoute`.
3. Строит новый путь от текущей позиции до прежнего назначения с прежними промежуточными точками и параметрами.
4. При ошибке формирует `CalculationFailure` для сущности `route`.
5. При успехе заменяет начало и расчет, увеличивает `Revision`, обновляет временные показатели и вызывает `UpdateCalculation`.

### `Service.SetRouteStatus`

```go
func (s *Service) SetRouteStatus(
    ctx context.Context,
    id string,
    target models.RouteStatus,
) (*models.Route, error)
```

Проверяет UUID, загружает маршрут и проверяет переход через `canTransition`. Недопустимый переход возвращает `ErrConflict`; допустимый передается `UpdateStatus`.

### `canTransition`

```go
func canTransition(
    current models.RouteStatus,
    target models.RouteStatus,
) bool
```

Возвращает `true` только для четырех разрешенных переходов состояния, перечисленных в общем описании.

### `Service.ListRoutes`

```go
func (s *Service) ListRoutes(
    ctx context.Context,
    in *models.ListRoutesInput,
) (*models.ListRoutesResult, error)
```

При отсутствии запроса создает пустой фильтр. Неположительный `Limit` заменяет на `50`. Значение больше `500` и отрицательный `Offset` отклоняет. Затем вызывает хранилище.

### `Service.recordCalculationFailure`

```go
func (s *Service) recordCalculationFailure(ctx context.Context, failure models.CalculationFailure) error
```

Проверяет, реализует ли хранилище дополнительный метод `RecordCalculationFailure`. Если нет, завершает работу без ошибки; если да, передает ему сведения о сбое.

### `routingEngineName`

```go
func routingEngineName(engine RoutingEngine) string
```

Получает имя через необязательный метод `Name`, убирает пробелы и переводит его в нижний регистр. Для отсутствующего или пустого имени возвращает `unknown`.

### `routingFailureCode`

```go
func routingFailureCode(err error) string
```

Возвращает `ENGINE_TIMEOUT` для превышения срока, `REQUEST_CANCELED` для отмены, `INVALID_REQUEST` для неверных данных и `ENGINE_ERROR` для остальных ошибок.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Routing_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
