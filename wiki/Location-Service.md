# Сервис местоположения (Location Service)

## Ответственность

Приём GPS, последнее положение, history, nearby search, geozones и signal-loss detection.

## Ключевое поведение

- Последняя позиция пишется синхронно в Redis.
- Новая non-duplicate position помещается в bounded history buffer и batch-пишется в PostGIS.
- Ошибка history buffer не откатывает уже принятое current location.
- Signal state change и event в Redis Stream фиксируются атомарно.
- Simulator может отправлять telemetry по HTTP; доменный API также доступен через gRPC.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | Redis + PostgreSQL/PostGIS. |
| Синхронные взаимодействия | Предоставляет данные Dispatch; сам не требует перечисленных domain gRPC clients. |
| Kafka | `locations.events.v1` публикуется через Redis Stream → Kafka. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Полные сигнатуры и структуры параметров приведены в [справочнике функций Location Service](https://automaticsystem.youtrack.cloud/articles/ACS-A-31/Kod-i-funkcii-Location-Service).

### `positionBuffer.Add`

```go
func (w *Worker) Add(position *models.Position) error
```

```go
func (b *MemoryPositionBuffer) Add(position *models.Position) error
```

```go
func (c *Closer) Add(name string, fn func() error)
```

Добавляет позицию в конец буфера под блокировкой. Если достигнута заданная вместимость, сообщает вызывающему коду, что пакет пора выгрузить.

### `positionBuffer.Len`

```go
func (b *MemoryPositionBuffer) Len() int
```

Под блокировкой возвращает текущее количество ожидающих позиций.

### `positionBuffer.TakeBatch`

```go
func (b *MemoryPositionBuffer) TakeBatch(maxSize int) []*models.Position
```

Извлекает до заданного числа первых позиций, копирует их в отдельный срез и удаляет из очереди. Пустой или неположительный размер возвращает пустой результат.

### `positionBuffer.Prepend`

```go
func (b *MemoryPositionBuffer) Prepend(batch []*models.Position)
```

Возвращает неотправленный пакет в начало очереди, сохраняя его порядок перед более новыми позициями.

### Конструкторы позиций

`NewPositionServiceStruct` создает сервис без буфера истории.
`NewPositionServiceStructWithHistory` добавляет приемник истории.
`NewPositionServiceStructWithLogger` является полным конструктором и заменяет
пустой журнал на `zap.NewNop()`.

### `RecordPosition`

```go
func (s *PositionServiceStruct) RecordPosition(
    ctx context.Context,
    in *models.RecordPositionInput,
) (*models.RecordPositionResult, error)
```

Проверяет вход, сохраняет текущую позицию в Redis через
`SaveCurrentLocation` и возвращает точку с признаком повтора. Только новую
точку добавляет в настроенный буфер истории. Переполнение буфера
`ErrPositionBufferFull` записывается как предупреждение, но не превращает
успешный прием текущей позиции в ошибку.

### `GetCurrentLocation` и `GetCurrentLocations`

```go
func (s *PositionServiceStruct) GetCurrentLocation(
    ctx context.Context,
    in *models.GetCurrentLocationInput,
) (*models.GetCurrentLocationResult, error)
```

```go
func (s *PositionServiceStruct) GetCurrentLocations(
    ctx context.Context,
    in *models.GetCurrentLocationsInput,
) (*models.GetCurrentLocationsResult, error)
```

Первый метод проверяет вид и идентификатор одной сущности. Второй требует
непустой список ненулевых UUID бригад и учитывает `AllowStale`. Оба передают
запрос репозиторию и добавляют имя операции к ошибке.

### `ListPositionHistory`

```go
func (s *PositionServiceStruct) ListPositionHistory(
    ctx context.Context,
    in *models.ListPositionHistoryInput,
) (*models.ListPositionHistoryResult, error)
```

Проверяет бригаду, обязательный корректный период, порядок и страницу, затем
возвращает точки из PostGIS и общий счетчик.

### `FindNearbyBrigades`

```go
func (s *PositionServiceStruct) FindNearbyBrigades(
    ctx context.Context,
    in *models.FindNearbyBrigadesInput,
) (*models.FindNearbyBrigadesResult, error)
```

Проверяет координаты, положительный радиус и предел до 1000. Репозиторий
выполняет пространственный поиск, может ограничить множество бригад и свежесть.

### `DetectLostSignals`

```go
func (s *PositionServiceStruct) DetectLostSignals(
    ctx context.Context,
    in *models.DetectLostSignalsInput,
) (*models.DetectLostSignalsResult, error)
```

Проверяет временные границы и размер пакета, затем вызывает атомарную операцию
репозитория. При изменениях журналирует их количество. Возвращает только
фактически выполненные переходы.

### `validationError`

```go
func validationError(operation string, err error) error
```

Оборачивает причину именем операции и `models.ErrValidation`, сохраняя
возможность распознавания через `errors.Is`.

### Конструкторы геозон

`NewGeoZoneServiceStruct` создает реализацию с пустым журналом.
`NewGeoZoneServiceStructWithLogger` принимает журнал и подставляет
`zap.NewNop()` для `nil`.

### `CreateGeoZone`

```go
func (s *GeoZoneServiceStruct) CreateGeoZone(
    ctx context.Context,
    in *models.CreateGeoZoneInput,
) (*models.CreateGeoZoneResult, error)
```

Требует подразделение, название, GeoJSON и роль управления. Репозиторий
проверяет и сохраняет геометрию PostGIS; сервис оборачивает ошибку и
журналирует созданный UUID.

### `UpdateGeoZone`

```go
func (s *GeoZoneServiceStruct) UpdateGeoZone(
    ctx context.Context,
    in *models.UpdateGeoZoneInput,
) (*models.UpdateGeoZoneResult, error)
```

Требует UUID, хотя бы одно новое поле и право управления, затем выполняет
частичное обновление.

### `DeleteGeoZone`

```go
func (s *GeoZoneServiceStruct) DeleteGeoZone(
    ctx context.Context,
    in *models.DeleteGeoZoneInput,
) (*models.DeleteGeoZoneResult, error)
```

Проверяет UUID и право и передает удаление репозиторию. Возвращает полную зону,
полученную от него.

### `ListGeoZones`

```go
func (s *GeoZoneServiceStruct) ListGeoZones(
    ctx context.Context,
    in *models.ListGeoZonesInput,
) (*models.ListGeoZonesResult, error)
```

Проверяет страницу и возвращает зоны с общим количеством, учитывая
необязательные подразделение и активность.

### `CheckPointInZones`

```go
func (s *GeoZoneServiceStruct) CheckPointInZones(
    ctx context.Context,
    in *models.CheckPointInZonesInput,
) (*models.CheckPointInZonesResult, error)
```

Проверяет координаты и возвращает активные либо выбранные репозиторием зоны,
геометрия которых содержит точку.

### `canManageZones`

```go
func canManageZones(roles []string) bool
```

Нормализует каждую роль и разрешает `admin`, `system_admin` и
`dispatcher`.

### `NewMemoryPositionBuffer`

```go
func NewMemoryPositionBuffer(capacity int) *MemoryPositionBuffer
```

Создает защищенный мьютексом буфер. Неположительная емкость заменяется на
10 000.

### `MemoryPositionBuffer.Add`

Отклоняет `nil`, затем под блокировкой проверяет емкость и добавляет указатель
на позицию. При заполнении возвращает `ErrPositionBufferFull`.

### `MemoryPositionBuffer.TakeBatch`

Под блокировкой выбирает начало очереди. Неположительный или слишком большой
размер означает весь буфер. Возвращаемый срез копируется, извлеченные ссылки
очищаются, остаток сдвигается без сохранения удаленных указателей.

### `MemoryPositionBuffer.Prepend`

Добавляет пакет в начало перед уже накопленными элементами. Используется для
возврата пакета после ошибки записи истории. Пустой пакет ничего не меняет.

### `MemoryPositionBuffer.Len`

Возвращает текущую длину под тем же мьютексом.

### Конструкторы общего сервиса

`NewService` создает сервис без истории, `NewServiceWithPositionHistory` —
с приемником истории, `NewServiceWithLogger` — полный вариант. Последний
создает обе реализации, позиций и геозон, с общим репозиторием и журналом.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Location_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Location_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
