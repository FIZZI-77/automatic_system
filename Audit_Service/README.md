# Сервис аудита (Audit Service)

## Общее описание и общий принцип работы

`Audit_Service` формирует неизменяемый журнал действий из предметных событий
Kafka. Он сохраняет исходные данные события вместе с исполнителем,
идентификаторами сущности, запроса и распределенной трассировки, а затем
предоставляет чтение отдельных записей и выборку по фильтру.

Запись работает по принципу «только добавление». Повтор одного события
устраняется ограничением `UNIQUE(topic, event_id)`. PostgreSQL-триггер
`audit_entries_no_update` запрещает изменение и удаление уже записанной
строки. Прикладной слой не преобразует результат и не скрывает ошибки
репозитория.

## Модели

### `Entry`

| Поле | Тип Go | Назначение |
|---|---|---|
| `ID` | `uuid.UUID` | Внутренний идентификатор записи аудита. |
| `EventID` | `string` | Идентификатор исходного события. |
| `Topic` | `string` | Раздел Kafka, из которого получено событие. |
| `Action` | `string` | Вид зафиксированного действия. |
| `ActorID` | `*uuid.UUID` | Необязательный идентификатор исполнителя. |
| `EntityType` | `*string` | Необязательный вид затронутой сущности. |
| `EntityID` | `*string` | Необязательный идентификатор сущности. |
| `RequestID` | `*string` | Идентификатор исходного запроса. |
| `TraceID` | `*string` | Идентификатор распределенной трассировки. |
| `Data` | `map[string]any` | Полное содержимое события. |
| `OccurredAt` | `time.Time` | Время предметного действия. |
| `RecordedAt` | `time.Time` | Время записи в журнал аудита. |

### `Filter`

| Поле | Тип Go | Назначение |
|---|---|---|
| `ActorID` | `*uuid.UUID` | Отбор по исполнителю. |
| `Action` | `*string` | Отбор по действию. |
| `EntityType` | `*string` | Отбор по виду сущности. |
| `EntityID` | `*string` | Отбор по идентификатору сущности. |
| `RequestID` | `*string` | Отбор по запросу. |
| `TraceID` | `*string` | Отбор по распределенной трассировке. |
| `Topic` | `*string` | Отбор по разделу Kafka. |
| `From` | `*time.Time` | Необязательное начало периода. |
| `To` | `*time.Time` | Необязательный конец периода. |
| `Limit` | `int32` | Максимальное число строк. |
| `Offset` | `int32` | Число пропускаемых строк. |

### `Event`

| Поле | Тип Go | Назначение |
|---|---|---|
| `ID` | `string` | Идентификатор события. |
| `Type` | `string` | Вид события, преобразуемый репозиторием в действие. |
| `Topic` | `string` | Исходный раздел Kafka. |
| `Payload` | `map[string]any` | Разобранное содержимое. |
| `Headers` | `map[string]string` | Заголовки сообщения с дополнительным контекстом. |
| `Timestamp` | `time.Time` | Время исходного события. |

## Функции

Имя функции открывает её реализацию в ветке `test`; структуры параметров и результатов описаны в конце README.

### func [NewAuditServiceStruct](https://github.com/FIZZI-77/automatic_system/blob/test/Audit_Service/src/core/service/audit_service.go#L15)

```go
func NewAuditServiceStruct(repo *repository.Repository) *AuditServiceStruct
```

Типы: [AuditServiceStruct](#type-auditservicestruct), [Repository](#type-repository).

Структуры: [AuditServiceStruct](#type-auditservicestruct).

Принимает общий `repository.Repository` и сохраняет отдельно интерфейсы записи
и чтения. Проверок соединения и запросов к базе конструктор не выполняет.

### func (*AuditServiceStruct) [Consume](https://github.com/FIZZI-77/automatic_system/blob/test/Audit_Service/src/core/service/audit_service.go#L21)

```go
func (s *AuditServiceStruct) Consume(c context.Context, e models.Event) error
```

Типы: [AuditServiceStruct](#type-auditservicestruct), [Event](#type-event).

Структуры: [Event](#type-event).

Принимает `models.Event` и передает его в `EntryWriterRepository.Store`.
Нормализация полей, преобразование содержимого и устранение повтора выполняются
репозиторием и ограничением базы. Возвращает ошибку записи без изменения.

### func (*AuditServiceStruct) [Get](https://github.com/FIZZI-77/automatic_system/blob/test/Audit_Service/src/core/service/audit_service.go#L24)

```go
func (s *AuditServiceStruct) Get(c context.Context, id uuid.UUID) (*models.Entry, error)
```

Типы: [AuditServiceStruct](#type-auditservicestruct), [Entry](#type-entry).

Структуры: [Entry](#type-entry).

Принимает идентификатор `uuid.UUID`, вызывает `EntryReaderRepository.Get` и
возвращает найденную `Entry`. Отсутствующая запись представляется ошибкой
репозитория.

### func (*AuditServiceStruct) [List](https://github.com/FIZZI-77/automatic_system/blob/test/Audit_Service/src/core/service/audit_service.go#L27)

```go
func (s *AuditServiceStruct) List(c context.Context, f models.Filter) ([]*models.Entry, int64, error)
```

Типы: [AuditServiceStruct](#type-auditservicestruct), [Entry](#type-entry), [Filter](#type-filter).

Структуры: [Filter](#type-filter), [Entry](#type-entry).

Принимает `models.Filter`, передает его репозиторию чтения и возвращает список
указателей на записи, общее число подходящих строк и ошибку. `Limit` и
`Offset` влияют на страницу, но не на общий счетчик.

### func [NewService](https://github.com/FIZZI-77/automatic_system/blob/test/Audit_Service/src/core/service/service.go#L17)

```go
func NewService(repo *repository.Repository) *Service
```

Типы: [Repository](#type-repository), [Service](#type-service).

Создает оболочку `Service` и встраивает в нее реализацию
`AuditService`.

### func [IsNotFound](https://github.com/FIZZI-77/automatic_system/blob/test/Audit_Service/src/core/service/service.go#L20)

```go
func IsNotFound(err error) bool
```

Передает ошибку в `repository.IsNotFound`. Нужна вызывающему коду, чтобы
распознать отсутствие записи, не связываясь с внутренним типом ошибки
репозитория.

## Структура БД

### `audit_entries` — неизменяемый журнал

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `uuid` | Первичный ключ, по умолчанию `gen_random_uuid()`. |
| `event_id` | `text` | Идентификатор события; обязателен. |
| `topic` | `text` | Раздел Kafka; обязателен. |
| `action` | `text` | Вид действия; обязателен. |
| `actor_id` | `uuid` | Необязательный исполнитель. |
| `entity_type` | `text` | Необязательный вид сущности. |
| `entity_id` | `text` | Необязательный идентификатор сущности. |
| `request_id` | `text` | Необязательный идентификатор запроса. |
| `trace_id` | `text` | Необязательный идентификатор трассировки. |
| `data` | `jsonb` | Полное содержимое события; обязательно. |
| `occurred_at` | `timestamptz` | Время действия; обязательно. |
| `recorded_at` | `timestamptz` | Время записи, по умолчанию `now()`. |

Пара `(topic, event_id)` уникальна. Индексы ускоряют чтение по времени,
исполнителю, сущности, действию, запросу и распределенной трассировке.
Функция `audit_entries_immutable()` и триггер
`audit_entries_no_update` отклоняют любые `UPDATE` и `DELETE`, поэтому
исправление истории выполняется только добавлением нового события.

## Структуры параметров и результатов

### type AuditServiceStruct

```go
type AuditServiceStruct struct {
	writer repository.EntryWriterRepository
	reader repository.EntryReaderRepository
}
```

### type Entry

```go
type Entry struct {
	ID         uuid.UUID
	EventID    string
	Topic      string
	Action     string
	ActorID    *uuid.UUID
	EntityType *string
	EntityID   *string
	RequestID  *string
	TraceID    *string
	Data       map[string]any
	OccurredAt time.Time
	RecordedAt time.Time
}
```

### type Event

```go
type Event struct {
	ID        string
	Type      string
	Topic     string
	Payload   map[string]any
	Headers   map[string]string
	Timestamp time.Time
}
```

### type Filter

```go
type Filter struct {
	ActorID    *uuid.UUID
	Action     *string
	EntityType *string
	EntityID   *string
	RequestID  *string
	TraceID    *string
	Topic      *string
	From       *time.Time
	To         *time.Time
	Limit      int32
	Offset     int32
}
```

### type Repository

```go
type Repository struct {
	EntryWriterRepository
	EntryReaderRepository
}
```

### type Service

```go
type Service struct{ AuditService }
```
