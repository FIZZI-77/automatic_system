# Сервис подразделений (Department Service)

## Общее описание и общий принцип работы

`Department_Service` управляет справочником подразделений. Чтение доступно
через получение одной записи и постраничный список. Создание, изменение и
архивирование разрешены только ролям `admin` и `dispatcher`.

Изменяющие методы поддерживают ключ идемпотентности из контекста. Репозиторий
выполняет изменение, запись результата идемпотентности и создание исходящего
события в одной транзакции. Ошибки проверки оборачиваются
`models.ErrValidation`.

## Модели

### Перечисления

| Тип | Значения | Назначение |
|---|---|---|
| `DepartmentStatus` | `ACTIVE`, `INACTIVE`, `ARCHIVED` | Состояние подразделения. |
| `DepartmentSortBy` | `created_at`, `updated_at`, `name`, `status` | Поле сортировки списка. |
| `SortOrder` | `asc`, `desc` | Направление сортировки. |

Методы `IsValid` каждого перечисления проверяют точное совпадение с одним из
перечисленных значений.

### Основные структуры

| Структура | Поля и назначение |
|---|---|
| `Department` | `ID` — идентификатор; `Name` — уникальное название; `Description` — описание; `Status` — состояние; `CreatedAt`, `UpdatedAt` — времена создания и изменения. |
| `CreateDepartmentInput` | `Name` — название; `Description` — описание; `ActorRoles` — роли автора для проверки права. |
| `CreateDepartmentResult` | `Department` — созданное подразделение. |
| `GetDepartmentByIDInput` | `ID` — искомое подразделение. |
| `GetDepartmentByIDResult` | `Department` — найденное подразделение. |
| `ListDepartmentsInput` | `Status` — необязательное состояние; `CreatedFrom`, `CreatedTo` — период создания; `SortBy` — поле; `SortOrder` — направление; `Limit`, `Offset` — страница. |
| `ListDepartmentsResult` | `Departments` — страница; `Total` — общее число. |
| `UpdateDepartmentInput` | `ID` — подразделение; `Name`, `Description`, `Status` — необязательные новые значения; `ActorRoles` — роли автора. |
| `UpdateDepartmentResult` | `Department` — измененная запись. |
| `DeleteDepartmentInput` | `ID` — подразделение; `ActorRoles` — роли автора. |
| `DeleteDepartmentResult` | `Department` — запись после удаления или архивирования. |

### Проверка входных данных

`validateUUID` отклоняет нулевой UUID. `validateText` требует непустую
строку и ограничивает ее длину в байтах; `validateOptionalText` пропускает
`nil`. `normalizeLimitOffset` задает предел 20, максимум 100 и заменяет
отрицательное смещение на 0.

`CreateDepartmentInput.Validate` требует название до 255 байтов и допускает
пустое описание, иначе ограничивает его 1000 байт.
`ListDepartmentsInput.Validate` проверяет состояние и период, по умолчанию
сортирует по `created_at desc` и нормализует страницу.
`UpdateDepartmentInput.Validate` требует UUID, проверяет переданные значения
и требует хотя бы одно изменение. `DeleteDepartmentInput.Validate` проверяет
UUID.

## Функции

Имя функции открывает её реализацию в ветке `test`; структуры параметров и результатов описаны в конце README.

### func [NewDepartmentServiceStruct](https://github.com/FIZZI-77/automatic_system/blob/test/Department_Service/src/core/service/department_service.go#L21)

```go
func NewDepartmentServiceStruct(repo *repository.Repository, logger *zap.Logger) *DepartmentServiceStruct
```

Типы: [DepartmentServiceStruct](#type-departmentservicestruct), [Repository](#type-repository).

Создаёт сервис с переданными репозиторием и журналом. Конструктор не проверяет `nil` и не открывает соединений; фактические вызовы методов требуют готовых зависимостей. `NewService` ниже создаёт `zap.NewNop()` при отсутствии журнала.

### func (*DepartmentServiceStruct) [CreateDepartment](https://github.com/FIZZI-77/automatic_system/blob/test/Department_Service/src/core/service/department_service.go#L25)

```go
func (s *DepartmentServiceStruct) CreateDepartment(ctx context.Context, in *models.CreateDepartmentInput) (*models.CreateDepartmentResult, error)
```

Типы: [CreateDepartmentInput](#type-createdepartmentinput), [CreateDepartmentResult](#type-createdepartmentresult), [DepartmentServiceStruct](#type-departmentservicestruct).

Вход: [CreateDepartmentInput](#type-createdepartmentinput). Результат: [CreateDepartmentResult](#type-createdepartmentresult) → [Department](#type-department).

Создаёт запись подразделения. Сначала добавляет `request_id` из контекста к журналу и проверяет вход: название непустое и не длиннее 255 байт, описание пустое либо не длиннее 1000 байт. Затем проверяет точное наличие роли `admin` или `dispatcher`. Ошибки этих двух проверок возвращаются как `ErrValidation` и `ErrPermissionDenied` до обращения к БД.

Операция передаётся в `withIdempotency` с именем `CreateDepartment` и пустым `actorKey`. Репозиторий вставляет запись и outbox-событие в транзакции; уникальность `name` обеспечивает БД. При повторе с тем же ключом и содержимым сервис восстанавливает результат из JSON через `cachedResult`. Ошибки оборачиваются контекстом метода; успешный ответ содержит полную `Department`. Журнал фиксирует ID, имя и длительность.

### func (*DepartmentServiceStruct) [GetDepartmentByID](https://github.com/FIZZI-77/automatic_system/blob/test/Department_Service/src/core/service/department_service.go#L79)

```go
func (s *DepartmentServiceStruct) GetDepartmentByID(ctx context.Context, in *models.GetDepartmentByIDInput) (*models.GetDepartmentByIDResult, error)
```

Типы: [DepartmentServiceStruct](#type-departmentservicestruct), [GetDepartmentByIDInput](#type-getdepartmentbyidinput), [GetDepartmentByIDResult](#type-getdepartmentbyidresult).

Вход: [GetDepartmentByIDInput](#type-getdepartmentbyidinput). Результат: [GetDepartmentByIDResult](#type-getdepartmentbyidresult) → [Department](#type-department).

Проверяет, что UUID не нулевой, затем вызывает чтение репозитория по ID. Возвращает найденную запись без проверки привилегированной роли и без идемпотентности, поскольку метод не меняет состояние. Ошибка репозитория сохраняется через `%w`, поэтому вызывающий код может распознать `NotFound`; журнал содержит ID и длительность.

### func (*DepartmentServiceStruct) [ListDepartments](https://github.com/FIZZI-77/automatic_system/blob/test/Department_Service/src/core/service/department_service.go#L115)

```go
func (s *DepartmentServiceStruct) ListDepartments(ctx context.Context, in *models.ListDepartmentsInput) (*models.ListDepartmentsResult, error)
```

Типы: [DepartmentServiceStruct](#type-departmentservicestruct), [ListDepartmentsInput](#type-listdepartmentsinput), [ListDepartmentsResult](#type-listdepartmentsresult).

Вход: [ListDepartmentsInput](#type-listdepartmentsinput). Результат: [ListDepartmentsResult](#type-listdepartmentsresult) → [Department](#type-department).

`Validate` проверяет фильтр `Status`, границы периода создания и сортировку; выставляет `created_at desc`, если порядок не задан, нормализует `Limit` до 20 по умолчанию и до 100 максимум, отрицательный `Offset` заменяет на 0. Репозиторий выполняет выборку страницы и подсчёт `Total`. Возвращаются массив `Departments` и общее число записей независимо от размера страницы; журнал фиксирует число записей и длительность.

### func (*DepartmentServiceStruct) [UpdateDepartment](https://github.com/FIZZI-77/automatic_system/blob/test/Department_Service/src/core/service/department_service.go#L150)

```go
func (s *DepartmentServiceStruct) UpdateDepartment(ctx context.Context, in *models.UpdateDepartmentInput) (*models.UpdateDepartmentResult, error)
```

Типы: [DepartmentServiceStruct](#type-departmentservicestruct), [UpdateDepartmentInput](#type-updatedepartmentinput), [UpdateDepartmentResult](#type-updatedepartmentresult).

Вход: [UpdateDepartmentInput](#type-updatedepartmentinput). Результат: [UpdateDepartmentResult](#type-updatedepartmentresult) → [Department](#type-department).

Проверяет ненулевой ID, корректность переданных `Name`, `Description`, `Status` и наличие хотя бы одного изменяемого поля. После проверки роли `admin` или `dispatcher` вызывает репозиторий внутри механизма идемпотентности. Репозиторий меняет только переданные поля, обновляет `updated_at`, возвращает запись и сохраняет outbox-событие в той же транзакции. Повтор завершённой операции восстанавливает полный ответ; ошибки оборачиваются, в журнал попадают ID, итоговый статус и длительность.

### func (*DepartmentServiceStruct) [DeleteDepartment](https://github.com/FIZZI-77/automatic_system/blob/test/Department_Service/src/core/service/department_service.go#L204)

```go
func (s *DepartmentServiceStruct) DeleteDepartment(ctx context.Context, in *models.DeleteDepartmentInput) (*models.DeleteDepartmentResult, error)
```

Типы: [DeleteDepartmentInput](#type-deletedepartmentinput), [DeleteDepartmentResult](#type-deletedepartmentresult), [DepartmentServiceStruct](#type-departmentservicestruct).

Вход: [DeleteDepartmentInput](#type-deletedepartmentinput). Результат: [DeleteDepartmentResult](#type-deletedepartmentresult) → [Department](#type-department).

Проверяет ненулевой ID и роль `admin` или `dispatcher`, после чего выполняет операцию через `withIdempotency`. В репозитории это `UPDATE departments SET status = ARCHIVED, updated_at = now() WHERE id = ... RETURNING ...`, а затем запись `department.archived` в outbox той же транзакции. Метод возвращает архивированную запись; строка физически остаётся в БД. Повтор с тем же ключом возвращает сохранённый результат.

### func [hasPrivilegedRole](https://github.com/FIZZI-77/automatic_system/blob/test/Department_Service/src/core/service/department_service.go#L258)

```go
func hasPrivilegedRole(roles []string) bool
```

Последовательно проверяет элементы среза на точное совпадение с `admin` или `dispatcher`. Возвращает `true` при первом совпадении, иначе `false`; регистр и пробелы не нормализует.

### func (*DepartmentServiceStruct) [withIdempotency](https://github.com/FIZZI-77/automatic_system/blob/test/Department_Service/src/core/service/idempotency.go#L19)

```go
func (s *DepartmentServiceStruct) withIdempotency(ctx context.Context, operation string, actorKey string, request any, fn func(context.Context) (any, uuid.UUID, error)) (any, error)
```

Типы: [DepartmentServiceStruct](#type-departmentservicestruct).

Извлекает ключ из контекста. Если ключа нет, вызывает `fn` непосредственно. Иначе сериализует запрос в JSON, считает SHA-256 и передаёт ключ, хеш, имя операции и срок 24 часа в `RunIdempotentTx`. При новом ключе функция выполняется внутри транзакции, в которой репозиторий сохраняет доменное изменение, outbox и результат идемпотентности.

Если ключ уже занят, сначала сравнивается `RequestHash`. Другой запрос с тем же ключом даёт `ErrIdempotencyConflict`; `COMPLETED` декодирует сохранённый JSON-ответ; `PROCESSING` и `FAILED` возвращают соответствующие ошибки. Неизвестный статус и сбой декодирования не маскируются успешным ответом. В текущих вызовах `actorKey` — пустая строка.

### func [cachedResult](https://github.com/FIZZI-77/automatic_system/blob/test/Department_Service/src/core/service/idempotency.go#L63)

```go
func cachedResult[T any](result any) (*T, error)
```

Возвращает уже типизированный указатель напрямую. Сохранённый ответ, декодированный как универсальный JSON-объект, сериализует и декодирует в `T`, чтобы новые и повторные вызовы имели одинаковый тип результата. Ошибку преобразования возвращает вызывающему методу.

### func [hashRequest](https://github.com/FIZZI-77/automatic_system/blob/test/Department_Service/src/core/service/idempotency.go#L81)

```go
func hashRequest(request any) (string, error)
```

Сериализует входной запрос через `json.Marshal`, считает SHA-256 полученных байтов и выдаёт хеш в шестнадцатеричном виде. Невозможность сериализации возвращает как ошибку идемпотентности, не вызывая предметную операцию.

### func [NewService](https://github.com/FIZZI-77/automatic_system/blob/test/Department_Service/src/core/service/service.go#L24)

```go
func NewService(repo *repository.Repository, logger *zap.Logger) *Service
```

Типы: [Repository](#type-repository), [Service](#type-service).

Подставляет `zap.NewNop()` вместо отсутствующего журнала и создает оболочку
`Service` с `DepartmentServiceStruct`.


## Структура БД

### `departments` — подразделения

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `UUID` | Первичный ключ, создаваемый приложением. |
| `name` | `VARCHAR(255)` | Уникальное обязательное название. |
| `description` | `TEXT` | Описание, по умолчанию пустое. |
| `status` | `VARCHAR(32)` | `ACTIVE`, `INACTIVE` или `ARCHIVED`. |
| `created_at` | `TIMESTAMP` | Время создания. |
| `updated_at` | `TIMESTAMP` | Время изменения. |

Отдельные индексы созданы по состоянию и обоим временам.

### `outbox_events` — исходящие события

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `UUID` | Первичный ключ события. |
| `aggregate_type` | `VARCHAR(100)` | Вид сущности. |
| `aggregate_id` | `UUID` | Идентификатор подразделения. |
| `event_type` | `VARCHAR(100)` | Вид события. |
| `payload` | `JSONB` | Содержимое события. |
| `status` | `VARCHAR(50)` | `PENDING`, `PROCESSING`, `SENT` или `FAILED`. |
| `attempts` | `INT` | Число попыток. |
| `last_error` | `TEXT` | Последняя ошибка. |
| `next_attempt_at` | `TIMESTAMP` | Следующая попытка публикации. |
| `locked_at` | `TIMESTAMP` | Время захвата обработчиком. |
| `created_at` | `TIMESTAMP` | Время создания. |
| `sent_at` | `TIMESTAMP` | Время успешной публикации. |

Индексы поддерживают очередь повторов, поиск по сущности и виду события.

### `idempotency_keys` — результаты повторяемых операций

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `UUID` | Первичный ключ. |
| `actor_key` | `VARCHAR(128)` | Владелец области ключа; в текущих вызовах передается пустая строка. |
| `operation` | `VARCHAR(100)` | Имя операции. |
| `idempotency_key` | `VARCHAR(128)` | Ключ запроса. |
| `request_hash` | `VARCHAR(128)` | Хеш входных данных. |
| `status` | `VARCHAR(32)` | `PROCESSING`, `COMPLETED` или `FAILED`. |
| `response` | `JSONB` | Сохраненный успешный ответ. |
| `error` | `TEXT` | Текст ошибки. |
| `resource_type` | `VARCHAR(100)` | Вид ресурса. |
| `resource_id` | `UUID` | Идентификатор ресурса. |
| `created_at`, `updated_at`, `expires_at` | `TIMESTAMP` | Создание, изменение и окончание срока хранения. |

Сочетание `actor_key`, `operation`, `idempotency_key` уникально; индексы
созданы по сроку и состоянию.

## Структуры параметров и результатов

### type CreateDepartmentInput

```go
type CreateDepartmentInput struct {
	Name        string
	Description string
	ActorRoles  []string
}
```

### type CreateDepartmentResult

```go
type CreateDepartmentResult struct {
	Department *Department
}
```

### type DeleteDepartmentInput

```go
type DeleteDepartmentInput struct {
	ID         uuid.UUID
	ActorRoles []string
}
```

### type DeleteDepartmentResult

```go
type DeleteDepartmentResult struct {
	Department *Department
}
```

### type Department

```go
type Department struct {
	ID          uuid.UUID
	Name        string
	Description string
	Status      DepartmentStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
```

### type DepartmentServiceStruct

```go
type DepartmentServiceStruct struct {
	repo   *repository.Repository
	logger *zap.Logger
}
```

### type GetDepartmentByIDInput

```go
type GetDepartmentByIDInput struct {
	ID uuid.UUID
}
```

### type GetDepartmentByIDResult

```go
type GetDepartmentByIDResult struct {
	Department *Department
}
```

### type ListDepartmentsInput

```go
type ListDepartmentsInput struct {
	Status      *DepartmentStatus
	CreatedFrom *time.Time
	CreatedTo   *time.Time
	SortBy      DepartmentSortBy
	SortOrder   SortOrder
	Limit       int32
	Offset      int32
}
```

### type ListDepartmentsResult

```go
type ListDepartmentsResult struct {
	Departments []*Department
	Total       int64
}
```

### type Repository

```go
type Repository struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
	DepartmentRepository
}
```

### type Service

```go
type Service struct {
	DepartmentService
}
```

### type UpdateDepartmentInput

```go
type UpdateDepartmentInput struct {
	ID          uuid.UUID
	Name        *string
	Description *string
	Status      *DepartmentStatus
	ActorRoles  []string
}
```

### type UpdateDepartmentResult

```go
type UpdateDepartmentResult struct {
	Department *Department
}
```
