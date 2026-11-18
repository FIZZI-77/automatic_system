# Сервис подразделений (Department Service)

## Ответственность

Справочник подразделений и их lifecycle.

## Ключевое поведение

- Состояния: `ACTIVE`, `INACTIVE`, `ARCHIVED`.
- Создание/изменение/архивирование разрешены admin/dispatcher.
- Write transaction объединяет domain change, idempotency result и outgoing event.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL. |
| Синхронные взаимодействия | Прямых downstream gRPC clients в карте взаимодействий не отмечено. |
| Kafka | Publisher: `departments.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Полные сигнатуры и структуры параметров приведены в [справочнике функций Department Service](https://automaticsystem.youtrack.cloud/articles/ACS-A-35/Kod-i-funkcii-Department-Service).

### `NewDepartmentServiceStruct`

```go
func NewDepartmentServiceStruct(repo *repository.Repository, logger *zap.Logger) *DepartmentServiceStruct
```

Создает реализацию с общим репозиторием и журналом. Значения не проверяет.

### `CreateDepartment`

```go
func (s *DepartmentServiceStruct) CreateDepartment(ctx context.Context, in *models.CreateDepartmentInput) (*models.CreateDepartmentResult, error)
```

1. Проверяет входную модель.
2. Требует роль `admin` или `dispatcher`.
3. Запускает `CreateDepartment` репозитория внутри `withIdempotency`.
4. Сохраняет идентификатор результата для записи идемпотентности.
5. Приводит как новый, так и восстановленный из JSON результат к
   `CreateDepartmentResult`.
6. Записывает идентификатор, имя и длительность в журнал.

### `GetDepartmentByID`

```go
func (s *DepartmentServiceStruct) GetDepartmentByID(ctx context.Context, in *models.GetDepartmentByIDInput) (*models.GetDepartmentByIDResult, error)
```

Проверяет ненулевой UUID, загружает подразделение, оборачивает ошибку контекстом
метода и возвращает `GetDepartmentByIDResult`.

### `ListDepartments`

```go
func (s *DepartmentServiceStruct) ListDepartments(ctx context.Context, in *models.ListDepartmentsInput) (*models.ListDepartmentsResult, error)
```

Проверяет и одновременно нормализует фильтр, передает его репозиторию и
возвращает страницу и общий счетчик. В журнале фиксируются количество и
длительность.

### `UpdateDepartment`

```go
func (s *DepartmentServiceStruct) UpdateDepartment(ctx context.Context, in *models.UpdateDepartmentInput) (*models.UpdateDepartmentResult, error)
```

Проверяет вход, право и наличие хотя бы одного нового значения. Изменение
выполняется через общий механизм идемпотентности. Возвращает полную запись после
обновления.

### `DeleteDepartment`

```go
func (s *DepartmentServiceStruct) DeleteDepartment(ctx context.Context, in *models.DeleteDepartmentInput) (*models.DeleteDepartmentResult, error)
```

Проверяет UUID и право, затем выполняет репозиторную операцию через
идемпотентную транзакцию. Метод возвращает состояние записи после операции; по
коду прикладного слоя физическое удаление не предполагается и определяется
репозиторием.

### `hasPrivilegedRole`

```go
func hasPrivilegedRole(roles []string) bool
```

Последовательно просматривает роли и возвращает `true` только для точного
значения `admin` или `dispatcher`.

### `withIdempotency`

```go
func (s *DepartmentServiceStruct) withIdempotency(ctx context.Context, operation string, actorKey string, request any, fn func(context.Context) (any, uuid.UUID, error)) (any, error)
```

Без ключа сразу выполняет переданную функцию. С ключом вычисляет хеш JSON и
вызывает `RunIdempotentTx` со сроком 24 часа. Для существующей записи сверяет
хеш: `COMPLETED` возвращает сохраненный ответ, `PROCESSING` дает
`ErrIdempotencyInProgress`, `FAILED` — `ErrIdempotencyFailed`, другой
запрос с тем же ключом — `ErrIdempotencyConflict`.

### `cachedResult`

```go
func cachedResult[T any](result any) (*T, error)
```

Возвращает указатель нужного типа напрямую либо преобразует восстановленный
универсальный JSON-объект через сериализацию и разбор.

### `hashRequest`

```go
func hashRequest(request any) (string, error)
```

Сериализует запрос, вычисляет `SHA-256` и возвращает шестнадцатеричный хеш.

### `NewService`

```go
func NewService(repo *repository.Repository, logger *zap.Logger) *Service
```

Подставляет `zap.NewNop()` вместо отсутствующего журнала и создает оболочку
`Service` с `DepartmentServiceStruct`.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Department_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Department_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
