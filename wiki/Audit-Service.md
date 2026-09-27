# Сервис аудита (Audit Service)

## Ответственность

Неизменяемый журнал действий, построенный из domain events Kafka.

## Ключевое поведение

- Модель только для добавления записей.
- `UNIQUE(topic, event_id)` устраняет повтор одного event.
- PostgreSQL trigger запрещает UPDATE/DELETE existing audit entries.
- Сохраняются actor/entity/request/trace context и исходный event data.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL. |
| Синхронные взаимодействия | Нет обязательных domain synchronous dependencies. |
| Kafka | Consumer широкого набора domain topics; publisher отсутствует. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Полные сигнатуры и структуры параметров приведены в [справочнике функций Audit Service](https://automaticsystem.youtrack.cloud/articles/ACS-A-42/Kod-i-funkcii-Audit-Service).

### `NewAuditServiceStruct`

```go
func NewAuditServiceStruct(repo *repository.Repository) *AuditServiceStruct
```

Принимает общий `repository.Repository` и сохраняет отдельно интерфейсы записи
и чтения. Проверок соединения и запросов к базе конструктор не выполняет.

### `Consume`

```go
func (s *AuditServiceStruct) Consume(c context.Context, e models.Event) error
```

Принимает `models.Event` и передает его в `EntryWriterRepository.Store`.
Нормализация полей, преобразование содержимого и устранение повтора выполняются
репозиторием и ограничением базы. Возвращает ошибку записи без изменения.

### `Get`

```go
func (s *AuditServiceStruct) Get(c context.Context, id uuid.UUID) (*models.Entry, error)
```

Принимает идентификатор `uuid.UUID`, вызывает `EntryReaderRepository.Get` и
возвращает найденную `Entry`. Отсутствующая запись представляется ошибкой
репозитория.

### `List`

```go
func (s *AuditServiceStruct) List(c context.Context, f models.Filter) ([]*models.Entry, int64, error)
```

Принимает `models.Filter`, передает его репозиторию чтения и возвращает список
указателей на записи, общее число подходящих строк и ошибку. `Limit` и
`Offset` влияют на страницу, но не на общий счетчик.

### `NewService`

```go
func NewService(repo *repository.Repository) *Service
```

Создает оболочку `Service` и встраивает в нее реализацию
`AuditService`.

### `IsNotFound`

```go
func IsNotFound(err error) bool
```

Передает ошибку в `repository.IsNotFound`. Нужна вызывающему коду, чтобы
распознать отсутствие записи, не связываясь с внутренним типом ошибки
репозитория.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Audit_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Audit_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
