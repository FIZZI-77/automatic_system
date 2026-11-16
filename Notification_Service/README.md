# Сервис уведомлений (Notification Service)

## Общее описание и общий принцип работы

`Notification_Service` преобразует выбранные события заявок в долговечные
уведомления пользователей. PostgreSQL является источником истины, а
`Publisher` передает уже созданные уведомления в канал живых соединений.
Предпочтения пользователя определяют независимые доставки внутри приложения,
через FCM, электронную почту и СМС.

`Consume` сознательно пропускает события, которых нет в разрешенном списке.
Для поддерживаемого события репозиторий определяет получателей и одной
операцией создает уведомления и доставки. Ошибка живой публикации игнорируется:
запись уже сохранена, поэтому клиент после переподключения может получить ее
через `List`.

## События Kafka

**Издатель `notifications.events.v1` — Notification_Service.** Это отдельный
канал от Redis/live `Publisher`: PostgreSQL-триггеры сохраняют исходящие события
в `outbox_events` атомарно с изменением уведомления или доставки, затем
[фоновый передатчик](src/cmd/server/outbox.go) отправляет их в Kafka.
Топик читают Audit и Analytics. Сам Notification не подписан на собственный топик.

| Тип события | Когда создаётся |
|---|---|
| `notification.created` | Создана запись уведомления в `Dispatch`, в том числе при выключенном IN_APP. |
| `notification.read` | Признак прочтения изменён с `false` на `true` через `MarkRead` или `MarkAllRead`. |
| `notification.delivery.sent` | Доставка переведена в `SENT`. |
| `notification.delivery.failed` | Попытка доставки завершилась состоянием `FAILED`. |
| `notification.delivery.dead` | Доставка переведена в `DEAD` после исчерпания попыток. |

Повтор исходного события не создаёт новые уведомления и исходящие события.
Повторное прочтение и отклонённое обновление устаревшей попытки доставки также
не создают событий. `notification.created` не означает успешную доставку;
`notification.delivery.sent` отражает сохранённый результат соответствующего
канала, а прочтение подтверждается отдельным событием.

Kafka key — ID уведомления. Общие поля JSON: `event_id`, `event_type`,
`event_version=1`, `occurred_at`, `entity_type=notification`, `entity_id`,
`notification_id`, `user_id`, `source_event_id`, `source_event_type`.
События уведомления дополнительно содержат `read`, события доставки —
`delivery_id`, `channel`, `status`, `attempts`. `source_event_id` связывает
уведомление с исходным входящим событием и отличается от ID исходящего события.
Тексты, адреса получателей, токены устройств, ID провайдеров и их ошибки
в Kafka payload не включаются.

Перед запуском нужно применить
[миграцию outbox](scheme/20261116000100_create_event_outbox.sql), задать
`KAFKA_BROKERS` и создать топик через `kafka-init`. Исторические записи
автоматически не публикуются. Доставка — at-least-once: после подтверждения Kafka
записывается `sent_at`; сбой между этими шагами может вызвать повтор с тем же
`event_id` и временем события. Передатчик сохраняет неотправленные строки,
повторяет отправку с задержкой до 256 секунд и восстанавливается после перезапуска.

Из каталога Notification_Service проверки атомарности, идемпотентности и
восстановления передатчика запускаются так:

```powershell
$env:OUTBOX_TEST_DATABASE_URL = "postgres://user:password@localhost:5432/test_db?sslmode=disable"
go test -tags=integration -v ./src/infrastructure/outboxrelay
```

Без `OUTBOX_TEST_DATABASE_URL` эти проверки пропускаются. В CI они подключены
к PostgreSQL. Общая карта потоков — в
[событийной архитектуре](../wiki/Event-Driven-Architecture.md), диагностика — в
[Troubleshooting](../wiki/Troubleshooting.md#5-kafka-events-пропали).

## Модели

### `Notification`

| Поле | Тип Go | Назначение |
|---|---|---|
| `ID` | `uuid.UUID` | Идентификатор уведомления. |
| `EventID` | `string` | Исходное событие. |
| `UserID` | `uuid.UUID` | Получатель. |
| `EventType` | `string` | Вид исходного события. |
| `Title` | `string` | Заголовок. |
| `Body` | `string` | Текст. |
| `Data` | `map[string]string` | Дополнительные неперсональные данные. |
| `Read` | `bool` | Признак прочтения. |
| `ReadAt` | `*time.Time` | Время прочтения. |
| `CreatedAt` | `time.Time` | Время создания. |

### Остальные структуры

| Структура | Поля и назначение |
|---|---|
| `Preferences` | `UserID` — пользователь; `InApp`, `Push`, `Email`, `SMS` — разрешенные каналы; `EmailAddress`, `Phone` — необязательные адрес и номер; `UpdatedAt` — время изменения. |
| `Device` | `ID` — устройство; `UserID` — владелец; `Token` — токен FCM; `Platform` — `android`, `ios` или `web`; `Active` — пригодность токена; `CreatedAt`, `UpdatedAt` — времена. |
| `Template` | `ID` — шаблон; `EventType` — вид события; `Channel` — канал; `Subject` — тема; `Body` — текст с подстановками; `Active` — активность; `CreatedAt`, `UpdatedAt` — времена. |
| `Delivery` | `ID` — доставка; `NotificationID` — уведомление; `Channel` — канал; `Recipient` — адрес получателя; `Status` — состояние; `ProviderID` — идентификатор внешнего поставщика; `LastError` — последняя ошибка; `Attempts` — попытки; `NextAttemptAt` — следующая попытка; `CreatedAt`, `UpdatedAt` — времена. |
| `Event` | `ID` — событие; `Type` — вид; `Topic` — раздел Kafka; `Payload` — разобранное содержимое. |

## Функции

Имя функции открывает её реализацию в ветке `test`; структуры параметров и результатов описаны в конце README.

### func [New](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/core/service/service.go#L23)

```go
func New(r *repository.Repository, p Publisher) *Service
```

Типы: [Publisher](#type-publisher), [Repository](#type-repository), [Service](#type-service).

Структуры: [Publisher](#type-publisher).

Создает сервис с репозиторием и необязательным издателем живых уведомлений.

### func (*Service) [Consume](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/core/service/service.go#L24)

```go
func (s *Service) Consume(c context.Context, e models.Event) error
```

Типы: [Event](#type-event), [Service](#type-service).

Структуры: [Event](#type-event).

1. Проверяет вид события через `isUserFacingEvent`; неизвестное событие
   считается успешно пропущенным.
2. Вызывает `ResolveRecipients`.
3. Передает событие и получателей в `Dispatch`, который сохраняет уведомления
   и доставки.
4. Для каждого созданного уведомления вызывает `live.Publish`, если издатель
   настроен.
5. Ошибка живого канала не возвращается и не отменяет сохраненные данные.

### func [isUserFacingEvent](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/core/service/service.go#L45)

```go
func isUserFacingEvent(eventType string) bool
```

Удаляет пробелы, приводит вид события к нижнему регистру и разрешает:
`ticket.created`, `ticket.assigned`, `ticket.status_changed`,
`ticket.completed`, `ticket.canceled`,
`ticket.completion_report.generated.v1` и
`ticket.completion_report.failed.v1`.

### func (*Service) [List](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/core/service/service.go#L59)

```go
func (s *Service) List(c context.Context, u uuid.UUID, x *bool, l, o int32) ([]*models.Notification, int64, int64, error)
```

Типы: [Notification](#type-notification), [Service](#type-service).

Структуры: [Notification](#type-notification).

Передает пользователя, необязательный признак прочтения, предел и смещение
репозиторию. Возвращает страницу уведомлений, общее количество и число
непрочитанных.

### func (*Service) [MarkRead](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/core/service/service.go#L62)

```go
func (s *Service) MarkRead(c context.Context, u, id uuid.UUID) (*models.Notification, error)
```

Типы: [Notification](#type-notification), [Service](#type-service).

Структуры: [Notification](#type-notification).

Помечает одно уведомление пользователя прочитанным. Ошибка отсутствующей строки
преобразуется функцией `mapErr` в `ErrNotFound`.

### func (*Service) [MarkAllRead](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/core/service/service.go#L66)

```go
func (s *Service) MarkAllRead(c context.Context, u uuid.UUID) (int64, error)
```

Типы: [Service](#type-service).

Помечает прочитанными все уведомления пользователя и возвращает число
измененных строк.

### func (*Service) [GetPreferences](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/core/service/service.go#L69)

```go
func (s *Service) GetPreferences(c context.Context, u uuid.UUID) (*models.Preferences, error)
```

Типы: [Preferences](#type-preferences), [Service](#type-service).

Структуры: [Preferences](#type-preferences).

Читает настройки каналов пользователя из репозитория по UUID. Возвращает полную `Preferences` либо ошибку чтения без изменения состояния.

### func (*Service) [SavePreferences](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/core/service/service.go#L72)

```go
func (s *Service) SavePreferences(c context.Context, v *models.Preferences) (*models.Preferences, error)
```

Типы: [Preferences](#type-preferences), [Service](#type-service).

Структуры: [Preferences](#type-preferences).

Передаёт всю `Preferences` репозиторию для вставки либо обновления; возвращает сохранённую структуру и ошибку операции. Проверка разрешённых каналов и адресов выполняется на уровне данных репозитория.

### func (*Service) [RegisterDevice](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/core/service/service.go#L75)

```go
func (s *Service) RegisterDevice(c context.Context, v *models.Device) (*models.Device, error)
```

Типы: [Device](#type-device), [Service](#type-service).

Структуры: [Device](#type-device).

Приводит платформу к нижнему регистру, удаляет пробелы и требует непустой токен
и платформу `android`, `ios` или `web`. Затем регистрирует устройство
через репозиторий.

### func (*Service) [DeleteDevice](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/core/service/service.go#L82)

```go
func (s *Service) DeleteDevice(c context.Context, u, id uuid.UUID) (*models.Device, error)
```

Типы: [Device](#type-device), [Service](#type-service).

Структуры: [Device](#type-device).

Удаляет либо деактивирует устройство конкретного пользователя. Отсутствие
строки преобразуется в `ErrNotFound`.

### func (*Service) [UpsertTemplate](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/core/service/service.go#L86)

```go
func (s *Service) UpsertTemplate(c context.Context, v *models.Template) (*models.Template, error)
```

Типы: [Service](#type-service), [Template](#type-template).

Структуры: [Template](#type-template).

Требует непустые `EventType`, `Body` и `Channel`, после чего вставляет или
обновляет шаблон. Допустимость канала дополнительно защищена ограничением базы.

### func (*Service) [ListTemplates](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/core/service/service.go#L92)

```go
func (s *Service) ListTemplates(c context.Context, e, ch *string, l, o int32) ([]*models.Template, int64, error)
```

Типы: [Service](#type-service), [Template](#type-template).

Структуры: [Template](#type-template).

Возвращает страницу шаблонов с необязательными ограничениями по событию и
каналу.

### func (*Service) [ListDeliveries](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/core/service/service.go#L95)

```go
func (s *Service) ListDeliveries(c context.Context, st, ch *string, l, o int32) ([]*models.Delivery, int64, error)
```

Типы: [Delivery](#type-delivery), [Service](#type-service).

Структуры: [Delivery](#type-delivery).

Возвращает страницу попыток доставки с необязательными ограничениями по
состоянию и каналу.

### func [mapErr](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/core/service/service.go#L98)

```go
func mapErr(e error) error
```

Преобразует `pgx.ErrNoRows` в предметную `ErrNotFound`; остальные ошибки
возвращает без изменения.

## Структура БД

### `notification_preferences` — предпочтения

| Поле | Тип | Назначение |
|---|---|---|
| `user_id` | `uuid` | Пользователь и первичный ключ. |
| `in_app_enabled`, `push_enabled`, `email_enabled` | `bool` | Разрешение каналов, по умолчанию `true`. |
| `sms_enabled` | `bool` | Разрешение СМС, по умолчанию `false`. |
| `email`, `phone` | `text` | Необязательные адрес и номер телефона. |
| `updated_at` | `timestamptz` | Время изменения. |

### `devices` — устройства FCM

| Поле | Тип | Назначение |
|---|---|---|
| `id`, `user_id` | `uuid` | Устройство и пользователь. |
| `token` | `text` | Уникальный токен FCM. |
| `platform` | `text` | `android`, `ios` или `web`. |
| `active` | `bool` | Активность токена. |
| `created_at`, `updated_at` | `timestamptz` | Времена записи. |

### `notification_templates` — шаблоны

| Поле | Тип | Назначение |
|---|---|---|
| `id` | `uuid` | Первичный ключ. |
| `event_type` | `text` | Вид события. |
| `channel` | `text` | `IN_APP`, `PUSH`, `EMAIL` или `SMS`. |
| `subject` | `text` | Тема, по умолчанию пустая. |
| `body` | `text` | Текст шаблона. |
| `active` | `bool` | Активность. |
| `created_at`, `updated_at` | `timestamptz` | Времена записи. |

Пара `(event_type, channel)` уникальна.

### `notifications` — уведомления

| Поле | Тип | Назначение |
|---|---|---|
| `id` | `uuid` | Первичный ключ. |
| `event_id` | `text` | Исходное событие. |
| `user_id` | `uuid` | Получатель. |
| `event_type`, `title`, `body` | `text` | Вид, заголовок и текст. |
| `data` | `jsonb` | Дополнительные данные. |
| `read` | `bool` | Признак прочтения. |
| `read_at` | `timestamptz` | Время прочтения. |
| `created_at` | `timestamptz` | Время создания. |

Пара `(event_id, user_id)` уникальна.

### `deliveries` — доставки по каналам

| Поле | Тип | Назначение |
|---|---|---|
| `id`, `notification_id` | `uuid` | Доставка и уведомление. |
| `channel`, `recipient`, `status` | `text` | Канал, адрес и состояние. |
| `provider_id` | `text` | Идентификатор поставщика. |
| `attempts` | `int` | Число попыток. |
| `next_attempt_at`, `locked_at` | `timestamptz` | Следующая попытка и захват. |
| `last_error` | `text` | Последняя ошибка. |
| `created_at`, `updated_at` | `timestamptz` | Времена записи. |

Сочетание уведомления, канала и получателя уникально.

### `event_inbox` — принятые события

| Поле | Тип | Назначение |
|---|---|---|
| `event_id` | `text` | Первичный ключ для устранения повторов. |
| `event_type`, `topic` | `text` | Вид и раздел Kafka. |
| `payload` | `jsonb` | Исходное содержимое. |
| `processed_at` | `timestamptz` | Время обработки. |

### `ticket_recipients` — получатели заявки

| Поле | Тип | Назначение |
|---|---|---|
| `ticket_id` | `uuid` | Заявка и первичный ключ. |
| `user_id` | `uuid` | Пользователь, связанный с заявкой. |
| `department_id` | `uuid` | Подразделение. |
| `brigade_id` | `uuid` | Назначенная бригада. |
| `updated_at` | `timestamptz` | Время обновления снимка. |

## Структуры параметров и результатов

### type Delivery

```go
type Delivery struct {
	ID             uuid.UUID
	NotificationID uuid.UUID
	Channel        string
	Recipient      string
	Title          string
	Body           string
	Status         string
	ProviderID     *string
	LastError      *string
	Attempts       int32
	NextAttemptAt  time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
```

### type Device

```go
type Device struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Token     string
	Platform  string
	Active    bool
	CreatedAt time.Time
	UpdatedAt time.Time
}
```

### type Event

```go
type Event struct {
	ID      string
	Type    string
	Topic   string
	Payload map[string]any
}
```

### type Notification

```go
type Notification struct {
	ID        uuid.UUID
	EventID   string
	UserID    uuid.UUID
	EventType string
	Title     string
	Body      string
	Data      map[string]string
	Read      bool
	ReadAt    *time.Time
	CreatedAt time.Time
}
```

### type Preferences

```go
type Preferences struct {
	UserID       uuid.UUID
	InApp        bool
	Push         bool
	Email        bool
	SMS          bool
	EmailAddress *string
	Phone        *string
	UpdatedAt    time.Time
}
```

### type Publisher

```go
type Publisher struct {
	redis  *redis.Client
	prefix string
}
```

### type Repository

```go
type Repository struct {
	db *pgxpool.Pool
}
```

### type Service

```go
type Service struct {
	repo *repository.Repository
	live Publisher
}
```

### type Template

```go
type Template struct {
	ID        uuid.UUID
	EventType string
	Channel   string
	Subject   string
	Body      string
	Active    bool
	CreatedAt time.Time
	UpdatedAt time.Time
}
```
