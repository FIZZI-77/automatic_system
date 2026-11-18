# Сервис SLA (SLA Service)

## Общее описание и общий принцип работы

`SLA_Service` рассчитывает сроки реакции и решения для заявок. Он принимает
события `tickets.events.v1`, выбирает наиболее подходящее активное правило,
хранит текущее состояние срока и историю переходов, а события публикует через
транзакционную таблицу исходящих сообщений.

Поля `department_id`, `category_id` и `priority` в правиле необязательны и
играют роль шаблонов. Репозиторий выбирает наиболее конкретное совпадение.
Проверка сроков рассчитана на параллельные экземпляры и использует
`FOR UPDATE SKIP LOCKED`.

## Модели

### Перечисления

| Тип | Значения | Назначение |
|---|---|---|
| `Priority` | `LOW`, `MEDIUM`, `HIGH`, `EMERGENCY` | Приоритет заявки. |
| `Status` | `ACTIVE`, `COMPLETED`, `CANCELLED` | Состояние контроля срока заявки. |
| `EventType` | `CREATED`, `RESPONSE_RECORDED`, `RESPONSE_WARNING`, `RESPONSE_BREACHED`, `RESOLUTION_WARNING`, `RESOLUTION_BREACHED`, `RECALCULATED`, `COMPLETED`, `CANCELLED` | Вид записи истории и исходящего события. |

### `Rule`

| Поле | Тип Go | Назначение |
|---|---|---|
| `ID` | `uuid.UUID` | Идентификатор правила. |
| `Name` | `string` | Название правила. |
| `DepartmentID` | `*uuid.UUID` | Необязательное подразделение. |
| `CategoryID` | `*uuid.UUID` | Необязательная категория. |
| `Priority` | `*Priority` | Необязательный приоритет. |
| `ResponseTime` | `time.Duration` | Допустимое время до реакции. |
| `ResolutionTime` | `time.Duration` | Допустимое время до решения. |
| `WarningPercent` | `int32` | Процент срока, после которого отправляется предупреждение. |
| `Active` | `bool` | Участвует ли правило в подборе. |
| `CreatedAt` | `time.Time` | Время создания. |
| `UpdatedAt` | `time.Time` | Время изменения. |

### Остальные структуры

| Структура | Поля и назначение |
|---|---|
| `TicketSLA` | `ID` — запись; `TicketID` — заявка; `RuleID` — примененное правило; `DepartmentID`, `CategoryID`, `Priority` — снимок признаков; `Status` — состояние; `ResponseDeadline`, `ResolutionDeadline` — предельные времена; `RespondedAt`, `CompletedAt` — фактические времена; `ResponseBreached`, `ResolutionBreached` — нарушения; `ResponseWarningSent`, `ResolutionWarningSent` — уже отправленные предупреждения; `Version` — версия записи; `CreatedAt`, `UpdatedAt` — времена. |
| `History` | `ID` — запись истории; `TicketSLAID` — состояние срока; `TicketID` — заявка; `EventType` — переход; `OccurredAt` — время; `Details` — пояснение. |
| `TicketEvent` | `EventID` — событие; `EventType` — его вид; `TicketID`, `DepartmentID`, `CategoryID` — идентификаторы; `Priority` — приоритет; `Status` — состояние заявки; `CreatedAt`, `UpdatedAt` — времена заявки. |
| `RuleFilter` | `DepartmentID`, `CategoryID`, `Priority`, `Active` — необязательные условия; `Limit`, `Offset` — страница. |
| `SLAFilter` | `DepartmentID`, `Status`, `Breached` — необязательные условия; `Limit`, `Offset` — страница. |

`Priority.Valid` проверяет принадлежность одному из четырех значений.
`Rule.Validate` требует непустое имя, положительные сроки, время реакции не
больше времени решения, процент предупреждения от 1 до 99 и корректный
необязательный приоритет.

## Функции

Имя функции открывает её реализацию в ветке `test`; структуры параметров и результатов описаны в конце README.

### func [New](https://github.com/FIZZI-77/automatic_system/blob/test/SLA_Service/src/core/service/service.go#L14)

```go
func New(r *repository.Repository) *Service
```

Типы: [Repository](#type-repository), [Service](#type-service).

Создает `Service` с общим репозиторием. Обращений к базе не выполняет.

### func (*Service) [CreateRule](https://github.com/FIZZI-77/automatic_system/blob/test/SLA_Service/src/core/service/service.go#L15)

```go
func (s *Service) CreateRule(c context.Context, v *models.Rule) (*models.Rule, error)
```

Типы: [Rule](#type-rule), [Service](#type-service).

Структуры: [Rule](#type-rule).

Проверяет правило через `Validate` и передает его в
`repo.CreateRule`. Ошибка проверки предотвращает запись.

### func (*Service) [GetRule](https://github.com/FIZZI-77/automatic_system/blob/test/SLA_Service/src/core/service/service.go#L21)

```go
func (s *Service) GetRule(c context.Context, id uuid.UUID) (*models.Rule, error)
```

Типы: [Rule](#type-rule), [Service](#type-service).

Структуры: [Rule](#type-rule).

Возвращает правило по UUID напрямую из репозитория.

### func (*Service) [UpdateRule](https://github.com/FIZZI-77/automatic_system/blob/test/SLA_Service/src/core/service/service.go#L24)

```go
func (s *Service) UpdateRule(c context.Context, v *models.Rule) (*models.Rule, error)
```

Типы: [Rule](#type-rule), [Service](#type-service).

Структуры: [Rule](#type-rule).

Повторно проверяет все значения правила и только после этого вызывает
`repo.UpdateRule`.

### func (*Service) [DeleteRule](https://github.com/FIZZI-77/automatic_system/blob/test/SLA_Service/src/core/service/service.go#L30)

```go
func (s *Service) DeleteRule(c context.Context, id uuid.UUID) (*models.Rule, error)
```

Типы: [Rule](#type-rule), [Service](#type-service).

Структуры: [Rule](#type-rule).

Передает UUID в репозиторий. Фактический способ удаления определяется
репозиторием; прикладной слой возвращает полученное правило или ошибку.

### func (*Service) [ListRules](https://github.com/FIZZI-77/automatic_system/blob/test/SLA_Service/src/core/service/service.go#L33)

```go
func (s *Service) ListRules(c context.Context, f models.RuleFilter) ([]*models.Rule, int64, error)
```

Типы: [Rule](#type-rule), [RuleFilter](#type-rulefilter), [Service](#type-service).

Структуры: [RuleFilter](#type-rulefilter), [Rule](#type-rule).

Передает `RuleFilter` в репозиторий и возвращает страницу правил вместе с
общим количеством.

### func (*Service) [GetTicketSLA](https://github.com/FIZZI-77/automatic_system/blob/test/SLA_Service/src/core/service/service.go#L36)

```go
func (s *Service) GetTicketSLA(c context.Context, id uuid.UUID) (*models.TicketSLA, error)
```

Типы: [Service](#type-service), [TicketSLA](#type-ticketsla).

Структуры: [TicketSLA](#type-ticketsla).

Загружает текущее состояние сроков одной заявки.

### func (*Service) [ListSLAs](https://github.com/FIZZI-77/automatic_system/blob/test/SLA_Service/src/core/service/service.go#L39)

```go
func (s *Service) ListSLAs(c context.Context, f models.SLAFilter) ([]*models.TicketSLA, int64, error)
```

Типы: [SLAFilter](#type-slafilter), [Service](#type-service), [TicketSLA](#type-ticketsla).

Структуры: [SLAFilter](#type-slafilter), [TicketSLA](#type-ticketsla).

Возвращает страницу состояний по `SLAFilter` и общий счетчик.

### func (*Service) [ListHistory](https://github.com/FIZZI-77/automatic_system/blob/test/SLA_Service/src/core/service/service.go#L42)

```go
func (s *Service) ListHistory(c context.Context, id uuid.UUID, l, o int32) ([]*models.History, int64, error)
```

Типы: [History](#type-history), [Service](#type-service).

Структуры: [History](#type-history).

Принимает UUID заявки либо состояния, `l` и `o` для страницы и возвращает
историю с общим количеством без дополнительной обработки.

### func (*Service) [Consume](https://github.com/FIZZI-77/automatic_system/blob/test/SLA_Service/src/core/service/service.go#L45)

```go
func (s *Service) Consume(c context.Context, e models.TicketEvent) error
```

Типы: [Service](#type-service), [TicketEvent](#type-ticketevent).

Структуры: [TicketEvent](#type-ticketevent).

1. Требует непустой `EventID` и ненулевой `TicketID`.
2. Для `ticket.created` и `ticket.updated` подбирает правило по
   подразделению, категории и приоритету.
3. Для остальных событий правило не загружает.
4. Передает событие и найденное либо пустое правило в `repo.ApplyEvent`,
   который атомарно ведет входящие события, состояние, историю и исходящие
   сообщения.

### func (*Service) [CheckDeadlines](https://github.com/FIZZI-77/automatic_system/blob/test/SLA_Service/src/core/service/service.go#L59)

```go
func (s *Service) CheckDeadlines(c context.Context, now time.Time) error
```

Типы: [Service](#type-service).

Передает контрольное время в `repo.CheckDeadlines`. Репозиторий находит
активные сроки, создает предупреждения и нарушения, не обрабатывая одну запись
одновременно несколькими экземплярами.

## Структура БД

### `sla_rules` — правила сроков

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `uuid` | Первичный ключ. |
| `name` | `text` | Название. |
| `department_id` | `uuid` | Необязательное подразделение. |
| `category_id` | `uuid` | Необязательная категория. |
| `priority` | `text` | Необязательный приоритет из четырех значений. |
| `response_seconds` | `bigint` | Положительный срок реакции. |
| `resolution_seconds` | `bigint` | Срок решения не меньше срока реакции. |
| `warning_percent` | `integer` | Процент предупреждения от 1 до 99, по умолчанию 80. |
| `active` | `boolean` | Активность правила. |
| `created_at`, `updated_at` | `timestamptz` | Времена создания и изменения. |

Частичный уникальный индекс запрещает два активных правила одной области с
учетом пустых значений как шаблонов. Миграция добавляет по умолчанию правило
для каждого приоритета.

### `ticket_slas` — текущее состояние сроков

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `uuid` | Первичный ключ. |
| `ticket_id` | `uuid` | Уникальная заявка. |
| `rule_id` | `uuid` | Внешний ключ на `sla_rules`. |
| `department_id`, `category_id` | `uuid` | Подразделение и категория. |
| `priority` | `text` | Приоритет. |
| `status` | `text` | `ACTIVE`, `COMPLETED` или `CANCELLED`. |
| `response_deadline`, `resolution_deadline` | `timestamptz` | Предельные времена. |
| `responded_at`, `completed_at` | `timestamptz` | Фактические времена. |
| `response_breached`, `resolution_breached` | `boolean` | Признаки нарушений. |
| `response_warning_sent`, `resolution_warning_sent` | `boolean` | Признаки отправленных предупреждений. |
| `version` | `integer` | Версия состояния, по умолчанию 1. |
| `created_at`, `updated_at` | `timestamptz` | Времена записи. |

### `sla_history` — история

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `uuid` | Первичный ключ. |
| `ticket_sla_id` | `uuid` | Внешний ключ на `ticket_slas`. |
| `ticket_id` | `uuid` | Заявка. |
| `event_type` | `text` | Вид перехода. |
| `details` | `text` | Пояснение, по умолчанию пустая строка. |
| `occurred_at` | `timestamptz` | Время события. |

### `ticket_event_inbox` — принятые события

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `event_id` | `text` | Первичный ключ для устранения повторов. |
| `event_type` | `text` | Вид события. |
| `ticket_id` | `uuid` | Заявка. |
| `payload` | `jsonb` | Исходное содержимое. |
| `processed_at` | `timestamptz` | Время обработки. |

### `outbox_events` — исходящие события

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `uuid` | Первичный ключ. |
| `aggregate_type` | `text` | Вид сущности. |
| `aggregate_id` | `uuid` | Идентификатор сущности. |
| `event_type` | `text` | Вид события. |
| `payload` | `jsonb` | Содержимое. |
| `status` | `text` | Состояние публикации. |
| `attempts` | `integer` | Число попыток. |
| `next_attempt_at` | `timestamptz` | Следующая попытка. |
| `locked_at` | `timestamptz` | Время захвата. |
| `last_error` | `text` | Последняя ошибка. |
| `sent_at` | `timestamptz` | Время публикации. |
| `created_at` | `timestamptz` | Время создания. |

## Структуры параметров и результатов

### type History

```go
type History struct {
	ID          uuid.UUID
	TicketSLAID uuid.UUID
	TicketID    uuid.UUID
	EventType   EventType
	OccurredAt  time.Time
	Details     string
}
```

### type Repository

```go
type Repository struct {
	db *pgxpool.Pool
}
```

### type Rule

```go
type Rule struct {
	ID             uuid.UUID
	Name           string
	DepartmentID   *uuid.UUID
	CategoryID     *uuid.UUID
	Priority       *Priority
	ResponseTime   time.Duration
	ResolutionTime time.Duration
	WarningPercent int32
	Active         bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
```

### type RuleFilter

```go
type RuleFilter struct {
	DepartmentID *uuid.UUID
	CategoryID   *uuid.UUID
	Priority     *Priority
	Active       *bool
	Limit        int32
	Offset       int32
}
```

### type SLAFilter

```go
type SLAFilter struct {
	DepartmentID *uuid.UUID
	Status       *Status
	Breached     *bool
	Limit        int32
	Offset       int32
}
```

### type Service

```go
type Service struct{ repo *repository.Repository }
```

### type TicketEvent

```go
type TicketEvent struct {
	EventID      string
	EventType    string
	TicketID     uuid.UUID
	DepartmentID uuid.UUID
	CategoryID   uuid.UUID
	Priority     Priority
	Status       string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
```

### type TicketSLA

```go
type TicketSLA struct {
	ID                    uuid.UUID
	TicketID              uuid.UUID
	RuleID                uuid.UUID
	DepartmentID          uuid.UUID
	CategoryID            uuid.UUID
	Priority              Priority
	Status                Status
	TicketCreatedAt       time.Time
	ResponseDeadline      time.Time
	ResolutionDeadline    time.Time
	RespondedAt           *time.Time
	CompletedAt           *time.Time
	ResponseBreached      bool
	ResolutionBreached    bool
	ResponseWarningSent   bool
	ResolutionWarningSent bool
	Version               int32
	CreatedAt             time.Time
	UpdatedAt             time.Time
}
```
