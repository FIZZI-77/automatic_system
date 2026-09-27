# Сервис SLA (SLA Service)

## Ответственность

Расчёт response/resolution deadlines, warnings, breaches и SLA history.

## Ключевое поведение

- Принимает ticket events.
- Rule может wildcard-ить department/category/priority; repository выбирает наиболее specific active match.
- Parallel deadline scanning использует `FOR UPDATE SKIP LOCKED`.
- Хранит текущее SLA state и transition history.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL. |
| Синхронные взаимодействия | Основной вход — Kafka event processing. |
| Kafka | Consumer: `tickets.events.v1`; publisher: `sla.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Полные сигнатуры и структуры параметров приведены в [справочнике функций SLA Service](https://automaticsystem.youtrack.cloud/articles/ACS-A-37/Kod-i-funkcii-SLA-Service).

### `New`

```go
func New(r *repository.Repository) *Service
```

Создает `Service` с общим репозиторием. Обращений к базе не выполняет.

### `CreateRule`

```go
func (s *Service) CreateRule(c context.Context, v *models.Rule) (*models.Rule, error)
```

Проверяет правило через `Validate` и передает его в
`repo.CreateRule`. Ошибка проверки предотвращает запись.

### `GetRule`

```go
func (s *Service) GetRule(c context.Context, id uuid.UUID) (*models.Rule, error)
```

Возвращает правило по UUID напрямую из репозитория.

### `UpdateRule`

```go
func (s *Service) UpdateRule(c context.Context, v *models.Rule) (*models.Rule, error)
```

Повторно проверяет все значения правила и только после этого вызывает
`repo.UpdateRule`.

### `DeleteRule`

```go
func (s *Service) DeleteRule(c context.Context, id uuid.UUID) (*models.Rule, error)
```

Передает UUID в репозиторий. Фактический способ удаления определяется
репозиторием; прикладной слой возвращает полученное правило или ошибку.

### `ListRules`

```go
func (s *Service) ListRules(c context.Context, f models.RuleFilter) ([]*models.Rule, int64, error)
```

Передает `RuleFilter` в репозиторий и возвращает страницу правил вместе с
общим количеством.

### `GetTicketSLA`

```go
func (s *Service) GetTicketSLA(c context.Context, id uuid.UUID) (*models.TicketSLA, error)
```

Загружает текущее состояние сроков одной заявки.

### `ListSLAs`

```go
func (s *Service) ListSLAs(c context.Context, f models.SLAFilter) ([]*models.TicketSLA, int64, error)
```

Возвращает страницу состояний по `SLAFilter` и общий счетчик.

### `ListHistory`

```go
func (s *Service) ListHistory(c context.Context, id uuid.UUID, l, o int32) ([]*models.History, int64, error)
```

Принимает UUID заявки либо состояния, `l` и `o` для страницы и возвращает
историю с общим количеством без дополнительной обработки.

### `Consume`

```go
func (s *Service) Consume(c context.Context, e models.TicketEvent) error
```

1. Требует непустой `EventID` и ненулевой `TicketID`.
2. Для `ticket.created` и `ticket.updated` подбирает правило по
   подразделению, категории и приоритету.
3. Для остальных событий правило не загружает.
4. Передает событие и найденное либо пустое правило в `repo.ApplyEvent`,
   который атомарно ведет входящие события, состояние, историю и исходящие
   сообщения.

### `CheckDeadlines`

```go
func (s *Service) CheckDeadlines(c context.Context, now time.Time) error
```

Передает контрольное время в `repo.CheckDeadlines`. Репозиторий находит
активные сроки, создает предупреждения и нарушения, не обрабатывая одну запись
одновременно несколькими экземплярами.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/SLA_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/SLA_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
