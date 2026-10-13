# Сервис заявок (Ticket Service)

## Ответственность

Источник истины по обращениям жителей, городским инцидентам, связям обращение–инцидент, категориям, истории статусов, назначениям бригад, отчетам о работах и учетным данным внешних интеграций.

## Ключевое поведение

- Основной lifecycle: `NEW → ASSIGNED → IN_PROGRESS → DONE`; cancel разрешён из NEW/ASSIGNED/IN_PROGRESS.
- `DONE` и `CANCELED` — terminal application states.
- Access зависит от роли и ownership; worker работает с ticket своей brigade.
- Write operations поддерживают idempotency.
- Completion report request сохраняется вместе с outbox event; результат возвращается асинхронно.
- Запись `tickets` имеет тип `INCIDENT` или `REQUEST`. Работы, статусы и назначения относятся к городскому инциденту, а обращение жителя хранит связь `incident_id`.
- При создании обращения сервис в одной транзакции ищет активный инцидент той же категории и департамента, созданный за последние 24 часа не дальше 100 метров. Выбирается ближайший, затем наиболее новый инцидент; при отсутствии совпадения создается новый.
- Диспетчер своего департамента или администратор может вручную присоединить обращение к другому инциденту либо отсоединить его. Причина изменения обязательна и попадает в outbox event.
- Внешние системы регистрируются администратором. Секрет с префиксом `tki_` возвращается только при регистрации, а в БД хранится SHA-256; опционально интеграция ограничивается одним департаментом.
- Повторный внешний запрос с той же комбинацией `external_system_id`, `external_id` и департамента возвращает ранее созданное обращение и не создает дубль.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL; Citus topology определяется deployment, а не business code. |
| Синхронные взаимодействия | В текущем `main.go` нет прямых gRPC clients Department/Brigade. |
| Kafka | Publisher: `tickets.events.v1`; consumers: `routing.events.v1`, `reports.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Полные сигнатуры и структуры параметров приведены в [справочнике функций Ticket Service](https://automaticsystem.youtrack.cloud/articles/ACS-A-34/Kod-i-funkcii-Ticket-Service).

Все gRPC-методы, включая обращения и интеграции, реализованы общим `TicketHandler` в `src/core/handler/handler.go`; отдельный handler для них не создается.

### `NewService`

```go
func NewService(repo *repository.Repository, logger *zap.Logger) *Service
```

При отсутствии журнала подставляет `zap.NewNop()`, создает службы заявок, категорий, отчетов и интеграций с общим хранилищем. Возвращает единый `Service`.

### `NewTicketServiceStruct`, `NewCategoryServiceStruct`, `NewReportService`

```go
func NewTicketServiceStruct(repo *repository.Repository, logger *zap.Logger) *TicketServiceStruct
```

```go
func NewCategoryServiceStruct(repo *repository.Repository, logger *zap.Logger) *CategoryServiceStruct
```

```go
func NewReportService(repo *repository.Repository) *ReportService
```

Создают соответствующую службу и сохраняют необходимые зависимости. `NewReportService` отдельно получает интерфейс заявок и создает хранилище отчетов поверх общего `Repository`.

### `TicketServiceStruct.CreateTicket`

```go
func (s *TicketServiceStruct) CreateTicket(ctx context.Context, in *models.CreateTicketInput) (*models.CreateTicketResult, error)
```

1. Проверяет обязательные UUID, заголовок до 255 символов, описание до 3000, приоритет, адрес до 500 и координаты.
2. Для непривилегированного исполнителя требует, чтобы `ActorUserID` совпадал с `UserID` создаваемой заявки.
3. Выполняет создание через защиту идемпотентности.
4. Хранилище проверяет активность категории, создает заявку `NEW`, первую запись истории и событие `ticket.created` в одной транзакции.
5. Возвращает созданную заявку или ранее сохраненный ответ для повторного ключа.

### `TicketServiceStruct.GetTicket`

```go
func (s *TicketServiceStruct) GetTicket(ctx context.Context, in *models.GetTicketInput) (*models.GetTicketResult, error)
```

Проверяет UUID, загружает заявку и вызывает `canReadTicket`. Доступ получает владелец, привилегированная роль или работник назначенной бригады.

### `TicketServiceStruct.ListTickets`

```go
func (s *TicketServiceStruct) ListTickets(ctx context.Context, in *models.ListTicketsInput) (*models.ListTicketsResult, error)
```

До проверки фильтра ограничивает область видимости: работнику принудительно оставляет только его бригаду, обычному пользователю — только его `UserID`; привилегированные роли сохраняют переданные фильтры. Затем подставляет сортировку `created_at desc`, нормализует страницу до диапазона 1–100 записей и запрашивает список с общим количеством.

### `TicketServiceStruct.UpdateTicket`

```go
func (s *TicketServiceStruct) UpdateTicket(ctx context.Context, in *models.UpdateTicketInput) (*models.UpdateTicketResult, error)
```

Проверяет UUID, переданные текстовые поля, перечисления, парность координат и обязательный `UpdatedBy`. Затем выполняет частичное обновление через идемпотентную транзакцию и возвращает актуальную заявку. Проверка допустимости конкретного изменения и запись события находятся в хранилище.

### `TicketServiceStruct.ChangeTicketStatus`

```go
func (s *TicketServiceStruct) ChangeTicketStatus(ctx context.Context, in *models.ChangeTicketStatusInput) (*models.ChangeTicketStatusResult, error)
```

Проверяет запрос. Непривилегированный исполнитель должен быть `worker`, может выбрать только `IN_PROGRESS` и обязан принадлежать назначенной бригаде. Операция выполняется идемпотентно; хранилище блокирует запись, проверяет переход, добавляет историю и событие.

### `TicketServiceStruct.AssignBrigade`

```go
func (s *TicketServiceStruct) AssignBrigade(ctx context.Context, in *models.AssignBrigadeInput) (*models.AssignBrigadeResult, error)
```

Разрешена только `admin` или `dispatcher`. Проверяет UUID и комментарий, затем идемпотентно назначает бригаду. Хранилище использует транзакционную блокировку по бригаде и не допускает одновременно две заявки `ASSIGNED`/`IN_PROGRESS` для одной бригады; состояние заявки становится `ASSIGNED`.

### `TicketServiceStruct.CancelTicket`

```go
func (s *TicketServiceStruct) CancelTicket(ctx context.Context, in *models.CancelTicketInput) (*models.CancelTicketResult, error)
```

Загружает заявку после проверки входа. Непривилегированный пользователь может отменить только собственную заявку. В транзакции проверяется допустимость перехода, устанавливается `CANCELED`, сохраняются время, причина в истории и событие `ticket.canceled`.

### `TicketServiceStruct.CompleteTicket`

```go
func (s *TicketServiceStruct) CompleteTicket(ctx context.Context, in *models.CompleteTicketInput) (*models.CompleteTicketResult, error)
```

Привилегированная роль может завершить заявку напрямую. Иначе исполнитель должен иметь роль `worker` и принадлежать назначенной бригаде. Идемпотентная операция переводит заявку из `IN_PROGRESS` в `DONE`, устанавливает время, добавляет историю и событие `ticket.completed`.

### `TicketServiceStruct.GetTicketStatusHistory`

```go
func (s *TicketServiceStruct) GetTicketStatusHistory(ctx context.Context, in *models.GetTicketStatusHistoryInput) (*models.GetTicketStatusHistoryResult, error)
```

Проверяет заявку и параметры страницы, загружает заявку для проверки доступа, затем возвращает историю в прямом хронологическом порядке и полное количество записей.

### `TicketServiceStruct.CreateRequest`

```go
func (s *TicketServiceStruct) CreateRequest(ctx context.Context, in *models.CreateRequestInput) (*models.CreateRequestResult, error)
```

Проверяет данные обращения и передает создание в транзакционное хранилище. Хранилище сериализует поиск дублей advisory lock по департаменту и категории, проверяет активность категории и ищет ближайший активный `INCIDENT` в радиусе 100 метров за последние 24 часа. Если совпадения нет, сначала создает `INCIDENT`; затем всегда создает отдельный `REQUEST`, записывает `incident_id`, историю и outbox events. Ответ содержит `request`, `incident` и признак `duplicate_matched`.

### `TicketServiceStruct.AttachRequest`

```go
func (s *TicketServiceStruct) AttachRequest(ctx context.Context, in *models.AttachRequestInput) (*models.Ticket, error)
```

Разрешает администратору либо диспетчеру департамента инцидента перенести `REQUEST` в указанный `INCIDENT`. Оба объекта должны принадлежать одному департаменту; повторное присоединение к тому же инциденту отклоняется. Обязательная причина и исполнитель записываются в событие `ticket.request_attached`.

### `TicketServiceStruct.DetachRequest`

```go
func (s *TicketServiceStruct) DetachRequest(ctx context.Context, in *models.DetachRequestInput) (*models.Ticket, error)
```

Разрешает администратору либо диспетчеру соответствующего департамента очистить `incident_id` у `REQUEST`. Обязательная причина и исполнитель записываются в событие `ticket.request_detached`.

### `TicketServiceStruct.ListIncidentRequests`

```go
func (s *TicketServiceStruct) ListIncidentRequests(ctx context.Context, in *models.ListIncidentRequestsInput) ([]*models.Ticket, int64, error)
```

Проверяет право управления инцидентом, нормализует страницу и возвращает связанные обращения и общее количество. Администратор видит любой департамент; диспетчер — только свой.

### `IntegrationServiceStruct.RegisterIntegration`

```go
func (s *IntegrationServiceStruct) RegisterIntegration(ctx context.Context, in *models.RegisterIntegrationInput) (*models.RegisterIntegrationResult, error)
```

Доступен только роли `admin`. Генерирует криптографически случайный 32-байтовый секрет с префиксом `tki_`, сохраняет только SHA-256 и отображаемый префикс секрета. Полный секрет возвращается один раз. `AllowedDepartmentID` ограничивает интеграцию одним департаментом.

### `IntegrationServiceStruct.CreateExternalRequest`

```go
func (s *IntegrationServiceStruct) CreateExternalRequest(ctx context.Context, in *models.CreateExternalRequestInput) (*models.CreateRequestResult, error)
```

Проверяет `client_id` и секрет сравнением хешей в constant time, активность интеграции и разрешенный департамент. Затем добавляет `external_system_id` и `external_id` и вызывает общий путь `CreateRequest`. Внешняя идемпотентность обеспечивается уникальной комбинацией интеграции, внешнего идентификатора и департамента; после успешного вызова обновляется `last_used_at`.

### `hasRole`, `hasPrivilegedRole`, `canReadTicket`

```go
func hasRole(roles []string, expected string) bool
```

```go
func hasPrivilegedRole(roles []string) bool
```

```go
func canReadTicket(ticket *models.Ticket, actorUserID, actorBrigadeID *uuid.UUID, actorRoles []string) bool
```

`hasRole` ищет точное значение роли. `hasPrivilegedRole` распознает `admin` и `dispatcher`. `canReadTicket` разрешает чтение привилегированным ролям, владельцу заявки и работнику той бригады, которая назначена на заявку.

### `CategoryServiceStruct.CreateCategory`

```go
func (s *CategoryServiceStruct) CreateCategory(ctx context.Context, in *models.CreateCategoryInput) (*models.CreateCategoryResult, error)
```

Проверяет код, название и описание, требует привилегированную роль и идемпотентно создает категорию. Код содержит только строчные латинские буквы, цифры, `_` или `-`.

### `CategoryServiceStruct.GetCategory`

```go
func (s *CategoryServiceStruct) GetCategory(ctx context.Context, in *models.GetCategoryInput) (*models.GetCategoryResult, error)
```

Проверяет `CategoryID`, загружает категорию и возвращает ее. Дополнительного ограничения по роли нет.

### `CategoryServiceStruct.ListCategories`

```go
func (s *CategoryServiceStruct) ListCategories(ctx context.Context, in *models.ListCategoriesInput) (*models.ListCategoriesResult, error)
```

Нормализует страницу, при необходимости оставляет только активные категории и возвращает список с общим количеством.

### `CategoryServiceStruct.UpdateCategory`

```go
func (s *CategoryServiceStruct) UpdateCategory(ctx context.Context, in *models.UpdateCategoryInput) (*models.UpdateCategoryResult, error)
```

Требует хотя бы одно из полей `Name`, `Description`, `IsActive`, проверяет значения и привилегированную роль. Изменение выполняется идемпотентно.

### `CategoryServiceStruct.DeleteCategory`

```go
func (s *CategoryServiceStruct) DeleteCategory(ctx context.Context, in *models.DeleteCategoryInput) (*models.DeleteCategoryResult, error)
```

Проверяет UUID и привилегированную роль, затем идемпотентно вызывает удаление. Хранилище возвращает удаленную категорию или ошибку, если операция невозможна.

### `ReportService.Create`

```go
func (s *ReportService) Create(ctx context.Context, in *models.CreateWorkReportInput) (*models.WorkReport, error)
```

1. Убирает пробелы по краям описания, проверяет длину, UUID и до 20 уникальных файлов.
2. Загружает заявку и разрешает отчет только для `ASSIGNED` или `IN_PROGRESS`.
3. Непривилегированный автор должен быть работником назначенной бригады.
4. Хранилище создает отчет и связи с файлами в одной транзакции.
5. Обычный отчет создает событие `ticket.report.created`.
6. При наличии `Completion` отчет получает состояние `PENDING`, срок десять минут и событие `ticket.completion_report.requested.v1` со снимком заявки и бригады.

### `ReportService.List`

```go
func (s *ReportService) List(ctx context.Context, ticketID, actor uuid.UUID, actorBrigadeID *uuid.UUID, roles []string) ([]*models.WorkReport, error)
```

Загружает заявку, проверяет доступ через `canReadTicket` и возвращает отчеты в порядке от новых к старым вместе с идентификаторами файлов.

### `withIdempotency`

```go
func withIdempotency(repo *repository.Repository, ctx context.Context, operation string, actorKey string, request any, fn func(context.Context) (any, uuid.UUID, error)) (any, error)
```

```go
func (s *TicketServiceStruct) withIdempotency(ctx context.Context, operation string, actorKey string, request any, fn func(context.Context) (any, uuid.UUID, error)) (any, error)
```

```go
func (s *CategoryServiceStruct) withIdempotency(ctx context.Context, operation string, actorKey string, request any, fn func(context.Context) (any, uuid.UUID, error)) (any, error)
```

Если ключа в контексте нет, немедленно выполняет функцию. Иначе сериализует запрос, вычисляет SHA-256 и пытается получить запись на 24 часа. Новый ключ выполняет функцию в транзакции. Для существующего ключа проверяет совпадение хеша и в зависимости от состояния возвращает сохраненный ответ, `ErrIdempotencyInProgress` или `ErrIdempotencyFailed`.

### `TicketServiceStruct.withIdempotency`, `CategoryServiceStruct.withIdempotency`

Передают общее хранилище и параметры в `withIdempotency`.

### `cachedResult`

```go
func cachedResult[T any](result any) (*T, error)
```

Возвращает указатель непосредственно, если тип уже совпадает. Сохраненный ответ вида `map[string]any` преобразует в требуемый тип через JSON.

### `hashRequest`

```go
func hashRequest(request any) (string, error)
```

Сериализует запрос в JSON и возвращает шестнадцатеричную строку SHA-256. Ошибка сериализации оборачивается контекстом операции.

### `idempotencyActor`

```go
func idempotencyActor(actor *uuid.UUID, fallback uuid.UUID) string
```

Возвращает переданный идентификатор исполнителя, затем запасной UUID, а при отсутствии обоих — пустую строку.

### Проверки входных данных

`validateUUID` запрещает нулевой UUID; `validateOptionalUUID` проверяет только заданное значение; `validateText` требует непустой текст с ограничением длины; `validateOptionalText` делает то же для указателя; `validateCoordinates` проверяет широту и долготу; `normalizeLimitOffset` подставляет `20`, ограничивает размер `100` и исправляет отрицательное смещение на ноль; `isValidCode` посимвольно проверяет код категории. Методы `Validate` входных моделей объединяют эти правила и нормализуют сортировку и страницу там, где это требуется.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Ticket_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Ticket_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
