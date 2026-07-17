# Ticket Service — developer documentation

Ticket Service владеет заявками жителей/пользователей, категориями заявок, назначением бригад и историей статусов. Он не владеет пользователями, департаментами или бригадами, а хранит их UUID как логические ссылки.

## Слои сервиса

- `models` — `Ticket`, `TicketCategory`, status/priority enums, input/result DTO.
- `src/core/handler` — gRPC handler.
- `src/core/service` — бизнес-логика заявок и категорий.
- `src/core/repository` — PostgreSQL queries, transactional updates, outbox.
- `scheme` — migrations.

## Основные структуры

- `Ticket`
  - `DepartmentID` — департамент заявки.
  - `CategoryID` — категория.
  - `UserID` — пользователь, создавший заявку.
  - `BrigadeID` — назначенная бригада, nullable.
  - `Title`, `Description`.
  - `Status` — `NEW`, `ASSIGNED`, `IN_PROGRESS`, `DONE`, `CANCELED`.
  - `Priority` — `LOW`, `MEDIUM`, `HIGH`, `EMERGENCY`.
  - `Address`, `Latitude`, `Longitude`.
  - timestamps: created/updated/assigned/completed/canceled.
- `TicketCategory`
  - справочник категорий заявок: `code`, `name`, `description`, `is_active`.
- `TicketStatusHistory`
  - история изменения статусов: old/new status, actor, comment, created_at.

## Ticket service methods

### `CreateTicket(ctx, *CreateTicketInput) -> CreateTicketResult`

Принимает department/category/user, title/description/priority/address/coordinates, actor context.

Логика:

1. Валидирует input.
2. Проверяет права actor.
3. Проверяет категорию, если такая проверка заведена в service/repository.
4. Создает ticket со статусом `NEW`.
5. Пишет status history и outbox event.
6. Возвращает created `Ticket`.

### `GetTicket(ctx, *GetTicketInput) -> GetTicketResult`

Принимает `ticket_id`, actor context.

Логика: читает ticket и проверяет, что actor имеет доступ к заявке. Пользователь видит свои заявки; staff/admin/dispatcher видят по правилам сервиса.

### `ListTickets(ctx, *ListTicketsInput) -> ListTicketsResult`

Фильтры:

- `department_id`
- `user_id`
- `brigade_id`
- `category_id`
- `status`
- `priority`
- `created_from`, `created_to`
- sort/pagination

Логика: нормализует фильтры и возвращает список + total. Service должен ограничивать область видимости actor, чтобы клиент не мог получить чужие заявки через фильтр.

### `UpdateTicket(ctx, *UpdateTicketInput) -> UpdateTicketResult`

Изменяет контентные поля заявки: title, description, category, priority, address, coordinates.

Логика: проверяет статус заявки; завершенные/отмененные заявки обычно нельзя редактировать. Возвращает updated ticket и публикует event.

### `ChangeTicketStatus(ctx, *ChangeTicketStatusInput) -> ChangeTicketStatusResult`

Принимает `ticket_id`, `new_status`, `changed_by`, optional comment.

Логика:

1. Валидирует переход статуса.
2. Обновляет ticket.
3. Пишет `TicketStatusHistory`.
4. Обновляет timestamps (`completed_at`, `canceled_at` и т.п.).
5. Публикует outbox event.

### `AssignBrigade(ctx, *AssignBrigadeInput) -> AssignBrigadeResult`

Принимает `ticket_id`, `brigade_id`, `assigned_by`, comment.

Логика: назначает бригаду, переводит ticket в `ASSIGNED`, пишет историю и outbox. Проверка способности бригады выполнить заявку должна идти через Brigade Service/API flow, а не через локальные FK.

### `CancelTicket(ctx, *CancelTicketInput) -> CancelTicketResult`

Принимает `ticket_id`, `canceled_by`, reason.

Логика: валидирует, что заявку можно отменить, переводит в `CANCELED`, пишет reason в history/comment и заполняет `canceled_at`.

### `CompleteTicket(ctx, *CompleteTicketInput) -> CompleteTicketResult`

Принимает `ticket_id`, `completed_by`, comment.

Логика: переводит заявку в `DONE`, заполняет `completed_at`, пишет history и outbox.

### `GetTicketStatusHistory(ctx, *GetTicketStatusHistoryInput) -> GetTicketStatusHistoryResult`

Принимает `ticket_id`, limit/offset, actor context.

Логика: проверяет доступ к ticket и возвращает историю статусов.

## Category service methods

### `CreateCategory(ctx, *CreateCategoryInput) -> CreateCategoryResult`

Создает категорию. Обычно доступно admin/staff. `code` должен быть стабильным и уникальным.

### `GetCategory(ctx, *GetCategoryInput) -> GetCategoryResult`

Возвращает категорию по id.

### `ListCategories(ctx, *ListCategoriesInput) -> ListCategoriesResult`

Возвращает список категорий, optionally only active.

### `UpdateCategory(ctx, *UpdateCategoryInput) -> UpdateCategoryResult`

Patch update name/description/is_active.

### `DeleteCategory(ctx, *DeleteCategoryInput) -> DeleteCategoryResult`

Не должен ломать старые tickets. Предпочтительный подход — soft delete/deactivate.

## Repository interfaces

- `TicketRepository`
  - CRUD заявки.
  - status transitions.
  - assign/cancel/complete.
  - status history.
- `CategoryRepository`
  - CRUD категорий.

Repository должен отвечать за атомарность ticket update + status history + outbox.

## Handler layer

`TicketHandler` реализует gRPC методы заявок и категорий. Он должен:

1. Извлекать actor context из metadata.
2. Мапить protobuf request в `models.*Input`.
3. Вызывать service.
4. Мапить domain errors в gRPC status.
5. Не принимать бизнес-решения сам.

## Интеграции

- Auth/API Gateway передает actor user id и роли.
- Department ID приходит как логическая ссылка.
- Brigade assignment должен согласовываться с Brigade Service.
- Outbox events могут использоваться Dispatch/notifications/analytics.

## Правила разработки

- Не делать межсервисные FK на `user_id`, `department_id`, `brigade_id`.
- Все изменения статуса должны писать `TicketStatusHistory`.
- Закрытые заявки (`DONE`, `CANCELED`) нельзя случайно вернуть в рабочий flow без явного бизнес-правила.
