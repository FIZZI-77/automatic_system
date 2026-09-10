# Department Service — developer documentation

Department Service владеет справочником департаментов. Другие сервисы хранят `department_id` как логическую ссылку и проверяют существование/активность департамента через Department Service.

## Слои сервиса

- `models` — доменные структуры, enum статусов, sort options, input/result DTO.
- `src/core/handler` — gRPC слой.
- `src/core/service` — бизнес-правила и access checks.
- `src/core/repository` — PostgreSQL access через `pgxpool`.
- `scheme` — goose migrations.

## Основные структуры

- `Department`
  - `ID` — UUID департамента.
  - `Name` — уникальное/человекочитаемое имя.
  - `Description` — описание.
  - `Status` — `ACTIVE`, `INACTIVE`, `ARCHIVED`.
  - `CreatedAt`, `UpdatedAt`.
- `DepartmentStatus`
  - `ACTIVE` — департамент можно использовать в новых связях.
  - `INACTIVE` — временно выключен.
  - `ARCHIVED` — больше не используется.
- `DepartmentSortBy`
  - `created_at`, `updated_at`, `name`, `status`.

## Service methods

### `CreateDepartment(ctx, *CreateDepartmentInput) -> CreateDepartmentResult`

Принимает `name`, `description`, `actor_roles`.

Логика:

1. Валидирует input.
2. Проверяет, что actor имеет роль `admin`.
3. Создает department в БД.
4. Возвращает созданный `Department`.

### `GetDepartmentByID(ctx, *GetDepartmentByIDInput) -> GetDepartmentByIDResult`

Принимает `id`.

Логика: валидирует UUID, читает department из repository, возвращает `Department`. Используется также другими сервисами для проверки `department_id`.

### `ListDepartments(ctx, *ListDepartmentsInput) -> ListDepartmentsResult`

Принимает фильтры:

- `status`
- `created_from`
- `created_to`
- `sort_by`
- `sort_order`
- `limit`
- `offset`

Логика: нормализует pagination/sort, читает список и total count.

### `UpdateDepartment(ctx, *UpdateDepartmentInput) -> UpdateDepartmentResult`

Принимает `id`, optional `name`, `description`, `status`, `actor_roles`.

Логика:

1. Валидирует input.
2. Проверяет admin role.
3. Обновляет только переданные поля.
4. Возвращает updated `Department`.

### `DeleteDepartment(ctx, *DeleteDepartmentInput) -> DeleteDepartmentResult`

Принимает `id`, `actor_roles`.

Логика: проверяет admin role и переводит department в удаленное/архивное состояние согласно repository implementation. Физическое удаление нежелательно, если на department ссылаются другие сервисы.

## Repository methods

- `CreateDepartment` — insert department.
- `GetDepartmentByID` — select by UUID.
- `ListDepartments` — фильтрация, сортировка, pagination, total count.
- `UpdateDepartment` — patch update.
- `DeleteDepartment` — delete/archive operation.

Репозиторий использует `DBPools{Write, Read}`. Если read pool не передан, используется write pool.

## Handler methods

`DepartmentHandler` реализует:

- `CreateDepartment`
- `GetDepartmentByID`
- `ListDepartments`
- `UpdateDepartment`
- `DeleteDepartment`

Handler отвечает за protobuf mapping и gRPC errors. Бизнес-правила должны оставаться в service layer.

## Интеграции

- Brigade Service проверяет департаменты при создании/обновлении бригад.
- Profile Service должен проверять `department_id` рабочего профиля через Department Service или через будущую read-model.
- Ticket Service использует `department_id` как часть заявки.

## Правила разработки

- Не добавлять межсервисные FK на `department_id`.
- Новые связи на department должны проверять `ACTIVE`, если создается новая операционная сущность.
- Для read-only списков использовать read pool.
- Изменяющие операции должны быть идемпотентны на уровне API Gateway/idempotency, если вызываются с idempotency key.
