# Brigade Service — developer documentation

Brigade Service владеет бригадами, участниками бригад, справочником навыков, навыками бригад, графиками работы, зонами обслуживания и проверками готовности бригады к заявке. Сервис не владеет пользователями, профилями, департаментами и заявками: он хранит их UUID как логические ссылки и ожидает, что внешние сервисы проверяют фактическое существование этих сущностей.

## Слои сервиса

- `models` — доменные структуры, enum-статусы, input/result DTO, ошибки и валидаторы.
- `src/core/handler` — gRPC handler. Мапит protobuf request в `models.*Input`, вызывает сервисный слой и возвращает protobuf response.
- `src/core/service` — бизнес-логика, проверки доступа, валидация переходов статусов, orchestration repository calls.
- `src/core/repository` — PostgreSQL access через `pgxpool`, транзакции, history tables, outbox/idempotency.
- `scheme` — SQL migrations. Таблица и индексы разнесены по разным файлам.
- `pkg` — общая инфраструктура: logger, request id, idempotency, PostgreSQL config, graceful closer.

## Основные структуры `models`

- `Brigade` — агрегат бригады.
  - `ID` — UUID бригады.
  - `DepartmentID` — департамент, к которому относится бригада.
  - `Name`, `Description`, `Specialization` — человекочитаемые атрибуты.
  - `Status` — текущий статус: `ACTIVE`, `INACTIVE`, `AVAILABLE`, `BUSY`, `ON_ROUTE`, `ON_SITE`, `OFFLINE`, `ARCHIVED`.
  - `DeactivatedAt`, `ArchivedAt` — lifecycle timestamps.
- `BrigadeMember` — активное или историческое членство пользователя в бригаде.
  - `BrigadeID`, `UserID`, `ProfileID` связывают участника с бригадой и профилем.
  - `Role` — роль внутри бригады: `LEAD`, `DRIVER`, `TECHNICIAN`, `TRAINEE`.
  - `Active` — находится ли пользователь сейчас в составе.
  - `AvailabilityStatus` — доступность конкретного участника: `AVAILABLE`/`UNAVAILABLE`.
- `BrigadeMemberHistory` — аудит добавления, удаления и смены роли участника.
- `BrigadeMemberStatusHistory` — аудит изменения availability-статуса участника.
- `Skill` — глобальный справочник навыков. Это каталог, на который могут ссылаться Brigade и Profile Service.
- `BrigadeSkill` — активная связь бригады с навыком. Отражает capability бригады, а не обязательно автоматически вычисленную сумму навыков всех участников.
- `BrigadeSchedule` — график работы бригады по дням недели, времени, timezone и интервалу действия.
- `BrigadeStatusHistory` — аудит переходов статуса бригады.
- `BrigadeZone` — зона обслуживания бригады в GeoJSON с priority.
- `OutboxEvent` — запись outbox для eventual consistency и интеграционных событий.

## Brigade service methods

### `CreateBrigade(ctx, *CreateBrigadeInput) -> CreateBrigadeResult`

Принимает `department_id`, `name`, `description`, optional `specialization`, actor context, `request_id`, `trace_id`.

Логика:

1. Валидирует input и обязательные поля.
2. Проверяет права actor: обычно `admin` или роль, которой разрешено управлять бригадами своего департамента.
3. Проверяет department boundary: пользователь без глобальных прав не должен создавать бригаду в чужом департаменте.
4. Создает бригаду в статусе по умолчанию.
5. При необходимости пишет outbox event.
6. Возвращает созданную `Brigade`.

### `GetBrigadeByID(ctx, *GetBrigadeByIDInput) -> GetBrigadeByIDResult`

Принимает UUID бригады и actor context.

Логика: валидирует UUID, читает бригаду, проверяет доступ к департаменту бригады, возвращает `Brigade` или доменную ошибку not found/forbidden.

### `ListBrigades(ctx, *ListBrigadesInput) -> ListBrigadesResult`

Принимает фильтры `department_id`, `status`, `specialization`, период создания, сортировку, пагинацию и actor context.

Логика: нормализует пагинацию/сортировку, ограничивает выборку департаментом actor при отсутствии глобальных прав, возвращает список и `total`.

### `UpdateBrigade(ctx, *UpdateBrigadeInput) -> UpdateBrigadeResult`

Принимает UUID бригады и optional поля для изменения.

Логика: проверяет доступ, не разрешает менять архивную бригаду как обычную активную сущность, обновляет только переданные поля, пишет outbox при изменении значимых данных, возвращает актуальную `Brigade`.

### `DeactivateBrigade(ctx, *DeactivateBrigadeInput) -> DeactivateBrigadeResult`

Принимает UUID, reason, changed_by и actor context.

Логика: проверяет права, переводит бригаду в `INACTIVE`, заполняет `deactivated_at`, пишет запись в `BrigadeStatusHistory`, возвращает обновленную бригаду. Метод не должен физически удалять данные.

### `ArchiveBrigade(ctx, *ArchiveBrigadeInput) -> ArchiveBrigadeResult`

Принимает UUID, reason, changed_by и actor context.

Логика: проверяет права, переводит бригаду в `ARCHIVED`, заполняет `archived_at`, пишет историю. Архивная бригада не должна участвовать в подборе доступных бригад.

### `SetBrigadeStatus(ctx, *SetBrigadeStatusInput) -> SetBrigadeStatusResult`

Принимает `brigade_id`, новый статус, reason, changed_by, actor context.

Логика: валидирует transition, запрещает нелегальные переходы для архивных/деактивированных бригад, обновляет статус, пишет `BrigadeStatusHistory`, возвращает актуальную бригаду.

### `GetBrigadeStatusHistory(ctx, *GetBrigadeStatusHistoryInput) -> GetBrigadeStatusHistoryResult`

Принимает `brigade_id`, limit/offset, actor context.

Логика: проверяет доступ к бригаде, читает историю статусов с пагинацией, возвращает `history` и `total`.

### `GetAvailableBrigades(ctx, *GetAvailableBrigadesInput) -> GetAvailableBrigadesResult`

Принимает `department_id`, optional координаты, требуемые skill IDs, required roles, limit/offset.

Логика: ищет бригады департамента со статусом доступности, при координатах фильтрует по зонам, при required skills/roles проверяет capability бригады и состав, возвращает candidates для назначения на заявку.

### `CheckBrigadeCanHandleTicket(ctx, *CheckBrigadeCanHandleTicketInput) -> CheckBrigadeCanHandleTicketResult`

Принимает `brigade_id`, `department_id`, координаты заявки, required skill IDs и required roles.

Логика:

1. Проверяет, что бригада существует и относится к нужному департаменту.
2. Проверяет, что бригада не archived/inactive/offline/busy, если бизнес-правило требует только свободные бригады.
3. Проверяет покрытие точки через `BrigadeZone`.
4. Проверяет наличие требуемых навыков в `BrigadeSkill`.
5. Проверяет наличие активных участников с нужными ролями.
6. Возвращает `CanHandle=true` или список причин отказа.

## Member service methods

### `AddBrigadeMember(ctx, *AddBrigadeMemberInput) -> AddBrigadeMemberResult`

Принимает `brigade_id`, `user_id`, optional `profile_id`, роль, changed_by и actor context.

Логика: проверяет доступ к бригаде, валидирует роль, не допускает дубли активного участника, создает `BrigadeMember`, пишет `BrigadeMemberHistory(ADDED)`. Проверку “может ли рабочий вступить в бригаду” лучше делать через Profile Service: work profile должен быть активным и принадлежать тому же департаменту.

### `RemoveBrigadeMember(ctx, *RemoveBrigadeMemberInput) -> RemoveBrigadeMemberResult`

Принимает `brigade_id`, `member_id`, reason, changed_by, actor context.

Логика: проверяет доступ, soft-removes участника (`active=false`, `left_at`), пишет `BrigadeMemberHistory(REMOVED)`, возвращает обновленного участника.

### `ChangeBrigadeMemberRole(ctx, *ChangeBrigadeMemberRoleInput) -> ChangeBrigadeMemberRoleResult`

Принимает `brigade_id`, `member_id`, новую роль, changed_by, actor context.

Логика: проверяет активное членство, валидирует роль, обновляет роль, пишет историю `ROLE_CHANGED` с old/new role.

### `SetBrigadeMemberAvailability(ctx, *SetBrigadeMemberAvailabilityInput) -> SetBrigadeMemberAvailabilityResult`

Принимает `brigade_id`, `member_id`, availability status, reason, changed_by, actor context.

Логика: меняет доступность участника, пишет `BrigadeMemberStatusHistory`, возвращает участника. Этот статус не равен статусу бригады: участник может быть unavailable, а бригада всё еще active.

### `ListBrigadeMembers(ctx, *ListBrigadeMembersInput) -> ListBrigadeMembersResult`

Принимает `brigade_id`, фильтры active/role/availability, пагинацию и actor context.

Логика: проверяет доступ к бригаде, возвращает состав с фильтрами и total.

### `GetBrigadeMemberHistory(ctx, *GetBrigadeMemberHistoryInput) -> GetBrigadeMemberHistoryResult`

Возвращает аудит состава бригады, optional по конкретному `member_id`.

### `GetBrigadeMemberStatusHistory(ctx, *GetBrigadeMemberStatusHistoryInput) -> GetBrigadeMemberStatusHistoryResult`

Возвращает аудит availability-статусов участников.

### `GetBrigadeByUserID(ctx, *GetBrigadeByUserIDInput) -> GetBrigadeByUserIDResult`

Принимает `user_id` и `only_active`.

Логика: ищет бригаду, где пользователь состоит или состоял. Используется для внутренних сценариев, например определить текущую бригаду работника.

## Skill service methods

### `CreateSkill(ctx, *CreateSkillInput) -> CreateSkillResult`

Создает навык в глобальном справочнике. `code` должен быть стабильным машинным идентификатором, `name` — человекочитаемым названием.

### `UpdateSkill(ctx, *UpdateSkillInput) -> UpdateSkillResult`

Обновляет поля навыка и флаг `active`. При деактивации связи `BrigadeSkill` могут оставаться в БД для истории, но не должны считаться активными capability.

### `DeactivateSkill(ctx, *DeactivateSkillInput) -> DeactivateSkillResult`

Soft-deactivate навыка без физического удаления.

### `ListSkills(ctx, *ListSkillsInput) -> ListSkillsResult`

Возвращает справочник навыков с фильтром active/query и пагинацией.

### `AddBrigadeSkill(ctx, *AddBrigadeSkillInput) -> AddBrigadeSkillResult`

Добавляет capability бригаде. Метод должен проверять доступ к бригаде и существование активного навыка.

### `RemoveBrigadeSkill(ctx, *RemoveBrigadeSkillInput) -> RemoveBrigadeSkillResult`

Soft-removes capability бригады. Это не удаляет сам навык из справочника.

### `ListBrigadeSkills(ctx, *ListBrigadeSkillsInput) -> ListBrigadeSkillsResult`

Возвращает навыки конкретной бригады, optional только активные.

## Schedule service methods

### `SetBrigadeSchedule(ctx, *SetBrigadeScheduleInput) -> SetBrigadeScheduleResult`

Принимает список `BrigadeScheduleItem`: day_of_week, starts_at, ends_at, timezone, valid_from, valid_to.

Логика: проверяет доступ, валидирует интервалы, заменяет или актуализирует расписание бригады транзакционно, возвращает актуальный набор schedule rows.

### `ListBrigadeSchedule(ctx, *ListBrigadeScheduleInput) -> ListBrigadeScheduleResult`

Возвращает график бригады, optional только активные записи.

## Zone service methods

### `CreateBrigadeZone(ctx, *CreateBrigadeZoneInput) -> CreateBrigadeZoneResult`

Создает зону обслуживания бригады. `GeoJSON` должен быть валидной геометрией, `DepartmentID` должен совпадать с департаментом бригады.

### `UpdateBrigadeZone(ctx, *UpdateBrigadeZoneInput) -> UpdateBrigadeZoneResult`

Обновляет name/geo_json/priority/active. Используется для корректировки зон без пересоздания бригады.

### `DeleteBrigadeZone(ctx, *DeleteBrigadeZoneInput) -> DeleteBrigadeZoneResult`

Soft-delete зоны через `active=false`. Историю обслуживания лучше сохранять.

### `ListBrigadeZones(ctx, *ListBrigadeZonesInput) -> ListBrigadeZonesResult`

Возвращает зоны бригады, optional только active.

### `CheckBrigadeCoversPoint(ctx, *CheckBrigadeCoversPointInput) -> CheckBrigadeCoversPointResult`

Проверяет, покрывает ли конкретная бригада точку `longitude/latitude`, и возвращает matched zones.

### `FindBrigadesByPoint(ctx, *FindBrigadesByPointInput) -> FindBrigadesByPointResult`

Ищет бригады департамента, покрывающие точку. Может дополнительно фильтровать только доступные бригады, required skills и roles.

## Repository layer

Repository слой должен оставаться тонким: он отвечает за SQL, транзакционность и маппинг строк БД в модели. Бизнес-решения — в service layer.

Для операций, которые изменяют несколько таблиц, нужна транзакция. Например:

- смена статуса бригады + запись в status history + outbox event;
- добавление участника + запись в member history;
- удаление участника + history;
- обновление расписания списком;
- изменение зон и связанных индексов.

## Бизнес-правила и интеграции

- `department_id` — граница доступа. Actor без глобальных прав работает только в своем департаменте.
- Департамент должен существовать и быть активным, но это проверяется через Department Service/Gateway/orchestrator, не FK между базами.
- Пользователь и рабочий профиль принадлежат Auth/Profile Service. Brigade Service хранит `user_id`/`profile_id` как ссылки.
- Один пользователь не должен иметь два активных членства в одной бригаде. Если нужно запретить участие в нескольких бригадах сразу — это отдельное бизнес-правило, которое надо явно закрепить и покрыть constraint/check.
- Навыки бригады (`BrigadeSkill`) — capability бригады. Не стоит автоматически добавлять навык в бригаду при каждом добавлении участника без отдельного источника истины: иначе удаление/истечение квалификации участника будет сложно синхронизировать.
- Для будущей связки с Profile Service правильный senior-подход: Profile хранит verified skills работника, а Brigade при добавлении участника или подборе бригады запрашивает/кэширует effective skills. Если понадобится агрегировать навыки участников в навыки бригады, лучше делать отдельную проекцию с source и пересчетом, а не смешивать ее с ручными `BrigadeSkill`.

## Ошибки и логирование

Сервисный слой должен возвращать доменные ошибки из `models/errors.go` или оборачивать их единообразно. Handler уже мапит эти ошибки в gRPC status. Логи должны содержать operation name, request id/trace id, actor id и ключевые IDs агрегатов, но не должны раскрывать лишние персональные данные.

## Как расширять сервис

1. Добавить DTO в `models`.
2. Добавить валидацию в `models/validator.go`.
3. Добавить метод в service interface и реализацию в `src/core/service`.
4. Добавить repository method и SQL.
5. Если меняется схема — создать migration: отдельный файл таблицы и отдельный файл индексов.
6. Обновить handler/mapper.
7. Добавить unit/integration tests.
8. Обновить этот `DEVELOPER.md`.
