# Сервис бригад (Brigade Service)

## Общее описание и общий принцип работы

`Brigade Service` хранит бригады, их участников, навыки, расписания, зоны обслуживания и текущую готовность к работе. Сервис проверяет принадлежность данных подразделению, права `admin` и `dispatcher`, состояние бригады и требования к составу. Данные профилей и профессиональных навыков поступают из `Profile Service`, маршруты и заявки — через Kafka.

Администратор имеет доступ ко всем подразделениям. Диспетчер работает только с бригадами своего `ActorDepartmentID`. Работник может читать состав и расписание только собственной активной бригады. Архивная бригада недоступна для изменения состава, навыков, расписания и зон.

При добавлении участника сервис запрашивает у `Profile Service`, может ли рабочий профиль войти в бригаду, получает канонические `UserID` и `ProfileID`, загружает действующие навыки и сохраняет их снимок. Один пользователь и один профиль не могут одновременно состоять в нескольких активных записях бригад. Все значимые изменения сопровождаются историей и событиями `outbox_events`.

## Модели

### Перечисления

| Тип | Значения | Назначение |
|---|---|---|
| `BrigadeStatus` | `ACTIVE`, `INACTIVE`, `AVAILABLE`, `BUSY`, `ON_ROUTE`, `ON_SITE`, `OFFLINE`, `ARCHIVED` | Состояние бригады. |
| `BrigadeMemberRole` | `LEAD`, `DRIVER`, `TECHNICIAN`, `TRAINEE` | Роль участника. |
| `BrigadeMemberAvailabilityStatus` | `AVAILABLE`, `UNAVAILABLE` | Личная доступность участника. |
| `BrigadeMemberHistoryAction` | `ADDED`, `REMOVED`, `ROLE_CHANGED` | Вид изменения состава. |
| `BrigadeSortBy` | `created_at`, `updated_at`, `name`, `status` | Поле сортировки. |
| `SortOrder` | `asc`, `desc` | Направление сортировки. |
| `OutboxEventStatus` | `PENDING`, `PROCESSING`, `SENT`, `FAILED` | Состояние публикации события. |

### Основные сущности

| Структура | Поле | Тип Go | Назначение |
|---|---|---|---|
| `Brigade` | `ID` | `uuid.UUID` | Идентификатор бригады. |
| `Brigade` | `DepartmentID` | `uuid.UUID` | Подразделение-владелец. |
| `Brigade` | `Name` | `string` | Название. |
| `Brigade` | `Description` | `string` | Описание. |
| `Brigade` | `Status` | `BrigadeStatus` | Текущее состояние. |
| `Brigade` | `Specialization` | `*string` | Необязательная специализация. |
| `Brigade` | `CreatedAt`, `UpdatedAt` | `time.Time` | Время создания и изменения. |
| `Brigade` | `DeactivatedAt`, `ArchivedAt` | `*time.Time` | Время деактивации и архивирования. |
| `BrigadeMember` | `ID`, `BrigadeID`, `UserID` | `uuid.UUID` | Запись участника, бригада и пользователь. |
| `BrigadeMember` | `ProfileID` | `*uuid.UUID` | Рабочий профиль. |
| `BrigadeMember` | `Role` | `BrigadeMemberRole` | Роль в бригаде. |
| `BrigadeMember` | `Active` | `bool` | Признак действующего участия. |
| `BrigadeMember` | `AvailabilityStatus` | `BrigadeMemberAvailabilityStatus` | Личная доступность. |
| `BrigadeMember` | `AvailabilityStatusChangedAt` | `time.Time` | Время изменения доступности. |
| `BrigadeMember` | `JoinedAt`, `LeftAt` | `time.Time`, `*time.Time` | Время вступления и выхода. |
| `BrigadeMember` | `CreatedAt`, `UpdatedAt` | `time.Time` | Время создания и изменения записи. |
| `Skill` | `ID` | `uuid.UUID` | Идентификатор навыка. |
| `Skill` | `Code`, `Name`, `Description` | `string` | Код, название и описание навыка. |
| `Skill` | `Active` | `bool` | Можно ли использовать навык. |
| `Skill` | `CreatedAt`, `UpdatedAt` | `time.Time` | Время создания и изменения. |
| `BrigadeSkill` | `ID`, `BrigadeID`, `SkillID` | `uuid.UUID` | Связь бригады и навыка. |
| `BrigadeSkill` | `Skill` | `*Skill` | Загруженное описание навыка. |
| `BrigadeSkill` | `Active` | `bool` | Действует ли связь. |
| `BrigadeSkill` | `CreatedAt`, `UpdatedAt` | `time.Time` | Время создания и изменения. |
| `BrigadeSchedule` | `ID`, `BrigadeID` | `uuid.UUID` | Запись расписания и бригада. |
| `BrigadeSchedule` | `DayOfWeek` | `int16` | День недели от 1 до 7. |
| `BrigadeSchedule` | `StartsAt`, `EndsAt` | `string` | Начало и окончание работы. |
| `BrigadeSchedule` | `Timezone` | `string` | Часовой пояс. |
| `BrigadeSchedule` | `Active` | `bool` | Действует ли строка расписания. |
| `BrigadeSchedule` | `ValidFrom`, `ValidTo` | `*time.Time` | Необязательный период действия. |
| `BrigadeSchedule` | `CreatedAt`, `UpdatedAt` | `time.Time` | Время создания и изменения. |
| `BrigadeZone` | `ID`, `BrigadeID`, `DepartmentID` | `uuid.UUID` | Зона, бригада и подразделение. |
| `BrigadeZone` | `Name` | `string` | Название зоны. |
| `BrigadeZone` | `GeoJSON` | `string` | Полигон или мультиполигон GeoJSON. |
| `BrigadeZone` | `Priority` | `int32` | Приоритет зоны. |
| `BrigadeZone` | `Active` | `bool` | Действует ли зона. |
| `BrigadeZone` | `CreatedAt`, `UpdatedAt` | `time.Time` | Время создания и изменения. |

### История и события

| Структура | Поля и назначение |
|---|---|
| `BrigadeMemberHistory` | `ID` — запись; `BrigadeID`, `MemberID`, `UserID`, `ProfileID` — участник и его связи; `Action` — действие; `OldRole`, `NewRole` — смена роли; `ChangedByUserID` — автор; `RequestID` — запрос; `CreatedAt` — время. |
| `BrigadeMemberStatusHistory` | `ID`, `BrigadeID`, `MemberID`, `UserID` — участник; `FromStatus`, `ToStatus` — изменение доступности; `Reason` — причина; `ChangedByUserID`, `RequestID`, `CreatedAt` — автор, запрос и время. |
| `BrigadeStatusHistory` | `ID`, `BrigadeID` — запись и бригада; `FromStatus`, `ToStatus` — переход; `Reason` — причина; `ChangedByUserID`, `RequestID`, `CreatedAt` — автор, запрос и время. |
| `OutboxEvent` | `ID` — событие; `AggregateType`, `AggregateID` — сущность; `EventType`, `Payload` — тип и данные; `RequestID`, `TraceID` — связь с запросом и трассировкой; `Status`, `Attempts`, `LastError`, `CreatedAt`, `SentAt` — доставка. |

### Запросы бригад

| Структура | Поля и назначение |
|---|---|
| `CreateBrigadeInput` | `DepartmentID`, `Name`, `Description`, `Specialization` — данные бригады; `ActorUserID`, `ActorDepartmentID`, `ActorRoles` — исполнитель; `RequestID`, `TraceID` — наблюдаемость. |
| `GetBrigadeByIDInput` | `ID` — бригада; поля `Actor*` — проверка доступа. |
| `ListBrigadesInput` | фильтры `DepartmentID`, `Status`, `Specialization`, `CreatedFrom`, `CreatedTo`; `SortBy`, `SortOrder`, `Limit`, `Offset`; поля `Actor*`. |
| `UpdateBrigadeInput` | `ID`; изменяемые `Name`, `Description`, `Specialization`; поля `Actor*`, `RequestID`, `TraceID`. |
| `DeactivateBrigadeInput`, `ArchiveBrigadeInput` | `ID`, `Reason`, `ChangedByUserID`; поля `Actor*`, `RequestID`, `TraceID`. |
| `SetBrigadeStatusInput` | `BrigadeID`, `Status`, `Reason`, `ChangedByUserID`; поля `Actor*`, `RequestID`, `TraceID`. |
| `GetBrigadeStatusHistoryInput` | `BrigadeID`, `Limit`, `Offset` и поля `Actor*`. |
| `GetAvailableBrigadesInput` | `DepartmentID`; необязательные координаты; `RequiredSkillIDs`, `RequiredRoles`; `Limit`, `Offset`. |
| `CheckBrigadeCanHandleTicketInput` | `BrigadeID`, `DepartmentID`, координаты, требуемые навыки и роли. |

Для каждого изменяющего или читающего запроса существует результат с тем же корнем имени: он содержит `Brigade`, `History`, список `Brigades` и `Total` либо `CanHandle` и список `Reasons`.

### Результирующие структуры

| Структура | Возвращаемые данные |
|---|---|
| `CreateBrigadeResult`, `GetBrigadeByIDResult`, `UpdateBrigadeResult`, `DeactivateBrigadeResult`, `ArchiveBrigadeResult`, `SetBrigadeStatusResult` | Поле `Brigade` с созданной, найденной или измененной бригадой. |
| `ListBrigadesResult`, `GetAvailableBrigadesResult`, `FindBrigadesByPointResult` | `Brigades` и полное количество `Total`. |
| `GetBrigadeStatusHistoryResult` | `History` переходов и `Total`. |
| `AddBrigadeMemberResult`, `RemoveBrigadeMemberResult`, `ChangeBrigadeMemberRoleResult`, `SetBrigadeMemberAvailabilityResult` | Поле `Member` с измененным участником. |
| `ListBrigadeMembersResult` | `Members` и `Total`. |
| `GetBrigadeMemberHistoryResult`, `GetBrigadeMemberStatusHistoryResult` | Соответствующая `History` и `Total`. |
| `GetBrigadeByUserIDResult` | Найденные `Brigade` и `Member`. |
| `CreateSkillResult`, `UpdateSkillResult`, `DeactivateSkillResult` | Поле `Skill`. |
| `ListSkillsResult` | `Skills` и `Total`. |
| `AddBrigadeSkillResult`, `RemoveBrigadeSkillResult` | Поле `BrigadeSkill`. |
| `ListBrigadeSkillsResult` | Список `Skills`. |
| `SetBrigadeScheduleResult`, `ListBrigadeScheduleResult` | Список `Schedule`. |
| `CreateBrigadeZoneResult`, `UpdateBrigadeZoneResult`, `DeleteBrigadeZoneResult` | Поле `Zone`. |
| `ListBrigadeZonesResult` | Список `Zones`. |
| `CheckBrigadeCoversPointResult` | `Covers` и `MatchedZones`. |
| `CheckBrigadeCanHandleTicketResult` | `CanHandle` и `Reasons`. |

### Запросы состава

| Структура | Поля и назначение |
|---|---|
| `AddBrigadeMemberInput` | `BrigadeID`, `UserID`, `ProfileID`, `Role`, `ChangedByUserID`; поля `Actor*`, `RequestID`, `TraceID`; `InitialSkills` — снимок навыков профиля. |
| `BrigadeMemberSkillSeed` | `WorkProfileID`, `SkillID`, `SourceGrantID`; `ProficiencyLevel`, `ValidUntil`, `Active`, `OccurredAt` — свойства выданного навыка. |
| `RemoveBrigadeMemberInput` | `BrigadeID`, `MemberID`, `Reason`, `ChangedByUserID`; поля `Actor*`, `RequestID`, `TraceID`. |
| `ChangeBrigadeMemberRoleInput` | `BrigadeID`, `MemberID`, новая `Role`, `ChangedByUserID`; поля `Actor*`, `RequestID`, `TraceID`. |
| `SetBrigadeMemberAvailabilityInput` | `BrigadeID`, `MemberID`, `Status`, `Reason`, `ChangedByUserID`; поля `Actor*`, `RequestID`, `TraceID`. |
| `ListBrigadeMembersInput` | `BrigadeID`; фильтры `Active`, `Role`, `AvailabilityStatus`; `Limit`, `Offset`; поля `Actor*`. |
| `GetBrigadeMemberHistoryInput`, `GetBrigadeMemberStatusHistoryInput` | `BrigadeID`, необязательный `MemberID`, `Limit`, `Offset`, поля `Actor*`. |
| `GetBrigadeByUserIDInput` | `UserID`, `OnlyActive`. |

Результаты содержат `Member`, список `Members`, соответствующую `History` и `Total`, либо пару `Brigade`/`Member` для поиска по пользователю.

### Запросы навыков, расписания и зон

| Структура | Поля и назначение |
|---|---|
| `CreateSkillInput` | `Code`, `Name`, `Description`; `ActorUserID`, `ActorRoles`, `RequestID`, `TraceID`. |
| `UpdateSkillInput` | `ID`; необязательные `Code`, `Name`, `Description`, `Active`; данные исполнителя. |
| `DeactivateSkillInput` | `ID` и данные исполнителя. |
| `ListSkillsInput` | фильтр `Active`, строка `Query`, `Limit`, `Offset`, данные исполнителя. |
| `AddBrigadeSkillInput`, `RemoveBrigadeSkillInput` | `BrigadeID`, `SkillID`, поля `Actor*`, `RequestID`, `TraceID`. |
| `ListBrigadeSkillsInput` | `BrigadeID`, фильтр `Active`, поля `Actor*`. |
| `BrigadeScheduleItem` | `DayOfWeek`, `StartsAt`, `EndsAt`, `Timezone`, `ValidFrom`, `ValidTo`. |
| `SetBrigadeScheduleInput` | `BrigadeID`, список `Items`, поля `Actor*`, `RequestID`, `TraceID`. |
| `ListBrigadeScheduleInput` | `BrigadeID`, фильтр `Active`, поля `Actor*`. |
| `CreateBrigadeZoneInput` | `BrigadeID`, `DepartmentID`, `Name`, `GeoJSON`, `Priority`, поля `Actor*`, `RequestID`, `TraceID`. |
| `UpdateBrigadeZoneInput` | `ID`; необязательные `Name`, `GeoJSON`, `Priority`, `Active`; данные исполнителя. |
| `DeleteBrigadeZoneInput` | `ID` и данные исполнителя. |
| `ListBrigadeZonesInput` | `BrigadeID`, фильтр `Active`, данные исполнителя. |
| `CheckBrigadeCoversPointInput` | `BrigadeID`, `Longitude`, `Latitude`. |
| `FindBrigadesByPointInput` | `DepartmentID`, координаты, `OnlyAvailable`, требуемые навыки и роли, `Limit`, `Offset`. |

Результаты содержат соответствующий `Skill`, `BrigadeSkill`, `Schedule`, `Zone`, список `Zones`, пару `Covers`/`MatchedZones` либо список `Brigades` с `Total`.

## Функции

Имя функции открывает её реализацию в ветке `test`; структуры параметров и результатов описаны в конце README.

### func [NewService](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/service.go#L75)

```go
func NewService(repo *repository.Repo, departmentClient departmentv1.DepartmentServiceClient, logger *zap.Logger) *Service
```

Типы: [Service](#type-service).

Вызывает `NewServiceWithProfile` без клиента профилей.

### func [NewServiceWithProfile](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/service.go#L79)

```go
func NewServiceWithProfile(repo *repository.Repo, departmentClient departmentv1.DepartmentServiceClient, profileClient profilev1.ProfileServiceClient, logger *zap.Logger) *Service
```

Типы: [Service](#type-service).

Подставляет журнал без вывода при `nil` и собирает единый `Service` из служб бригад, участников, навыков, расписания и зон. При наличии клиента профилей участники создаются через строгую проверку профиля.

### func [NewBrigadeService](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L32)

```go
func NewBrigadeService(repo *repository.Repo, departmentClient departmentv1.DepartmentServiceClient, log *zap.Logger) *BrigadeServiceStruct
```

Типы: [BrigadeServiceStruct](#type-brigadeservicestruct).

Структуры: [BrigadeServiceStruct](#type-brigadeservicestruct).

Создают службы и сохраняют зависимости. Вариант `WithProfile` устанавливает `requireProfile=true`, поэтому отсутствие клиента считается недоступностью зависимости.

### func [NewMemberServiceStruct](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/member_service.go#L24)

```go
func NewMemberServiceStruct(repo *repository.Repo, log *zap.Logger) *MemberServiceStruct
```

Типы: [MemberServiceStruct](#type-memberservicestruct).

Структуры: [MemberServiceStruct](#type-memberservicestruct).

Создают службы и сохраняют зависимости. Вариант `WithProfile` устанавливает `requireProfile=true`, поэтому отсутствие клиента считается недоступностью зависимости.

### func [NewMemberServiceStructWithProfile](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/member_service.go#L28)

```go
func NewMemberServiceStructWithProfile(repo *repository.Repo, profileClient profilev1.ProfileServiceClient, log *zap.Logger) *MemberServiceStruct
```

Типы: [MemberServiceStruct](#type-memberservicestruct).

Структуры: [MemberServiceStruct](#type-memberservicestruct).

Создают службы и сохраняют зависимости. Вариант `WithProfile` устанавливает `requireProfile=true`, поэтому отсутствие клиента считается недоступностью зависимости.

### func [NewSkillServiceStruct](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/skill_service.go#L20)

```go
func NewSkillServiceStruct(repo *repository.Repo, log *zap.Logger) *SkillServiceStruct
```

Типы: [SkillServiceStruct](#type-skillservicestruct).

Структуры: [SkillServiceStruct](#type-skillservicestruct).

Создают специализированные службы поверх общего хранилища и журнала.

### func [NewScheduleServiceStruct](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/schedule_service.go#L20)

```go
func NewScheduleServiceStruct(repo *repository.Repo, log *zap.Logger) *ScheduleServiceStruct
```

Типы: [ScheduleServiceStruct](#type-scheduleservicestruct).

Структуры: [ScheduleServiceStruct](#type-scheduleservicestruct).

Создают специализированные службы поверх общего хранилища и журнала.

### func [NewZoneServiceStruct](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/zone_service.go#L20)

```go
func NewZoneServiceStruct(repo *repository.Repo, log *zap.Logger) *ZoneServiceStruct
```

Типы: [ZoneServiceStruct](#type-zoneservicestruct).

Структуры: [ZoneServiceStruct](#type-zoneservicestruct).

Создают специализированные службы поверх общего хранилища и журнала.

### func [mapDepartmentServiceError](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L158)

```go
func mapDepartmentServiceError(err error) error
```

Преобразует отсутствие подразделения в `ErrNotFound`, временную недоступность и нехватку ресурсов — в `ErrDependencyUnavailable`, остальные ошибки оставляет без изменения.

### func [isRetryableDepartmentError](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L173)

```go
func isRetryableDepartmentError(err error) bool
```

Возвращает `true` только для трех временных кодов gRPC, перечисленных выше.

### func [checkPermissionAndDepartmentForAdminAndDispatcher](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L622)

```go
func checkPermissionAndDepartmentForAdminAndDispatcher(log *zap.Logger, start time.Time, actorRoles []string, actorDepartmentID *uuid.UUID, departmentID uuid.UUID) error
```

Администратору разрешает действие сразу. Диспетчеру требует непустой `ActorDepartmentID`, совпадающий с подразделением объекта. Остальным возвращает `ErrPermissionDenied`.

### func [brigadeStatusRequiresActiveMember](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/member_service.go#L503)

```go
func brigadeStatusRequiresActiveMember(status models.BrigadeStatus) bool
```

Требует активного участника для `ACTIVE`, `AVAILABLE`, `BUSY`, `ON_ROUTE`, `ON_SITE`, `OFFLINE`; для `INACTIVE` и `ARCHIVED` не требует.

### func [checkAdminRole](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/skill_service.go#L293)

```go
func checkAdminRole(log *zap.Logger, start time.Time, actorRoles []string) error
```

Первая функция разрешает только `admin`; вторая — `admin` или `dispatcher`. При отказе пишут предупреждение и возвращают `ErrPermissionDenied`.

### func [checkAdminOrDispatcherRole](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/skill_service.go#L308)

```go
func checkAdminOrDispatcherRole(log *zap.Logger, start time.Time, actorRoles []string) error
```

Первая функция разрешает только `admin`; вторая — `admin` или `dispatcher`. При отказе пишут предупреждение и возвращают `ErrPermissionDenied`.

### func (*BrigadeServiceStruct) [CreateBrigade](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L40)

```go
func (b *BrigadeServiceStruct) CreateBrigade(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error)
```

Типы: [BrigadeServiceStruct](#type-brigadeservicestruct), [CreateBrigadeInput](#type-createbrigadeinput), [CreateBrigadeResult](#type-createbrigaderesult).

Проверяет вход, права и подразделение. До записи трижды обращается к `Department Service` с тайм-аутом две секунды, растущей задержкой и случайной добавкой; продолжает только для активного подразделения. Затем создает бригаду, историю и событие через хранилище.


### func (*BrigadeServiceStruct) [getDepartmentByIDWithRetry](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L114)

```go
func (b *BrigadeServiceStruct) getDepartmentByIDWithRetry(ctx context.Context, log *zap.Logger, departmentID uuid.UUID) (*departmentv1.GetDepartmentByIDResponse, error)
```

Типы: [BrigadeServiceStruct](#type-brigadeservicestruct).

Повторяет только ошибки `Unavailable`, `DeadlineExceeded`, `ResourceExhausted`; учитывает отмену контекста. После последней попытки преобразует ошибку через `mapDepartmentServiceError`.


### func (*BrigadeServiceStruct) [GetBrigadeByID](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L182)

```go
func (b *BrigadeServiceStruct) GetBrigadeByID(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error)
```

Типы: [BrigadeServiceStruct](#type-brigadeservicestruct), [GetBrigadeByIDInput](#type-getbrigadebyidinput), [GetBrigadeByIDResult](#type-getbrigadebyidresult).

Проверяет UUID, загружает бригаду и применяет правило администратора/диспетчера. Если оно не выполнено, разрешает чтение работнику, который активно состоит именно в этой бригаде.


### func (*BrigadeServiceStruct) [ListBrigades](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L228)

```go
func (b *BrigadeServiceStruct) ListBrigades(ctx context.Context, in *models.ListBrigadesInput) (*models.ListBrigadesResult, error)
```

Типы: [BrigadeServiceStruct](#type-brigadeservicestruct), [ListBrigadesInput](#type-listbrigadesinput), [ListBrigadesResult](#type-listbrigadesresult).

Разрешает запрос только `admin` или `dispatcher`. Для диспетчера принудительно заменяет фильтр подразделения на его `ActorDepartmentID`, затем передает нормализованные фильтры хранилищу.


### func (*BrigadeServiceStruct) [UpdateBrigade](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L293)

```go
func (b *BrigadeServiceStruct) UpdateBrigade(ctx context.Context, in *models.UpdateBrigadeInput) (*models.UpdateBrigadeResult, error)
```

Типы: [BrigadeServiceStruct](#type-brigadeservicestruct), [UpdateBrigadeInput](#type-updatebrigadeinput), [UpdateBrigadeResult](#type-updatebrigaderesult).

Проверяет запрос, загружает текущую бригаду для определения подразделения, проверяет права и выполняет частичное обновление. Конфликт активного названия возвращается как `ErrAlreadyExists`.


### func (*BrigadeServiceStruct) [DeactivateBrigade](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L345)

```go
func (b *BrigadeServiceStruct) DeactivateBrigade(ctx context.Context, in *models.DeactivateBrigadeInput) (*models.DeactivateBrigadeResult, error)
```

Типы: [BrigadeServiceStruct](#type-brigadeservicestruct), [DeactivateBrigadeInput](#type-deactivatebrigadeinput), [DeactivateBrigadeResult](#type-deactivatebrigaderesult).

Проверяет бригаду и права, подставляет `ActorUserID` в `ChangedByUserID`, если автор не указан, и переводит бригаду в неактивное состояние с причиной.


### func (*BrigadeServiceStruct) [ArchiveBrigade](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L393)

```go
func (b *BrigadeServiceStruct) ArchiveBrigade(ctx context.Context, in *models.ArchiveBrigadeInput) (*models.ArchiveBrigadeResult, error)
```

Типы: [ArchiveBrigadeInput](#type-archivebrigadeinput), [ArchiveBrigadeResult](#type-archivebrigaderesult), [BrigadeServiceStruct](#type-brigadeservicestruct).

Работает аналогично деактивации, но переводит запись в `ARCHIVED` и фиксирует время архивирования.


### func (*BrigadeServiceStruct) [SetBrigadeStatus](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L441)

```go
func (b *BrigadeServiceStruct) SetBrigadeStatus(ctx context.Context, in *models.SetBrigadeStatusInput) (*models.SetBrigadeStatusResult, error)
```

Типы: [BrigadeServiceStruct](#type-brigadeservicestruct), [SetBrigadeStatusInput](#type-setbrigadestatusinput), [SetBrigadeStatusResult](#type-setbrigadestatusresult).

Проверяет вход, загружает бригаду, проверяет права и готовность через `checkStatusReadiness`, подставляет автора и передает переход хранилищу. В журнал пишутся длительности этапов.


### func (*BrigadeServiceStruct) [GetBrigadeStatusHistory](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L513)

```go
func (b *BrigadeServiceStruct) GetBrigadeStatusHistory(ctx context.Context, in *models.GetBrigadeStatusHistoryInput) (*models.GetBrigadeStatusHistoryResult, error)
```

Типы: [BrigadeServiceStruct](#type-brigadeservicestruct), [GetBrigadeStatusHistoryInput](#type-getbrigadestatushistoryinput), [GetBrigadeStatusHistoryResult](#type-getbrigadestatushistoryresult).

Проверяет страницу и доступ к подразделению, затем возвращает историю переходов бригады.


### func (*BrigadeServiceStruct) [GetAvailableBrigades](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L557)

```go
func (b *BrigadeServiceStruct) GetAvailableBrigades(ctx context.Context, in *models.GetAvailableBrigadesInput) (*models.GetAvailableBrigadesResult, error)
```

Типы: [BrigadeServiceStruct](#type-brigadeservicestruct), [GetAvailableBrigadesInput](#type-getavailablebrigadesinput), [GetAvailableBrigadesResult](#type-getavailablebrigadesresult).

Проверяет подразделение, парность координат, требуемые навыки и роли, страницу, затем выбирает готовые бригады с учетом указанных условий.


### func (*BrigadeServiceStruct) [CheckBrigadeCanHandleTicket](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L594)

```go
func (b *BrigadeServiceStruct) CheckBrigadeCanHandleTicket(ctx context.Context, in *models.CheckBrigadeCanHandleTicketInput) (*models.CheckBrigadeCanHandleTicketResult, error)
```

Типы: [BrigadeServiceStruct](#type-brigadeservicestruct), [CheckBrigadeCanHandleTicketInput](#type-checkbrigadecanhandleticketinput), [CheckBrigadeCanHandleTicketResult](#type-checkbrigadecanhandleticketresult).

Передает проверенный идентификатор бригады, подразделение, точку и требования хранилищу. Возвращает `CanHandle` и конкретные причины отказа.


### func (*BrigadeServiceStruct) [checkStatusReadiness](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/brigade_service.go#L674)

```go
func (b *BrigadeServiceStruct) checkStatusReadiness(ctx context.Context, log *zap.Logger, start time.Time, brigade *models.Brigade, targetStatus models.BrigadeStatus) error
```

Типы: [Brigade](#type-brigade), [BrigadeServiceStruct](#type-brigadeservicestruct).

Для `ACTIVE` требует готовность состава. Для `AVAILABLE` дополнительно запрещает исходные `INACTIVE` и `ARCHIVED` и требует полную готовность. Наличие причин превращает результат в `ErrBrigadeUnavailable`.


### func (*MemberServiceStruct) [AddBrigadeMember](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/member_service.go#L37)

```go
func (m *MemberServiceStruct) AddBrigadeMember(ctx context.Context, in *models.AddBrigadeMemberInput) (*models.AddBrigadeMemberResult, error)
```

Типы: [AddBrigadeMemberInput](#type-addbrigadememberinput), [AddBrigadeMemberResult](#type-addbrigadememberresult), [MemberServiceStruct](#type-memberservicestruct).

Проверяет вход, бригаду и права. При включенной связи с профилями проверяет разрешение на вступление, заменяет идентификаторы каноническими и загружает действующие навыки. Затем запрещает второе активное членство пользователя, подставляет автора и сохраняет участника, историю, навыки и событие.


### func (*MemberServiceStruct) [RemoveBrigadeMember](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/member_service.go#L157)

```go
func (m *MemberServiceStruct) RemoveBrigadeMember(ctx context.Context, in *models.RemoveBrigadeMemberInput) (*models.RemoveBrigadeMemberResult, error)
```

Типы: [MemberServiceStruct](#type-memberservicestruct), [RemoveBrigadeMemberInput](#type-removebrigadememberinput), [RemoveBrigadeMemberResult](#type-removebrigadememberresult).

Проверяет права и через `checkCanRemoveMember` не дает удалить последнего активного участника рабочей бригады. Затем деактивирует участника, фиксирует выход, историю и событие.


### func (*MemberServiceStruct) [ChangeBrigadeMemberRole](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/member_service.go#L202)

```go
func (m *MemberServiceStruct) ChangeBrigadeMemberRole(ctx context.Context, in *models.ChangeBrigadeMemberRoleInput) (*models.ChangeBrigadeMemberRoleResult, error)
```

Типы: [ChangeBrigadeMemberRoleInput](#type-changebrigadememberroleinput), [ChangeBrigadeMemberRoleResult](#type-changebrigadememberroleresult), [MemberServiceStruct](#type-memberservicestruct).

Проверяет бригаду, права и новую роль, подставляет автора и сохраняет изменение вместе с прежней и новой ролью в истории.


### func (*MemberServiceStruct) [SetBrigadeMemberAvailability](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/member_service.go#L244)

```go
func (m *MemberServiceStruct) SetBrigadeMemberAvailability(ctx context.Context, in *models.SetBrigadeMemberAvailabilityInput) (*models.SetBrigadeMemberAvailabilityResult, error)
```

Типы: [MemberServiceStruct](#type-memberservicestruct), [SetBrigadeMemberAvailabilityInput](#type-setbrigadememberavailabilityinput), [SetBrigadeMemberAvailabilityResult](#type-setbrigadememberavailabilityresult).

Проверяет состояние `AVAILABLE`/`UNAVAILABLE`, бригаду и права, подставляет автора, изменяет личную доступность и записывает отдельную историю с причиной.


### func (*MemberServiceStruct) [ListBrigadeMembers](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/member_service.go#L286)

```go
func (m *MemberServiceStruct) ListBrigadeMembers(ctx context.Context, in *models.ListBrigadeMembersInput) (*models.ListBrigadeMembersResult, error)
```

Типы: [ListBrigadeMembersInput](#type-listbrigademembersinput), [ListBrigadeMembersResult](#type-listbrigademembersresult), [MemberServiceStruct](#type-memberservicestruct).

Администратор и диспетчер читают состав по общему правилу. Работник также может читать состав собственной активной бригады. Поддерживаются фильтры активности, роли и доступности.


### func (*MemberServiceStruct) [GetBrigadeMemberHistory](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/member_service.go#L330)

```go
func (m *MemberServiceStruct) GetBrigadeMemberHistory(ctx context.Context, in *models.GetBrigadeMemberHistoryInput) (*models.GetBrigadeMemberHistoryResult, error)
```

Типы: [GetBrigadeMemberHistoryInput](#type-getbrigadememberhistoryinput), [GetBrigadeMemberHistoryResult](#type-getbrigadememberhistoryresult), [MemberServiceStruct](#type-memberservicestruct).

После проверки бригады и прав возвращает историю вступления, выхода и смены роли, при необходимости только для одного участника.


### func (*MemberServiceStruct) [GetBrigadeMemberStatusHistory](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/member_service.go#L366)

```go
func (m *MemberServiceStruct) GetBrigadeMemberStatusHistory(ctx context.Context, in *models.GetBrigadeMemberStatusHistoryInput) (*models.GetBrigadeMemberStatusHistoryResult, error)
```

Типы: [GetBrigadeMemberStatusHistoryInput](#type-getbrigadememberstatushistoryinput), [GetBrigadeMemberStatusHistoryResult](#type-getbrigadememberstatushistoryresult), [MemberServiceStruct](#type-memberservicestruct).

Возвращает историю личной доступности участника с теми же правилами доступа и постраничным выводом.


### func (*MemberServiceStruct) [GetBrigadeByUserID](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/member_service.go#L402)

```go
func (m *MemberServiceStruct) GetBrigadeByUserID(ctx context.Context, in *models.GetBrigadeByUserIDInput) (*models.GetBrigadeByUserIDResult, error)
```

Типы: [GetBrigadeByUserIDInput](#type-getbrigadebyuseridinput), [GetBrigadeByUserIDResult](#type-getbrigadebyuseridresult), [MemberServiceStruct](#type-memberservicestruct).

Проверяет `UserID` и возвращает бригаду вместе с записью участника; `OnlyActive` ограничивает поиск действующим членством.


### func (*MemberServiceStruct) [getBrigadeForMemberOperation](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/member_service.go#L429)

```go
func (m *MemberServiceStruct) getBrigadeForMemberOperation(
    ctx context.Context,
    log *zap.Logger,
    start time.Time,
    brigadeID uuid.UUID,
    actorUserID *uuid.UUID,
    actorDepartmentID *uuid.UUID,
    actorRoles []string,
    operation string,
) (*models.Brigade, error)
```

Типы: [Brigade](#type-brigade), [MemberServiceStruct](#type-memberservicestruct).

Загружает бригаду, оборачивает ошибку и запрещает любые операции над архивной бригадой.


### func (*MemberServiceStruct) [checkCanRemoveMember](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/member_service.go#L472)

```go
func (m *MemberServiceStruct) checkCanRemoveMember(ctx context.Context, log *zap.Logger, start time.Time, brigade *models.Brigade, in *models.RemoveBrigadeMemberInput) error
```

Типы: [Brigade](#type-brigade), [MemberServiceStruct](#type-memberservicestruct), [RemoveBrigadeMemberInput](#type-removebrigadememberinput).

Для рабочего состояния загружает до двух активных участников. Если удаляемая запись — единственный активный участник, возвращает `ErrBrigadeUnavailable`.


### func (*SkillServiceStruct) [CreateSkill](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/skill_service.go#L27)

```go
func (s *SkillServiceStruct) CreateSkill(ctx context.Context, in *models.CreateSkillInput) (*models.CreateSkillResult, error)
```

Типы: [CreateSkillInput](#type-createskillinput), [CreateSkillResult](#type-createskillresult), [SkillServiceStruct](#type-skillservicestruct).

Требует роль `admin`, проверяет код, название и описание, затем создает навык.


### func (*SkillServiceStruct) [UpdateSkill](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/skill_service.go#L58)

```go
func (s *SkillServiceStruct) UpdateSkill(ctx context.Context, in *models.UpdateSkillInput) (*models.UpdateSkillResult, error)
```

Типы: [SkillServiceStruct](#type-skillservicestruct), [UpdateSkillInput](#type-updateskillinput), [UpdateSkillResult](#type-updateskillresult).

Требует `admin`, хотя бы одно изменяемое поле и корректные значения; затем обновляет навык.


### func (*SkillServiceStruct) [DeactivateSkill](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/skill_service.go#L89)

```go
func (s *SkillServiceStruct) DeactivateSkill(ctx context.Context, in *models.DeactivateSkillInput) (*models.DeactivateSkillResult, error)
```

Типы: [DeactivateSkillInput](#type-deactivateskillinput), [DeactivateSkillResult](#type-deactivateskillresult), [SkillServiceStruct](#type-skillservicestruct).

Требует `admin` и переводит навык в неактивное состояние без физического удаления.


### func (*SkillServiceStruct) [ListSkills](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/skill_service.go#L120)

```go
func (s *SkillServiceStruct) ListSkills(ctx context.Context, in *models.ListSkillsInput) (*models.ListSkillsResult, error)
```

Типы: [ListSkillsInput](#type-listskillsinput), [ListSkillsResult](#type-listskillsresult), [SkillServiceStruct](#type-skillservicestruct).

Разрешен `admin` и `dispatcher`; применяет фильтр активности, текстовый поиск и страницу.


### func (*SkillServiceStruct) [AddBrigadeSkill](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/skill_service.go#L150)

```go
func (s *SkillServiceStruct) AddBrigadeSkill(ctx context.Context, in *models.AddBrigadeSkillInput) (*models.AddBrigadeSkillResult, error)
```

Типы: [AddBrigadeSkillInput](#type-addbrigadeskillinput), [AddBrigadeSkillResult](#type-addbrigadeskillresult), [SkillServiceStruct](#type-skillservicestruct).

Проверяет неархивную бригаду и доступ к ее подразделению, затем добавляет или восстанавливает связь навыка.


### func (*SkillServiceStruct) [RemoveBrigadeSkill](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/skill_service.go#L187)

```go
func (s *SkillServiceStruct) RemoveBrigadeSkill(ctx context.Context, in *models.RemoveBrigadeSkillInput) (*models.RemoveBrigadeSkillResult, error)
```

Типы: [RemoveBrigadeSkillInput](#type-removebrigadeskillinput), [RemoveBrigadeSkillResult](#type-removebrigadeskillresult), [SkillServiceStruct](#type-skillservicestruct).

Проверяет те же условия и деактивирует связь навыка с бригадой.


### func (*SkillServiceStruct) [ListBrigadeSkills](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/skill_service.go#L224)

```go
func (s *SkillServiceStruct) ListBrigadeSkills(ctx context.Context, in *models.ListBrigadeSkillsInput) (*models.ListBrigadeSkillsResult, error)
```

Типы: [ListBrigadeSkillsInput](#type-listbrigadeskillsinput), [ListBrigadeSkillsResult](#type-listbrigadeskillsresult), [SkillServiceStruct](#type-skillservicestruct).

Проверяет бригаду и права, затем возвращает ее навыки с необязательным фильтром активности.


### func (*SkillServiceStruct) [getBrigadeForSkillOperation](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/skill_service.go#L260)

```go
func (s *SkillServiceStruct) getBrigadeForSkillOperation(
    ctx context.Context,
    log *zap.Logger,
    start time.Time,
    brigadeID uuid.UUID,
    actorUserID *uuid.UUID,
    actorDepartmentID *uuid.UUID,
    actorRoles []string,
    operation string,
) (*models.Brigade, error)
```

Типы: [Brigade](#type-brigade), [SkillServiceStruct](#type-skillservicestruct).

Загружает бригаду и запрещает работу с навыками архивной бригады.


### func (*ScheduleServiceStruct) [SetBrigadeSchedule](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/schedule_service.go#L27)

```go
func (s *ScheduleServiceStruct) SetBrigadeSchedule(ctx context.Context, in *models.SetBrigadeScheduleInput) (*models.SetBrigadeScheduleResult, error)
```

Типы: [ScheduleServiceStruct](#type-scheduleservicestruct), [SetBrigadeScheduleInput](#type-setbrigadescheduleinput), [SetBrigadeScheduleResult](#type-setbrigadescheduleresult).

Проверяет каждый день, время, часовой пояс и период действия, затем проверяет неархивную бригаду и права. Хранилище заменяет расписание набором переданных строк.


### func (*ScheduleServiceStruct) [ListBrigadeSchedule](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/schedule_service.go#L63)

```go
func (s *ScheduleServiceStruct) ListBrigadeSchedule(ctx context.Context, in *models.ListBrigadeScheduleInput) (*models.ListBrigadeScheduleResult, error)
```

Типы: [ListBrigadeScheduleInput](#type-listbrigadescheduleinput), [ListBrigadeScheduleResult](#type-listbrigadescheduleresult), [ScheduleServiceStruct](#type-scheduleservicestruct).

Администратор и диспетчер читают расписание по общему правилу; участник может прочитать расписание своей активной бригады. Поддерживается фильтр активности.


### func (*ScheduleServiceStruct) [getBrigadeForScheduleOperation](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/schedule_service.go#L107)

```go
func (s *ScheduleServiceStruct) getBrigadeForScheduleOperation(
    ctx context.Context,
    log *zap.Logger,
    start time.Time,
    brigadeID uuid.UUID,
    actorUserID *uuid.UUID,
    actorDepartmentID *uuid.UUID,
    actorRoles []string,
    operation string,
) (*models.Brigade, error)
```

Типы: [Brigade](#type-brigade), [ScheduleServiceStruct](#type-scheduleservicestruct).

Загружает бригаду и запрещает расписание архивной бригады.


### func (*ZoneServiceStruct) [CreateBrigadeZone](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/zone_service.go#L27)

```go
func (z *ZoneServiceStruct) CreateBrigadeZone(ctx context.Context, in *models.CreateBrigadeZoneInput) (*models.CreateBrigadeZoneResult, error)
```

Типы: [CreateBrigadeZoneInput](#type-createbrigadezoneinput), [CreateBrigadeZoneResult](#type-createbrigadezoneresult), [ZoneServiceStruct](#type-zoneservicestruct).

Проверяет UUID, название, GeoJSON, координатную структуру и приоритет. Требует совпадения подразделения зоны и бригады, затем проверяет права и сохраняет географию.


### func (*ZoneServiceStruct) [UpdateBrigadeZone](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/zone_service.go#L75)

```go
func (z *ZoneServiceStruct) UpdateBrigadeZone(ctx context.Context, in *models.UpdateBrigadeZoneInput) (*models.UpdateBrigadeZoneResult, error)
```

Типы: [UpdateBrigadeZoneInput](#type-updatebrigadezoneinput), [UpdateBrigadeZoneResult](#type-updatebrigadezoneresult), [ZoneServiceStruct](#type-zoneservicestruct).

Загружает зону, по ней определяет бригаду и подразделение, проверяет права и частично обновляет поля.


### func (*ZoneServiceStruct) [DeleteBrigadeZone](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/zone_service.go#L116)

```go
func (z *ZoneServiceStruct) DeleteBrigadeZone(ctx context.Context, in *models.DeleteBrigadeZoneInput) (*models.DeleteBrigadeZoneResult, error)
```

Типы: [DeleteBrigadeZoneInput](#type-deletebrigadezoneinput), [DeleteBrigadeZoneResult](#type-deletebrigadezoneresult), [ZoneServiceStruct](#type-zoneservicestruct).

Загружает зону и бригаду, проверяет доступ и удаляет зону через хранилище.


### func (*ZoneServiceStruct) [ListBrigadeZones](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/zone_service.go#L157)

```go
func (z *ZoneServiceStruct) ListBrigadeZones(ctx context.Context, in *models.ListBrigadeZonesInput) (*models.ListBrigadeZonesResult, error)
```

Типы: [ListBrigadeZonesInput](#type-listbrigadezonesinput), [ListBrigadeZonesResult](#type-listbrigadezonesresult), [ZoneServiceStruct](#type-zoneservicestruct).

Проверяет неархивную бригаду и доступ, затем возвращает ее зоны с фильтром активности.


### func (*ZoneServiceStruct) [CheckBrigadeCoversPoint](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/zone_service.go#L193)

```go
func (z *ZoneServiceStruct) CheckBrigadeCoversPoint(ctx context.Context, in *models.CheckBrigadeCoversPointInput) (*models.CheckBrigadeCoversPointResult, error)
```

Типы: [CheckBrigadeCoversPointInput](#type-checkbrigadecoverspointinput), [CheckBrigadeCoversPointResult](#type-checkbrigadecoverspointresult), [ZoneServiceStruct](#type-zoneservicestruct).

Проверяет координаты и возвращает признак попадания точки хотя бы в одну действующую зону и список совпавших зон.


### func (*ZoneServiceStruct) [FindBrigadesByPoint](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/zone_service.go#L221)

```go
func (z *ZoneServiceStruct) FindBrigadesByPoint(ctx context.Context, in *models.FindBrigadesByPointInput) (*models.FindBrigadesByPointResult, error)
```

Типы: [FindBrigadesByPointInput](#type-findbrigadesbypointinput), [FindBrigadesByPointResult](#type-findbrigadesbypointresult), [ZoneServiceStruct](#type-zoneservicestruct).

Проверяет точку, подразделение, роли, навыки и страницу. Хранилище ищет бригады по пространственному пересечению и может оставить только доступные.


### func (*ZoneServiceStruct) [getBrigadeForZoneOperation](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/core/service/zone_service.go#L248)

```go
func (z *ZoneServiceStruct) getBrigadeForZoneOperation(
    ctx context.Context,
    log *zap.Logger,
    start time.Time,
    brigadeID uuid.UUID,
    actorUserID *uuid.UUID,
    actorDepartmentID *uuid.UUID,
    actorRoles []string,
    operation string,
) (*models.Brigade, error)
```

Типы: [Brigade](#type-brigade), [ZoneServiceStruct](#type-zoneservicestruct).

Загружает бригаду для операции с зоной и запрещает архивную запись.


## Структура БД

### Таблица `brigades`

| Поле | Тип | Назначение |
|---|---|---|
| `id` | `uuid` | Первичный ключ. |
| `department_id` | `uuid` | Подразделение. |
| `name` | `varchar(255)` | Название; уникально среди неархивных бригад подразделения. |
| `description` | `text` | Описание. |
| `status` | `varchar(32)` | Состояние бригады. |
| `specialization` | `varchar(255)` | Специализация. |
| `created_at`, `updated_at` | `timestamp` | Время создания и изменения. |
| `deactivated_at`, `archived_at` | `timestamp` | Время деактивации и архивирования. |

### Таблица `brigade_members`

| Поле | Тип | Назначение |
|---|---|---|
| `id` | `uuid` | Первичный ключ. |
| `brigade_id` | `uuid` | Бригада; удаление бригады удаляет участника. |
| `user_id` | `uuid` | Пользователь. |
| `profile_id` | `uuid` | Рабочий профиль. |
| `role` | `varchar(32)` | Роль участника. |
| `active` | `boolean` | Действующее членство. |
| `availability_status` | `varchar(32)` | Личная доступность. |
| `availability_status_changed_at` | `timestamp` | Время изменения доступности. |
| `joined_at`, `left_at` | `timestamp` | Вступление и выход. |
| `created_at`, `updated_at` | `timestamp` | Создание и изменение. |

### Таблица `brigade_member_history`

| Поле | Тип | Назначение |
|---|---|---|
| `id` | `uuid` | Первичный ключ. |
| `brigade_id`, `member_id`, `user_id`, `profile_id` | `uuid` | Связанные бригада, запись участника, пользователь и профиль. |
| `action` | `varchar(32)` | `ADDED`, `REMOVED` или `ROLE_CHANGED`. |
| `old_role`, `new_role` | `varchar(32)` | Прежняя и новая роль. |
| `changed_by_user_id` | `uuid` | Автор изменения. |
| `request_id` | `varchar(128)` | Идентификатор запроса. |
| `created_at` | `timestamp` | Время события. |

### Таблица `brigade_member_status_history`

| Поле | Тип | Назначение |
|---|---|---|
| `id`, `brigade_id`, `member_id`, `user_id` | `uuid` | Запись, бригада и участник. |
| `from_status`, `to_status` | `varchar(32)` | Прежняя и новая доступность. |
| `reason` | `text` | Причина. |
| `changed_by_user_id` | `uuid` | Автор. |
| `request_id` | `varchar(128)` | Запрос. |
| `created_at` | `timestamp` | Время. |

### Таблица `skills`

| Поле | Тип | Назначение |
|---|---|---|
| `id` | `uuid` | Первичный ключ. |
| `code` | `varchar(100)` | Код, уникальный без учета регистра. |
| `name` | `varchar(255)` | Название. |
| `description` | `text` | Описание. |
| `active` | `boolean` | Действует ли навык. |
| `created_at`, `updated_at` | `timestamp` | Создание и изменение. |

### Таблица `brigade_skills`

| Поле | Тип | Назначение |
|---|---|---|
| `id` | `uuid` | Первичный ключ. |
| `brigade_id`, `skill_id` | `uuid` | Бригада и навык. |
| `active` | `boolean` | Действует ли связь. |
| `created_at`, `updated_at` | `timestamp` | Создание и изменение. |

### Таблица `brigade_schedule`

| Поле | Тип | Назначение |
|---|---|---|
| `id`, `brigade_id` | `uuid` | Запись и бригада. |
| `day_of_week` | `smallint` | День 1–7. |
| `starts_at`, `ends_at` | `time` | Начало и окончание, которые не могут совпадать. |
| `timezone` | `varchar(64)` | Часовой пояс; по умолчанию `Europe/Moscow`. |
| `active` | `boolean` | Действует ли строка. |
| `valid_from`, `valid_to` | `date` | Период действия. |
| `created_at`, `updated_at` | `timestamp` | Создание и изменение. |

### Таблица `brigade_status_history`

| Поле | Тип | Назначение |
|---|---|---|
| `id`, `brigade_id` | `uuid` | Запись и бригада. |
| `from_status`, `to_status` | `varchar(32)` | Переход состояния. |
| `reason` | `text` | Причина. |
| `changed_by_user_id` | `uuid` | Автор. |
| `request_id` | `varchar(128)` | Запрос. |
| `created_at` | `timestamp` | Время. |

### Таблица `brigade_zones`

| Поле | Тип | Назначение |
|---|---|---|
| `id`, `brigade_id`, `department_id` | `uuid` | Зона, бригада и подразделение. |
| `name` | `varchar(255)` | Название. |
| `zone` | `geography(geometry,4326)` | Полигон или мультиполигон обслуживания. |
| `priority` | `integer` | Приоритет. |
| `active` | `boolean` | Действует ли зона. |
| `created_at`, `updated_at` | `timestamp` | Создание и изменение. |

### Таблица `outbox_events`

| Поле | Тип | Назначение |
|---|---|---|
| `id` | `uuid` | Событие. |
| `aggregate_type`, `event_type` | `varchar(100)` | Вид сущности и события. |
| `aggregate_id` | `uuid` | Идентификатор сущности. |
| `payload` | `jsonb` | Данные события. |
| `request_id`, `trace_id` | `varchar(128)` | Запрос и трассировка. |
| `status` | `varchar(50)` | Состояние доставки. |
| `attempts` | `integer` | Попытки. |
| `last_error` | `text` | Последняя ошибка. |
| `next_attempt_at`, `locked_at`, `created_at`, `sent_at` | `timestamp` | Планирование и времена обработки. |

### Таблица `idempotency_keys`

| Поле | Тип | Назначение |
|---|---|---|
| `id` | `uuid` | Запись. |
| `actor_key` | `varchar(128)` | Исполнитель. |
| `operation` | `varchar(100)` | Операция. |
| `idempotency_key`, `request_hash` | `varchar(128)` | Ключ и хеш запроса. |
| `status` | `varchar(32)` | `PROCESSING`, `COMPLETED`, `FAILED`. |
| `response` | `jsonb` | Сохраненный ответ. |
| `error` | `text` | Ошибка. |
| `resource_type` | `varchar(100)` | Вид ресурса. |
| `resource_id` | `uuid` | Идентификатор ресурса. |
| `created_at`, `updated_at`, `expires_at` | `timestamp` | Создание, изменение и срок хранения. |

### Таблица `inbox_events`

| Поле | Тип | Назначение |
|---|---|---|
| `event_id` | `uuid` | Первичный ключ входящего события профиля. |
| `source_service` | `varchar(100)` | Сервис-источник. |
| `topic` | `varchar(255)` | Раздел Kafka. |
| `partition_id` | `integer` | Номер раздела. |
| `message_offset` | `bigint` | Позиция сообщения. |
| `event_type` | `varchar(128)` | Тип события. |
| `event_version` | `integer` | Версия формата. |
| `occurred_at`, `processed_at` | `timestamptz` | Время события и обработки. |
| `payload` | `jsonb` | Данные. |

### Таблица `brigade_member_skills`

| Поле | Тип | Назначение |
|---|---|---|
| `id`, `brigade_id`, `member_id`, `work_profile_id`, `skill_id`, `source_grant_id` | `uuid` | Запись и связи с бригадой, участником, профилем, навыком и выдачей. |
| `proficiency_level` | `varchar(100)` | Уровень владения. |
| `valid_until` | `timestamptz` | Окончание действия. |
| `active`, `work_profile_active` | `boolean` | Активность выдачи и профиля. |
| `source_occurred_at`, `created_at`, `updated_at` | `timestamptz` | Время источника, создания и изменения. |

### Таблица `routing_inbox_events`

| Поле | Тип | Назначение |
|---|---|---|
| `event_id` | `uuid` | Входящее событие маршрута. |
| `event_type` | `varchar(128)` | Тип события. |
| `topic` | `varchar(255)` | Раздел Kafka. |
| `partition_id` | `integer` | Раздел. |
| `message_offset` | `bigint` | Позиция. |
| `payload` | `jsonb` | Данные. |
| `processed_at` | `timestamp` | Время обработки. |

### Таблица `brigade_route_projection`

| Поле | Тип | Назначение |
|---|---|---|
| `brigade_id` | `uuid` | Первичный ключ и бригада. |
| `route_id`, `ticket_id` | `uuid` | Маршрут и заявка. |
| `route_status` | `varchar(32)` | `PLANNED`, `ACTIVE`, `COMPLETED` или `CANCELLED`. |
| `revision` | `integer` | Версия маршрута. |
| `source_updated_at` | `timestamptz` | Время изменения у источника. |
| `updated_at` | `timestamp` | Время обновления проекции. |

### Таблица `ticket_inbox_events`

| Поле | Тип | Назначение |
|---|---|---|
| `event_id` | `uuid` | Входящее событие заявки. |
| `event_type` | `varchar(128)` | Тип. |
| `topic` | `varchar(255)` | Раздел Kafka. |
| `partition_id` | `integer` | Раздел. |
| `message_offset` | `bigint` | Позиция. |
| `payload` | `jsonb` | Данные. |
| `processed_at` | `timestamp` | Время обработки. |

### Таблица `brigade_shifts`

| Поле | Тип | Назначение |
|---|---|---|
| `id`, `brigade_id`, `department_id` | `uuid` | Смена, бригада и подразделение. |
| `started_at`, `ended_at` | `timestamptz` | Начало и окончание смены. |
| `started_by_user_id`, `ended_by_user_id` | `uuid` | Кто открыл и закрыл смену. |
| `start_reason`, `end_reason` | `text` | Причины открытия и закрытия. |
| `created_at`, `updated_at` | `timestamptz` | Создание и изменение. |

Частичный уникальный индекс допускает только одну незавершенную смену для бригады.

## Структуры параметров и результатов

### type AddBrigadeMemberInput

```go
type AddBrigadeMemberInput struct {
	BrigadeID         uuid.UUID
	UserID            uuid.UUID
	ProfileID         *uuid.UUID
	Role              BrigadeMemberRole
	ChangedByUserID   *uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
	InitialSkills     []BrigadeMemberSkillSeed
}
```

### type AddBrigadeMemberResult

```go
type AddBrigadeMemberResult struct {
	Member *BrigadeMember
}
```

### type AddBrigadeSkillInput

```go
type AddBrigadeSkillInput struct {
	BrigadeID         uuid.UUID
	SkillID           uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}
```

### type AddBrigadeSkillResult

```go
type AddBrigadeSkillResult struct {
	BrigadeSkill *BrigadeSkill
}
```

### type ArchiveBrigadeInput

```go
type ArchiveBrigadeInput struct {
	ID                uuid.UUID
	Reason            string
	ChangedByUserID   *uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}
```

### type ArchiveBrigadeResult

```go
type ArchiveBrigadeResult struct {
	Brigade *Brigade
}
```

### type Brigade

```go
type Brigade struct {
	ID             uuid.UUID     `json:"id"`
	DepartmentID   uuid.UUID     `json:"department_id"`
	Name           string        `json:"name"`
	Description    string        `json:"description"`
	Status         BrigadeStatus `json:"status"`
	Specialization *string       `json:"specialization,omitempty"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
	DeactivatedAt  *time.Time    `json:"deactivated_at,omitempty"`
	ArchivedAt     *time.Time    `json:"archived_at,omitempty"`
}
```

### type BrigadeServiceStruct

```go
type BrigadeServiceStruct struct {
	repo             *repository.Repo
	departmentClient departmentv1.DepartmentServiceClient
	log              *zap.Logger
}
```

### type ChangeBrigadeMemberRoleInput

```go
type ChangeBrigadeMemberRoleInput struct {
	BrigadeID         uuid.UUID
	MemberID          uuid.UUID
	Role              BrigadeMemberRole
	ChangedByUserID   *uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}
```

### type ChangeBrigadeMemberRoleResult

```go
type ChangeBrigadeMemberRoleResult struct {
	Member *BrigadeMember
}
```

### type CheckBrigadeCanHandleTicketInput

```go
type CheckBrigadeCanHandleTicketInput struct {
	BrigadeID        uuid.UUID
	DepartmentID     uuid.UUID
	Longitude        float64
	Latitude         float64
	RequiredSkillIDs []uuid.UUID
	RequiredRoles    []BrigadeMemberRole
}
```

### type CheckBrigadeCanHandleTicketResult

```go
type CheckBrigadeCanHandleTicketResult struct {
	CanHandle bool
	Reasons   []string
}
```

### type CheckBrigadeCoversPointInput

```go
type CheckBrigadeCoversPointInput struct {
	BrigadeID uuid.UUID
	Longitude float64
	Latitude  float64
}
```

### type CheckBrigadeCoversPointResult

```go
type CheckBrigadeCoversPointResult struct {
	Covers       bool
	MatchedZones []*BrigadeZone
}
```

### type CreateBrigadeInput

```go
type CreateBrigadeInput struct {
	DepartmentID      uuid.UUID
	Name              string
	Description       string
	Specialization    *string
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}
```

### type CreateBrigadeResult

```go
type CreateBrigadeResult struct {
	Brigade *Brigade
}
```

### type CreateBrigadeZoneInput

```go
type CreateBrigadeZoneInput struct {
	BrigadeID         uuid.UUID
	DepartmentID      uuid.UUID
	Name              string
	GeoJSON           string
	Priority          int32
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}
```

### type CreateBrigadeZoneResult

```go
type CreateBrigadeZoneResult struct {
	Zone *BrigadeZone
}
```

### type CreateSkillInput

```go
type CreateSkillInput struct {
	Code        string
	Name        string
	Description string
	ActorUserID *uuid.UUID
	ActorRoles  []string
	RequestID   *string
	TraceID     *string
}
```

### type CreateSkillResult

```go
type CreateSkillResult struct {
	Skill *Skill
}
```

### type DeactivateBrigadeInput

```go
type DeactivateBrigadeInput struct {
	ID                uuid.UUID
	Reason            string
	ChangedByUserID   *uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}
```

### type DeactivateBrigadeResult

```go
type DeactivateBrigadeResult struct {
	Brigade *Brigade
}
```

### type DeactivateSkillInput

```go
type DeactivateSkillInput struct {
	ID          uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
	RequestID   *string
	TraceID     *string
}
```

### type DeactivateSkillResult

```go
type DeactivateSkillResult struct {
	Skill *Skill
}
```

### type DeleteBrigadeZoneInput

```go
type DeleteBrigadeZoneInput struct {
	ID                uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}
```

### type DeleteBrigadeZoneResult

```go
type DeleteBrigadeZoneResult struct {
	Zone *BrigadeZone
}
```

### type FindBrigadesByPointInput

```go
type FindBrigadesByPointInput struct {
	DepartmentID     uuid.UUID
	Longitude        float64
	Latitude         float64
	OnlyAvailable    bool
	RequiredSkillIDs []uuid.UUID
	RequiredRoles    []BrigadeMemberRole
	Limit            int32
	Offset           int32
}
```

### type FindBrigadesByPointResult

```go
type FindBrigadesByPointResult struct {
	Brigades []*Brigade
	Total    int64
}
```

### type GetAvailableBrigadesInput

```go
type GetAvailableBrigadesInput struct {
	DepartmentID     uuid.UUID
	Longitude        *float64
	Latitude         *float64
	RequiredSkillIDs []uuid.UUID
	RequiredRoles    []BrigadeMemberRole
	Limit            int32
	Offset           int32
}
```

### type GetAvailableBrigadesResult

```go
type GetAvailableBrigadesResult struct {
	Brigades []*Brigade
	Total    int64
}
```

### type GetBrigadeByIDInput

```go
type GetBrigadeByIDInput struct {
	ID                uuid.UUID
	ActorUserID       *uuid.UUID // only for service
	ActorDepartmentID *uuid.UUID // only for service
	ActorRoles        []string   // only for service
}
```

### type GetBrigadeByIDResult

```go
type GetBrigadeByIDResult struct {
	Brigade *Brigade
}
```

### type GetBrigadeByUserIDInput

```go
type GetBrigadeByUserIDInput struct {
	UserID     uuid.UUID
	OnlyActive bool
}
```

### type GetBrigadeByUserIDResult

```go
type GetBrigadeByUserIDResult struct {
	Brigade *Brigade
	Member  *BrigadeMember
}
```

### type GetBrigadeMemberHistoryInput

```go
type GetBrigadeMemberHistoryInput struct {
	BrigadeID         uuid.UUID
	MemberID          *uuid.UUID
	Limit             int32
	Offset            int32
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}
```

### type GetBrigadeMemberHistoryResult

```go
type GetBrigadeMemberHistoryResult struct {
	History []*BrigadeMemberHistory
	Total   int64
}
```

### type GetBrigadeMemberStatusHistoryInput

```go
type GetBrigadeMemberStatusHistoryInput struct {
	BrigadeID         uuid.UUID
	MemberID          *uuid.UUID
	Limit             int32
	Offset            int32
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}
```

### type GetBrigadeMemberStatusHistoryResult

```go
type GetBrigadeMemberStatusHistoryResult struct {
	History []*BrigadeMemberStatusHistory
	Total   int64
}
```

### type GetBrigadeStatusHistoryInput

```go
type GetBrigadeStatusHistoryInput struct {
	BrigadeID         uuid.UUID
	Limit             int32
	Offset            int32
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}
```

### type GetBrigadeStatusHistoryResult

```go
type GetBrigadeStatusHistoryResult struct {
	History []*BrigadeStatusHistory
	Total   int64
}
```

### type ListBrigadeMembersInput

```go
type ListBrigadeMembersInput struct {
	BrigadeID          uuid.UUID
	Active             *bool
	Role               *BrigadeMemberRole
	AvailabilityStatus *BrigadeMemberAvailabilityStatus
	Limit              int32
	Offset             int32
	ActorUserID        *uuid.UUID
	ActorDepartmentID  *uuid.UUID
	ActorRoles         []string
}
```

### type ListBrigadeMembersResult

```go
type ListBrigadeMembersResult struct {
	Members []*BrigadeMember
	Total   int64
}
```

### type ListBrigadeScheduleInput

```go
type ListBrigadeScheduleInput struct {
	BrigadeID         uuid.UUID
	Active            *bool
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}
```

### type ListBrigadeScheduleResult

```go
type ListBrigadeScheduleResult struct {
	Schedule []*BrigadeSchedule
}
```

### type ListBrigadeSkillsInput

```go
type ListBrigadeSkillsInput struct {
	BrigadeID         uuid.UUID
	Active            *bool
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}
```

### type ListBrigadeSkillsResult

```go
type ListBrigadeSkillsResult struct {
	Skills []*BrigadeSkill
}
```

### type ListBrigadeZonesInput

```go
type ListBrigadeZonesInput struct {
	BrigadeID         uuid.UUID
	Active            *bool
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}
```

### type ListBrigadeZonesResult

```go
type ListBrigadeZonesResult struct {
	Zones []*BrigadeZone
}
```

### type ListBrigadesInput

```go
type ListBrigadesInput struct {
	DepartmentID      *uuid.UUID
	Status            *BrigadeStatus
	Specialization    *string
	CreatedFrom       *time.Time
	CreatedTo         *time.Time
	SortBy            BrigadeSortBy
	SortOrder         SortOrder
	Limit             int32
	Offset            int32
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
}
```

### type ListBrigadesResult

```go
type ListBrigadesResult struct {
	Brigades []*Brigade
	Total    int64
}
```

### type ListSkillsInput

```go
type ListSkillsInput struct {
	Active      *bool
	Query       *string
	Limit       int32
	Offset      int32
	ActorUserID *uuid.UUID
	ActorRoles  []string
}
```

### type ListSkillsResult

```go
type ListSkillsResult struct {
	Skills []*Skill
	Total  int64
}
```

### type MemberServiceStruct

```go
type MemberServiceStruct struct {
	repo           *repository.Repo
	log            *zap.Logger
	profileClient  profilev1.ProfileServiceClient
	requireProfile bool
}
```

### type RemoveBrigadeMemberInput

```go
type RemoveBrigadeMemberInput struct {
	BrigadeID         uuid.UUID
	MemberID          uuid.UUID
	Reason            string
	ChangedByUserID   *uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}
```

### type RemoveBrigadeMemberResult

```go
type RemoveBrigadeMemberResult struct {
	Member *BrigadeMember
}
```

### type RemoveBrigadeSkillInput

```go
type RemoveBrigadeSkillInput struct {
	BrigadeID         uuid.UUID
	SkillID           uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}
```

### type RemoveBrigadeSkillResult

```go
type RemoveBrigadeSkillResult struct {
	BrigadeSkill *BrigadeSkill
}
```

### type ScheduleServiceStruct

```go
type ScheduleServiceStruct struct {
	repo *repository.Repo
	log  *zap.Logger
}
```

### type Service

```go
type Service struct {
	BrigadeService
	MemberService
	SkillService
	ScheduleService
	ZoneService
}
```

### type SetBrigadeMemberAvailabilityInput

```go
type SetBrigadeMemberAvailabilityInput struct {
	BrigadeID         uuid.UUID
	MemberID          uuid.UUID
	Status            BrigadeMemberAvailabilityStatus
	Reason            string
	ChangedByUserID   *uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}
```

### type SetBrigadeMemberAvailabilityResult

```go
type SetBrigadeMemberAvailabilityResult struct {
	Member *BrigadeMember
}
```

### type SetBrigadeScheduleInput

```go
type SetBrigadeScheduleInput struct {
	BrigadeID         uuid.UUID
	Items             []*BrigadeScheduleItem
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}
```

### type SetBrigadeScheduleResult

```go
type SetBrigadeScheduleResult struct {
	Schedule []*BrigadeSchedule
}
```

### type SetBrigadeStatusInput

```go
type SetBrigadeStatusInput struct {
	BrigadeID         uuid.UUID
	Status            BrigadeStatus
	Reason            string
	ChangedByUserID   *uuid.UUID
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}
```

### type SetBrigadeStatusResult

```go
type SetBrigadeStatusResult struct {
	Brigade *Brigade
}
```

### type SkillServiceStruct

```go
type SkillServiceStruct struct {
	repo *repository.Repo
	log  *zap.Logger
}
```

### type UpdateBrigadeInput

```go
type UpdateBrigadeInput struct {
	ID                uuid.UUID
	Name              *string
	Description       *string
	Specialization    *string
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}
```

### type UpdateBrigadeResult

```go
type UpdateBrigadeResult struct {
	Brigade *Brigade
}
```

### type UpdateBrigadeZoneInput

```go
type UpdateBrigadeZoneInput struct {
	ID                uuid.UUID
	Name              *string
	GeoJSON           *string
	Priority          *int32
	Active            *bool
	ActorUserID       *uuid.UUID
	ActorDepartmentID *uuid.UUID
	ActorRoles        []string
	RequestID         *string
	TraceID           *string
}
```

### type UpdateBrigadeZoneResult

```go
type UpdateBrigadeZoneResult struct {
	Zone *BrigadeZone
}
```

### type UpdateSkillInput

```go
type UpdateSkillInput struct {
	ID          uuid.UUID
	Code        *string
	Name        *string
	Description *string
	Active      *bool
	ActorUserID *uuid.UUID
	ActorRoles  []string
	RequestID   *string
	TraceID     *string
}
```

### type UpdateSkillResult

```go
type UpdateSkillResult struct {
	Skill *Skill
}
```

### type ZoneServiceStruct

```go
type ZoneServiceStruct struct {
	repo *repository.Repo
	log  *zap.Logger
}
```
