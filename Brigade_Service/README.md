# Brigade Service

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

### `NewService`

Вызывает `NewServiceWithProfile` без клиента профилей.

### `NewServiceWithProfile`

Подставляет журнал без вывода при `nil` и собирает единый `Service` из служб бригад, участников, навыков, расписания и зон. При наличии клиента профилей участники создаются через строгую проверку профиля.

### `NewBrigadeService`, `NewMemberServiceStruct`, `NewMemberServiceStructWithProfile`

Создают службы и сохраняют зависимости. Вариант `WithProfile` устанавливает `requireProfile=true`, поэтому отсутствие клиента считается недоступностью зависимости.

### `NewSkillServiceStruct`, `NewScheduleServiceStruct`, `NewZoneServiceStruct`

Создают специализированные службы поверх общего хранилища и журнала.

### `BrigadeServiceStruct.CreateBrigade`

Проверяет вход, права и подразделение. До записи трижды обращается к `Department Service` с тайм-аутом две секунды, растущей задержкой и случайной добавкой; продолжает только для активного подразделения. Затем создает бригаду, историю и событие через хранилище.

### `BrigadeServiceStruct.getDepartmentByIDWithRetry`

Повторяет только ошибки `Unavailable`, `DeadlineExceeded`, `ResourceExhausted`; учитывает отмену контекста. После последней попытки преобразует ошибку через `mapDepartmentServiceError`.

### `mapDepartmentServiceError`

Преобразует отсутствие подразделения в `ErrNotFound`, временную недоступность и нехватку ресурсов — в `ErrDependencyUnavailable`, остальные ошибки оставляет без изменения.

### `isRetryableDepartmentError`

Возвращает `true` только для трех временных кодов gRPC, перечисленных выше.

### `BrigadeServiceStruct.GetBrigadeByID`

Проверяет UUID, загружает бригаду и применяет правило администратора/диспетчера. Если оно не выполнено, разрешает чтение работнику, который активно состоит именно в этой бригаде.

### `BrigadeServiceStruct.ListBrigades`

Разрешает запрос только `admin` или `dispatcher`. Для диспетчера принудительно заменяет фильтр подразделения на его `ActorDepartmentID`, затем передает нормализованные фильтры хранилищу.

### `BrigadeServiceStruct.UpdateBrigade`

Проверяет запрос, загружает текущую бригаду для определения подразделения, проверяет права и выполняет частичное обновление. Конфликт активного названия возвращается как `ErrAlreadyExists`.

### `BrigadeServiceStruct.DeactivateBrigade`

Проверяет бригаду и права, подставляет `ActorUserID` в `ChangedByUserID`, если автор не указан, и переводит бригаду в неактивное состояние с причиной.

### `BrigadeServiceStruct.ArchiveBrigade`

Работает аналогично деактивации, но переводит запись в `ARCHIVED` и фиксирует время архивирования.

### `BrigadeServiceStruct.SetBrigadeStatus`

Проверяет вход, загружает бригаду, проверяет права и готовность через `checkStatusReadiness`, подставляет автора и передает переход хранилищу. В журнал пишутся длительности этапов.

### `BrigadeServiceStruct.GetBrigadeStatusHistory`

Проверяет страницу и доступ к подразделению, затем возвращает историю переходов бригады.

### `BrigadeServiceStruct.GetAvailableBrigades`

Проверяет подразделение, парность координат, требуемые навыки и роли, страницу, затем выбирает готовые бригады с учетом указанных условий.

### `BrigadeServiceStruct.CheckBrigadeCanHandleTicket`

Передает проверенный идентификатор бригады, подразделение, точку и требования хранилищу. Возвращает `CanHandle` и конкретные причины отказа.

### `checkPermissionAndDepartmentForAdminAndDispatcher`

Администратору разрешает действие сразу. Диспетчеру требует непустой `ActorDepartmentID`, совпадающий с подразделением объекта. Остальным возвращает `ErrPermissionDenied`.

### `BrigadeServiceStruct.checkStatusReadiness`

Для `ACTIVE` требует готовность состава. Для `AVAILABLE` дополнительно запрещает исходные `INACTIVE` и `ARCHIVED` и требует полную готовность. Наличие причин превращает результат в `ErrBrigadeUnavailable`.

### `MemberServiceStruct.AddBrigadeMember`

Проверяет вход, бригаду и права. При включенной связи с профилями проверяет разрешение на вступление, заменяет идентификаторы каноническими и загружает действующие навыки. Затем запрещает второе активное членство пользователя, подставляет автора и сохраняет участника, историю, навыки и событие.

### `MemberServiceStruct.RemoveBrigadeMember`

Проверяет права и через `checkCanRemoveMember` не дает удалить последнего активного участника рабочей бригады. Затем деактивирует участника, фиксирует выход, историю и событие.

### `MemberServiceStruct.ChangeBrigadeMemberRole`

Проверяет бригаду, права и новую роль, подставляет автора и сохраняет изменение вместе с прежней и новой ролью в истории.

### `MemberServiceStruct.SetBrigadeMemberAvailability`

Проверяет состояние `AVAILABLE`/`UNAVAILABLE`, бригаду и права, подставляет автора, изменяет личную доступность и записывает отдельную историю с причиной.

### `MemberServiceStruct.ListBrigadeMembers`

Администратор и диспетчер читают состав по общему правилу. Работник также может читать состав собственной активной бригады. Поддерживаются фильтры активности, роли и доступности.

### `MemberServiceStruct.GetBrigadeMemberHistory`

После проверки бригады и прав возвращает историю вступления, выхода и смены роли, при необходимости только для одного участника.

### `MemberServiceStruct.GetBrigadeMemberStatusHistory`

Возвращает историю личной доступности участника с теми же правилами доступа и постраничным выводом.

### `MemberServiceStruct.GetBrigadeByUserID`

Проверяет `UserID` и возвращает бригаду вместе с записью участника; `OnlyActive` ограничивает поиск действующим членством.

### `MemberServiceStruct.getBrigadeForMemberOperation`

Загружает бригаду, оборачивает ошибку и запрещает любые операции над архивной бригадой.

### `MemberServiceStruct.checkCanRemoveMember`

Для рабочего состояния загружает до двух активных участников. Если удаляемая запись — единственный активный участник, возвращает `ErrBrigadeUnavailable`.

### `brigadeStatusRequiresActiveMember`

Требует активного участника для `ACTIVE`, `AVAILABLE`, `BUSY`, `ON_ROUTE`, `ON_SITE`, `OFFLINE`; для `INACTIVE` и `ARCHIVED` не требует.

### `SkillServiceStruct.CreateSkill`

Требует роль `admin`, проверяет код, название и описание, затем создает навык.

### `SkillServiceStruct.UpdateSkill`

Требует `admin`, хотя бы одно изменяемое поле и корректные значения; затем обновляет навык.

### `SkillServiceStruct.DeactivateSkill`

Требует `admin` и переводит навык в неактивное состояние без физического удаления.

### `SkillServiceStruct.ListSkills`

Разрешен `admin` и `dispatcher`; применяет фильтр активности, текстовый поиск и страницу.

### `SkillServiceStruct.AddBrigadeSkill`

Проверяет неархивную бригаду и доступ к ее подразделению, затем добавляет или восстанавливает связь навыка.

### `SkillServiceStruct.RemoveBrigadeSkill`

Проверяет те же условия и деактивирует связь навыка с бригадой.

### `SkillServiceStruct.ListBrigadeSkills`

Проверяет бригаду и права, затем возвращает ее навыки с необязательным фильтром активности.

### `SkillServiceStruct.getBrigadeForSkillOperation`

Загружает бригаду и запрещает работу с навыками архивной бригады.

### `checkAdminRole`, `checkAdminOrDispatcherRole`

Первая функция разрешает только `admin`; вторая — `admin` или `dispatcher`. При отказе пишут предупреждение и возвращают `ErrPermissionDenied`.

### `ScheduleServiceStruct.SetBrigadeSchedule`

Проверяет каждый день, время, часовой пояс и период действия, затем проверяет неархивную бригаду и права. Хранилище заменяет расписание набором переданных строк.

### `ScheduleServiceStruct.ListBrigadeSchedule`

Администратор и диспетчер читают расписание по общему правилу; участник может прочитать расписание своей активной бригады. Поддерживается фильтр активности.

### `ScheduleServiceStruct.getBrigadeForScheduleOperation`

Загружает бригаду и запрещает расписание архивной бригады.

### `ZoneServiceStruct.CreateBrigadeZone`

Проверяет UUID, название, GeoJSON, координатную структуру и приоритет. Требует совпадения подразделения зоны и бригады, затем проверяет права и сохраняет географию.

### `ZoneServiceStruct.UpdateBrigadeZone`

Загружает зону, по ней определяет бригаду и подразделение, проверяет права и частично обновляет поля.

### `ZoneServiceStruct.DeleteBrigadeZone`

Загружает зону и бригаду, проверяет доступ и удаляет зону через хранилище.

### `ZoneServiceStruct.ListBrigadeZones`

Проверяет неархивную бригаду и доступ, затем возвращает ее зоны с фильтром активности.

### `ZoneServiceStruct.CheckBrigadeCoversPoint`

Проверяет координаты и возвращает признак попадания точки хотя бы в одну действующую зону и список совпавших зон.

### `ZoneServiceStruct.FindBrigadesByPoint`

Проверяет точку, подразделение, роли, навыки и страницу. Хранилище ищет бригады по пространственному пересечению и может оставить только доступные.

### `ZoneServiceStruct.getBrigadeForZoneOperation`

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
