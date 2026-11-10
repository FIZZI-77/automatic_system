# Сервис бригад (Brigade Service)

## Ответственность

Бригады, участники, skills, schedules, service zones и operational readiness.

## Ключевое поведение

- При добавлении участника запрашивает Profile, получает canonical user/profile IDs и snapshot действующих skills.
- Один user/profile не должен одновременно состоять в нескольких активных membership records.
- Архивная бригада не изменяет composition, skills, schedule и zones.
- Хранит историю ключевых изменений и использует outbox.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL. |
| Синхронные взаимодействия | Profile и Department. |
| Kafka | Publisher: `brigades.events.v1`; consumers: `profiles.events.v1`, `routing.events.v1`, `tickets.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Полные сигнатуры и структуры параметров приведены в [справочнике функций Brigade Service](https://automaticsystem.youtrack.cloud/articles/ACS-A-39/Kod-i-funkcii-Brigade-Service).

### `NewService`

```go
func NewService(repo *repository.Repo, departmentClient departmentv1.DepartmentServiceClient, logger *zap.Logger) *Service
```

Вызывает `NewServiceWithProfile` без клиента профилей.

### `NewServiceWithProfile`

```go
func NewServiceWithProfile(repo *repository.Repo, departmentClient departmentv1.DepartmentServiceClient, profileClient profilev1.ProfileServiceClient, logger *zap.Logger) *Service
```

Подставляет журнал без вывода при `nil` и собирает единый `Service` из служб бригад, участников, навыков, расписания и зон. При наличии клиента профилей участники создаются через строгую проверку профиля.

### `NewBrigadeService`, `NewMemberServiceStruct`, `NewMemberServiceStructWithProfile`

```go
func NewBrigadeService(repo *repository.Repo, departmentClient departmentv1.DepartmentServiceClient, log *zap.Logger) *BrigadeServiceStruct
```

```go
func NewMemberServiceStruct(repo *repository.Repo, log *zap.Logger) *MemberServiceStruct
```

```go
func NewMemberServiceStructWithProfile(repo *repository.Repo, profileClient profilev1.ProfileServiceClient, log *zap.Logger) *MemberServiceStruct
```

Создают службы и сохраняют зависимости. Вариант `WithProfile` устанавливает `requireProfile=true`, поэтому отсутствие клиента считается недоступностью зависимости.

### `NewSkillServiceStruct`, `NewScheduleServiceStruct`, `NewZoneServiceStruct`

```go
func NewSkillServiceStruct(repo *repository.Repo, log *zap.Logger) *SkillServiceStruct
```

```go
func NewScheduleServiceStruct(repo *repository.Repo, log *zap.Logger) *ScheduleServiceStruct
```

```go
func NewZoneServiceStruct(repo *repository.Repo, log *zap.Logger) *ZoneServiceStruct
```

Создают специализированные службы поверх общего хранилища и журнала.

### `BrigadeServiceStruct.CreateBrigade`

```go
func (b *BrigadeServiceStruct) CreateBrigade(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error)
```

Проверяет вход, права и подразделение. До записи трижды обращается к `Department Service` с тайм-аутом две секунды, растущей задержкой и случайной добавкой; продолжает только для активного подразделения. Затем создает бригаду, историю и событие через хранилище.

### `BrigadeServiceStruct.getDepartmentByIDWithRetry`

```go
func (b *BrigadeServiceStruct) getDepartmentByIDWithRetry(ctx context.Context, log *zap.Logger, departmentID uuid.UUID) (*departmentv1.GetDepartmentByIDResponse, error)
```

Повторяет только ошибки `Unavailable`, `DeadlineExceeded`, `ResourceExhausted`; учитывает отмену контекста. После последней попытки преобразует ошибку через `mapDepartmentServiceError`.

### `mapDepartmentServiceError`

```go
func mapDepartmentServiceError(err error) error
```

Преобразует отсутствие подразделения в `ErrNotFound`, временную недоступность и нехватку ресурсов — в `ErrDependencyUnavailable`, остальные ошибки оставляет без изменения.

### `isRetryableDepartmentError`

```go
func isRetryableDepartmentError(err error) bool
```

Возвращает `true` только для трех временных кодов gRPC, перечисленных выше.

### `BrigadeServiceStruct.GetBrigadeByID`

```go
func (b *BrigadeServiceStruct) GetBrigadeByID(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error)
```

Проверяет UUID, загружает бригаду и применяет правило администратора/диспетчера. Если оно не выполнено, разрешает чтение работнику, который активно состоит именно в этой бригаде.

### `BrigadeServiceStruct.ListBrigades`

```go
func (b *BrigadeServiceStruct) ListBrigades(ctx context.Context, in *models.ListBrigadesInput) (*models.ListBrigadesResult, error)
```

Разрешает запрос только `admin` или `dispatcher`. Для диспетчера принудительно заменяет фильтр подразделения на его `ActorDepartmentID`, затем передает нормализованные фильтры хранилищу.

### `BrigadeServiceStruct.UpdateBrigade`

```go
func (b *BrigadeServiceStruct) UpdateBrigade(ctx context.Context, in *models.UpdateBrigadeInput) (*models.UpdateBrigadeResult, error)
```

Проверяет запрос, загружает текущую бригаду для определения подразделения, проверяет права и выполняет частичное обновление. Конфликт активного названия возвращается как `ErrAlreadyExists`.

### `BrigadeServiceStruct.DeactivateBrigade`

```go
func (b *BrigadeServiceStruct) DeactivateBrigade(ctx context.Context, in *models.DeactivateBrigadeInput) (*models.DeactivateBrigadeResult, error)
```

Проверяет бригаду и права, подставляет `ActorUserID` в `ChangedByUserID`, если автор не указан, и переводит бригаду в неактивное состояние с причиной.

### `BrigadeServiceStruct.ArchiveBrigade`

```go
func (b *BrigadeServiceStruct) ArchiveBrigade(ctx context.Context, in *models.ArchiveBrigadeInput) (*models.ArchiveBrigadeResult, error)
```

Работает аналогично деактивации, но переводит запись в `ARCHIVED` и фиксирует время архивирования.

### `BrigadeServiceStruct.SetBrigadeStatus`

```go
func (b *BrigadeServiceStruct) SetBrigadeStatus(ctx context.Context, in *models.SetBrigadeStatusInput) (*models.SetBrigadeStatusResult, error)
```

Проверяет вход, загружает бригаду, проверяет права и готовность через `checkStatusReadiness`, подставляет автора и передает переход хранилищу. В журнал пишутся длительности этапов.

### `BrigadeServiceStruct.GetBrigadeStatusHistory`

```go
func (b *BrigadeServiceStruct) GetBrigadeStatusHistory(ctx context.Context, in *models.GetBrigadeStatusHistoryInput) (*models.GetBrigadeStatusHistoryResult, error)
```

Проверяет страницу и доступ к подразделению, затем возвращает историю переходов бригады.

### `BrigadeServiceStruct.GetAvailableBrigades`

```go
func (b *BrigadeServiceStruct) GetAvailableBrigades(ctx context.Context, in *models.GetAvailableBrigadesInput) (*models.GetAvailableBrigadesResult, error)
```

Проверяет подразделение, парность координат, требуемые навыки и роли, страницу, затем выбирает готовые бригады с учетом указанных условий.

### `BrigadeServiceStruct.CheckBrigadeCanHandleTicket`

```go
func (b *BrigadeServiceStruct) CheckBrigadeCanHandleTicket(ctx context.Context, in *models.CheckBrigadeCanHandleTicketInput) (*models.CheckBrigadeCanHandleTicketResult, error)
```

Передает проверенный идентификатор бригады, подразделение, точку и требования хранилищу. Возвращает `CanHandle` и конкретные причины отказа.

### `checkPermissionAndDepartmentForAdminAndDispatcher`

```go
func checkPermissionAndDepartmentForAdminAndDispatcher(log *zap.Logger, start time.Time, actorRoles []string, actorDepartmentID *uuid.UUID, departmentID uuid.UUID) error
```

Администратору разрешает действие сразу. Диспетчеру требует непустой `ActorDepartmentID`, совпадающий с подразделением объекта. Остальным возвращает `ErrPermissionDenied`.

### `BrigadeServiceStruct.checkStatusReadiness`

```go
func (b *BrigadeServiceStruct) checkStatusReadiness(ctx context.Context, log *zap.Logger, start time.Time, brigade *models.Brigade, targetStatus models.BrigadeStatus) error
```

Для `ACTIVE` требует готовность состава. Для `AVAILABLE` дополнительно запрещает исходные `INACTIVE` и `ARCHIVED` и требует полную готовность. Наличие причин превращает результат в `ErrBrigadeUnavailable`.

### `MemberServiceStruct.AddBrigadeMember`

```go
func (m *MemberServiceStruct) AddBrigadeMember(ctx context.Context, in *models.AddBrigadeMemberInput) (*models.AddBrigadeMemberResult, error)
```

Проверяет вход, бригаду и права. При включенной связи с профилями проверяет разрешение на вступление, заменяет идентификаторы каноническими и загружает действующие навыки. Затем запрещает второе активное членство пользователя, подставляет автора и сохраняет участника, историю, навыки и событие.

### `MemberServiceStruct.RemoveBrigadeMember`

```go
func (m *MemberServiceStruct) RemoveBrigadeMember(ctx context.Context, in *models.RemoveBrigadeMemberInput) (*models.RemoveBrigadeMemberResult, error)
```

Проверяет права и через `checkCanRemoveMember` не дает удалить последнего активного участника рабочей бригады. Затем деактивирует участника, фиксирует выход, историю и событие.

### `MemberServiceStruct.ChangeBrigadeMemberRole`

```go
func (m *MemberServiceStruct) ChangeBrigadeMemberRole(ctx context.Context, in *models.ChangeBrigadeMemberRoleInput) (*models.ChangeBrigadeMemberRoleResult, error)
```

Проверяет бригаду, права и новую роль, подставляет автора и сохраняет изменение вместе с прежней и новой ролью в истории.

### `MemberServiceStruct.SetBrigadeMemberAvailability`

```go
func (m *MemberServiceStruct) SetBrigadeMemberAvailability(ctx context.Context, in *models.SetBrigadeMemberAvailabilityInput) (*models.SetBrigadeMemberAvailabilityResult, error)
```

Проверяет состояние `AVAILABLE`/`UNAVAILABLE`, бригаду и права, подставляет автора, изменяет личную доступность и записывает отдельную историю с причиной.

### `MemberServiceStruct.ListBrigadeMembers`

```go
func (m *MemberServiceStruct) ListBrigadeMembers(ctx context.Context, in *models.ListBrigadeMembersInput) (*models.ListBrigadeMembersResult, error)
```

Администратор и диспетчер читают состав по общему правилу. Работник также может читать состав собственной активной бригады. Поддерживаются фильтры активности, роли и доступности.

### `MemberServiceStruct.GetBrigadeMemberHistory`

```go
func (m *MemberServiceStruct) GetBrigadeMemberHistory(ctx context.Context, in *models.GetBrigadeMemberHistoryInput) (*models.GetBrigadeMemberHistoryResult, error)
```

После проверки бригады и прав возвращает историю вступления, выхода и смены роли, при необходимости только для одного участника.

### `MemberServiceStruct.GetBrigadeMemberStatusHistory`

```go
func (m *MemberServiceStruct) GetBrigadeMemberStatusHistory(ctx context.Context, in *models.GetBrigadeMemberStatusHistoryInput) (*models.GetBrigadeMemberStatusHistoryResult, error)
```

Возвращает историю личной доступности участника с теми же правилами доступа и постраничным выводом.

### `MemberServiceStruct.GetBrigadeByUserID`

```go
func (m *MemberServiceStruct) GetBrigadeByUserID(ctx context.Context, in *models.GetBrigadeByUserIDInput) (*models.GetBrigadeByUserIDResult, error)
```

Проверяет `UserID` и возвращает бригаду вместе с записью участника; `OnlyActive` ограничивает поиск действующим членством.

### `MemberServiceStruct.getBrigadeForMemberOperation`

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

Загружает бригаду, оборачивает ошибку и запрещает любые операции над архивной бригадой.

### `MemberServiceStruct.checkCanRemoveMember`

```go
func (m *MemberServiceStruct) checkCanRemoveMember(ctx context.Context, log *zap.Logger, start time.Time, brigade *models.Brigade, in *models.RemoveBrigadeMemberInput) error
```

Для рабочего состояния загружает до двух активных участников. Если удаляемая запись — единственный активный участник, возвращает `ErrBrigadeUnavailable`.

### `brigadeStatusRequiresActiveMember`

```go
func brigadeStatusRequiresActiveMember(status models.BrigadeStatus) bool
```

Требует активного участника для `ACTIVE`, `AVAILABLE`, `BUSY`, `ON_ROUTE`, `ON_SITE`, `OFFLINE`; для `INACTIVE` и `ARCHIVED` не требует.

### `SkillServiceStruct.CreateSkill`

```go
func (s *SkillServiceStruct) CreateSkill(ctx context.Context, in *models.CreateSkillInput) (*models.CreateSkillResult, error)
```

Требует роль `admin`, проверяет код, название и описание, затем создает навык.

### `SkillServiceStruct.UpdateSkill`

```go
func (s *SkillServiceStruct) UpdateSkill(ctx context.Context, in *models.UpdateSkillInput) (*models.UpdateSkillResult, error)
```

Требует `admin`, хотя бы одно изменяемое поле и корректные значения; затем обновляет навык.

### `SkillServiceStruct.DeactivateSkill`

```go
func (s *SkillServiceStruct) DeactivateSkill(ctx context.Context, in *models.DeactivateSkillInput) (*models.DeactivateSkillResult, error)
```

Требует `admin` и переводит навык в неактивное состояние без физического удаления.

### `SkillServiceStruct.ListSkills`

```go
func (s *SkillServiceStruct) ListSkills(ctx context.Context, in *models.ListSkillsInput) (*models.ListSkillsResult, error)
```

Разрешен `admin` и `dispatcher`; применяет фильтр активности, текстовый поиск и страницу.

### `SkillServiceStruct.AddBrigadeSkill`

```go
func (s *SkillServiceStruct) AddBrigadeSkill(ctx context.Context, in *models.AddBrigadeSkillInput) (*models.AddBrigadeSkillResult, error)
```

Проверяет неархивную бригаду и доступ к ее подразделению, затем добавляет или восстанавливает связь навыка.

### `SkillServiceStruct.RemoveBrigadeSkill`

```go
func (s *SkillServiceStruct) RemoveBrigadeSkill(ctx context.Context, in *models.RemoveBrigadeSkillInput) (*models.RemoveBrigadeSkillResult, error)
```

Проверяет те же условия и деактивирует связь навыка с бригадой.

### `SkillServiceStruct.ListBrigadeSkills`

```go
func (s *SkillServiceStruct) ListBrigadeSkills(ctx context.Context, in *models.ListBrigadeSkillsInput) (*models.ListBrigadeSkillsResult, error)
```

Проверяет бригаду и права, затем возвращает ее навыки с необязательным фильтром активности.

### `SkillServiceStruct.getBrigadeForSkillOperation`

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

Загружает бригаду и запрещает работу с навыками архивной бригады.

### `checkAdminRole`, `checkAdminOrDispatcherRole`

```go
func checkAdminRole(log *zap.Logger, start time.Time, actorRoles []string) error
```

```go
func checkAdminOrDispatcherRole(log *zap.Logger, start time.Time, actorRoles []string) error
```

Первая функция разрешает только `admin`; вторая — `admin` или `dispatcher`. При отказе пишут предупреждение и возвращают `ErrPermissionDenied`.

### `ScheduleServiceStruct.SetBrigadeSchedule`

```go
func (s *ScheduleServiceStruct) SetBrigadeSchedule(ctx context.Context, in *models.SetBrigadeScheduleInput) (*models.SetBrigadeScheduleResult, error)
```

Проверяет каждый день, время, часовой пояс и период действия, затем проверяет неархивную бригаду и права. Хранилище заменяет расписание набором переданных строк.

### `ScheduleServiceStruct.ListBrigadeSchedule`

```go
func (s *ScheduleServiceStruct) ListBrigadeSchedule(ctx context.Context, in *models.ListBrigadeScheduleInput) (*models.ListBrigadeScheduleResult, error)
```

Администратор и диспетчер читают расписание по общему правилу; участник может прочитать расписание своей активной бригады. Поддерживается фильтр активности.

### `ScheduleServiceStruct.getBrigadeForScheduleOperation`

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

Загружает бригаду и запрещает расписание архивной бригады.

### `ZoneServiceStruct.CreateBrigadeZone`

```go
func (z *ZoneServiceStruct) CreateBrigadeZone(ctx context.Context, in *models.CreateBrigadeZoneInput) (*models.CreateBrigadeZoneResult, error)
```

Проверяет UUID, название, GeoJSON, координатную структуру и приоритет. Требует совпадения подразделения зоны и бригады, затем проверяет права и сохраняет географию.

### `ZoneServiceStruct.UpdateBrigadeZone`

```go
func (z *ZoneServiceStruct) UpdateBrigadeZone(ctx context.Context, in *models.UpdateBrigadeZoneInput) (*models.UpdateBrigadeZoneResult, error)
```

Загружает зону, по ней определяет бригаду и подразделение, проверяет права и частично обновляет поля.

### `ZoneServiceStruct.DeleteBrigadeZone`

```go
func (z *ZoneServiceStruct) DeleteBrigadeZone(ctx context.Context, in *models.DeleteBrigadeZoneInput) (*models.DeleteBrigadeZoneResult, error)
```

Загружает зону и бригаду, проверяет доступ и удаляет зону через хранилище.

### `ZoneServiceStruct.ListBrigadeZones`

```go
func (z *ZoneServiceStruct) ListBrigadeZones(ctx context.Context, in *models.ListBrigadeZonesInput) (*models.ListBrigadeZonesResult, error)
```

Проверяет неархивную бригаду и доступ, затем возвращает ее зоны с фильтром активности.

### `ZoneServiceStruct.CheckBrigadeCoversPoint`

```go
func (z *ZoneServiceStruct) CheckBrigadeCoversPoint(ctx context.Context, in *models.CheckBrigadeCoversPointInput) (*models.CheckBrigadeCoversPointResult, error)
```

Проверяет координаты и возвращает признак попадания точки хотя бы в одну действующую зону и список совпавших зон.

### `ZoneServiceStruct.FindBrigadesByPoint`

```go
func (z *ZoneServiceStruct) FindBrigadesByPoint(ctx context.Context, in *models.FindBrigadesByPointInput) (*models.FindBrigadesByPointResult, error)
```

Проверяет точку, подразделение, роли, навыки и страницу. Хранилище ищет бригады по пространственному пересечению и может оставить только доступные.

### `ZoneServiceStruct.getBrigadeForZoneOperation`

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

Загружает бригаду для операции с зоной и запрещает архивную запись.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Brigade_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
