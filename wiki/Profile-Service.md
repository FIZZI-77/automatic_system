# Сервис профилей (Profile Service)

## Ответственность

Личный профиль и отдельный рабочий профиль: подразделение, должность, статус, certificates и professional skills.

## Ключевое поведение

- Проверяет account через Auth и активность department через Department.
- Verified certificate создаёт skill grants; revoke/expiry отзывает связанные grants.
- Write operations используют idempotency с документированным сроком 24 часа.
- Authorization разделяет self-service, admin, dispatcher, HR/qualification-verifier и internal reads.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL. |
| Синхронные взаимодействия | Auth и Department. |
| Kafka | Publisher: `profiles.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Полные сигнатуры и структуры параметров приведены в [справочнике функций Profile Service](https://automaticsystem.youtrack.cloud/articles/ACS-A-40/Kod-i-funkcii-Profile-Service).

### `NewService`

```go
func NewService(repo *repository.Repository, deps Dependencies, logger *zap.Logger) *Service
```

Подставляет безопасный журнал при `nil` и собирает службы личных, рабочих, внутренних профилей и квалификаций с зависимостями `UserAccountChecker` и `DepartmentChecker`.

### `NewUserProfileServiceStruct`, `NewWorkProfileServiceStruct`, `NewProfileInternalServiceStruct`, `NewCertificationServiceStruct`

```go
func NewUserProfileServiceStruct(repo *repository.Repository, userChecker UserAccountChecker, logger *zap.Logger) *UserProfileServiceStruct
```

```go
func NewWorkProfileServiceStruct(repo *repository.Repository, departmentChecker DepartmentChecker, logger *zap.Logger) *WorkProfileServiceStruct
```

```go
func NewProfileInternalServiceStruct(repo *repository.Repository, logger *zap.Logger) *ProfileInternalServiceStruct
```

```go
func NewCertificationServiceStruct(repo *repository.Repository, logger *zap.Logger) *CertificationServiceStruct
```

Создают специализированные службы и сохраняют необходимые зависимости; каждый конструктор защищает методы от отсутствующего журнала.

### `UserProfileServiceStruct.CreateUserProfile`

```go
func (s *UserProfileServiceStruct) CreateUserProfile(ctx context.Context, in *models.CreateUserProfileInput) (*models.CreateUserProfileResult, error)
```

Проверяет UUID, имя, телефон и способ связи. Создавать профиль может сам пользователь или `admin`; при создании администратором дополнительно проверяется существование учетной записи. Команда идемпотентно создает профиль и событие.

### `UserProfileServiceStruct.GetUserProfileByID`

```go
func (s *UserProfileServiceStruct) GetUserProfileByID(ctx context.Context, in *models.GetUserProfileByIDInput) (*models.GetUserProfileByIDResult, error)
```

Загружает профиль по UUID и после получения владельца разрешает чтение только ему или администратору.

### `UserProfileServiceStruct.GetUserProfileByUserID`

```go
func (s *UserProfileServiceStruct) GetUserProfileByUserID(ctx context.Context, in *models.GetUserProfileByUserIDInput) (*models.GetUserProfileByUserIDResult, error)
```

До обращения к хранилищу требует совпадения исполнителя с `UserID` либо роль `admin`.

### `UserProfileServiceStruct.GetMyUserProfile`

```go
func (s *UserProfileServiceStruct) GetMyUserProfile(ctx context.Context, in *models.GetMyUserProfileInput) (*models.GetMyUserProfileResult, error)
```

Требует ненулевой `ActorUserID`, ищет профиль по нему и преобразует результат в `GetMyUserProfileResult`.

### `UserProfileServiceStruct.ListUserProfiles`

```go
func (s *UserProfileServiceStruct) ListUserProfiles(ctx context.Context, in *models.ListUserProfilesInput) (*models.ListUserProfilesResult, error)
```

Разрешен только администратору. Нормализует сортировку и страницу, применяет текстовый поиск и возвращает список с общим количеством.

### `UserProfileServiceStruct.UpdateUserProfile`

```go
func (s *UserProfileServiceStruct) UpdateUserProfile(ctx context.Context, in *models.UpdateUserProfileInput) (*models.UpdateUserProfileResult, error)
```

Проверяет изменяемые поля, загружает текущий профиль и разрешает изменение владельцу или администратору. Идемпотентная команда обновляет данные; отдельные флаги явно очищают телефон и изображение.

### `WorkProfileServiceStruct.CreateWorkProfile`

```go
func (s *WorkProfileServiceStruct) CreateWorkProfile(ctx context.Context, in *models.CreateWorkProfileInput) (*models.CreateWorkProfileResult, error)
```

Требует `admin`, существующий личный профиль и активное подразделение. После проверок идемпотентно создает рабочий профиль и его начальную историю.

### `WorkProfileServiceStruct.GetWorkProfileByID`, `WorkProfileServiceStruct.GetWorkProfileByUserID`

```go
func (s *WorkProfileServiceStruct) GetWorkProfileByID(ctx context.Context, in *models.GetWorkProfileByIDInput) (*models.GetWorkProfileByIDResult, error)
```

```go
func (s *WorkProfileServiceStruct) GetWorkProfileByUserID(ctx context.Context, in *models.GetWorkProfileByUserIDInput) (*models.GetWorkProfileByUserIDResult, error)
```

Загружают объединенные данные и вызывают `ensureCanReadWorkProfile`: владелец, `admin`, кадровая роль и диспетчер того же подразделения имеют доступ.

### `WorkProfileServiceStruct.ListWorkProfiles`

```go
func (s *WorkProfileServiceStruct) ListWorkProfiles(ctx context.Context, in *models.ListWorkProfilesInput) (*models.ListWorkProfilesResult, error)
```

Администратор сохраняет переданный фильтр. Диспетчер обязан иметь рабочий профиль; его подразделение вычисляется и принудительно подставляется в запрос. Остальным доступ запрещен.

### `WorkProfileServiceStruct.UpdateWorkProfile`

```go
func (s *WorkProfileServiceStruct) UpdateWorkProfile(ctx context.Context, in *models.UpdateWorkProfileInput) (*models.UpdateWorkProfileResult, error)
```

Требует `admin`, проверяет табельный номер и должность и идемпотентно выполняет частичное обновление.

### `WorkProfileServiceStruct.DeactivateWorkProfile`

```go
func (s *WorkProfileServiceStruct) DeactivateWorkProfile(ctx context.Context, in *models.DeactivateWorkProfileInput) (*models.DeactivateWorkProfileResult, error)
```

Требует `admin` и причину, переводит профиль в `INACTIVE`, устанавливает время деактивации, историю и событие.

### `WorkProfileServiceStruct.ChangeWorkProfileDepartment`

```go
func (s *WorkProfileServiceStruct) ChangeWorkProfileDepartment(ctx context.Context, in *models.ChangeWorkProfileDepartmentInput) (*models.ChangeWorkProfileDepartmentResult, error)
```

Требует `admin`, проверяет активность нового подразделения и идемпотентно переносит профиль с фиксацией причины.

### `WorkProfileServiceStruct.SetWorkProfileStatus`

```go
func (s *WorkProfileServiceStruct) SetWorkProfileStatus(ctx context.Context, in *models.SetWorkProfileStatusInput) (*models.SetWorkProfileStatusResult, error)
```

Администратор может устанавливать поддерживаемое состояние. Сам работник ограничен переходами, которые разрешает `isWorkerStatusTransitionAllowed`; команда фиксирует историю и событие.

### `WorkProfileServiceStruct.GetWorkProfileStatusHistory`

```go
func (s *WorkProfileServiceStruct) GetWorkProfileStatusHistory(ctx context.Context, in *models.GetWorkProfileStatusHistoryInput) (*models.GetWorkProfileStatusHistoryResult, error)
```

Загружает профиль для проверки прав и возвращает страницу истории его состояний.

### `WorkProfileServiceStruct.ensureCanReadWorkProfile`

```go
func (s *WorkProfileServiceStruct) ensureCanReadWorkProfile(ctx context.Context, actorUserID *uuid.UUID, roles []string, details *models.WorkProfileDetails) error
```

```go
func (s *CertificationServiceStruct) ensureCanReadWorkProfile(ctx context.Context, workProfileID uuid.UUID, actorUserID *uuid.UUID, roles []string) error
```

Разрешает владельца, администратора и кадровую роль. Для диспетчера вычисляет его подразделение и сравнивает с подразделением читаемого профиля.

### `WorkProfileServiceStruct.actorDepartmentID`

```go
func (s *WorkProfileServiceStruct) actorDepartmentID(ctx context.Context, actorUserID *uuid.UUID) (uuid.UUID, error)
```

```go
func (s *CertificationServiceStruct) actorDepartmentID(ctx context.Context, actorUserID *uuid.UUID) (uuid.UUID, error)
```

Требует `ActorUserID`, вызывает `ResolveWorkingDepartment` и возвращает `DepartmentID`.

### `WorkProfileServiceStruct.ensureDepartmentActive`

```go
func (s *WorkProfileServiceStruct) ensureDepartmentActive(ctx context.Context, departmentID uuid.UUID, method string) error
```

Если проверяющий подразделения задан, вызывает его; ошибку оборачивает именем операции.

### `isWorkerStatusTransitionAllowed`

```go
func isWorkerStatusTransitionAllowed(from models.WorkProfileStatus, to models.WorkProfileStatus) bool
```

Ограничивает самостоятельные переходы работника теми парами состояний, которые явно перечислены в коде; остальные переходы доступны только администратору.

### `ProfileInternalServiceStruct.ResolveWorkingDepartment`

```go
func (s *ProfileInternalServiceStruct) ResolveWorkingDepartment(ctx context.Context, in *models.ResolveWorkingDepartmentInput) (*models.ResolveWorkingDepartmentResult, error)
```

По `UserID` возвращает личный и рабочий профиль, подразделение, состояние и рассчитанный `CanOperate`.

### `ProfileInternalServiceStruct.CheckProfileCanJoinBrigade`

```go
func (s *ProfileInternalServiceStruct) CheckProfileCanJoinBrigade(ctx context.Context, in *models.CheckProfileCanJoinBrigadeInput) (*models.CheckProfileCanJoinBrigadeResult, error)
```

Ищет профиль по пользователю или рабочему профилю и возвращает не ошибку доступа, а `Allowed` с точной причиной: отсутствие/состояние профиля либо несовпадение подразделения.

### `CertificationServiceStruct.CreateCertificationType`

```go
func (s *CertificationServiceStruct) CreateCertificationType(ctx context.Context, in *models.CreateCertificationTypeInput) (*models.CreateCertificationTypeResult, error)
```

Требует `admin`, проверяет код, название и положительный срок и идемпотентно создает вид сертификата.

### `CertificationServiceStruct.UpdateCertificationType`

```go
func (s *CertificationServiceStruct) UpdateCertificationType(ctx context.Context, in *models.UpdateCertificationTypeInput) (*models.UpdateCertificationTypeResult, error)
```

Требует `admin`, хотя бы одно изменение и корректные значения. Флаги очистки позволяют отличить очистку от отсутствия поля.

### `CertificationServiceStruct.ListCertificationTypes`

```go
func (s *CertificationServiceStruct) ListCertificationTypes(ctx context.Context, in *models.ListCertificationTypesInput) (*models.ListCertificationTypesResult, error)
```

Разрешает администратору, кадровой роли, диспетчеру и внутреннему вызову читать справочник с фильтрами и страницей.

### `CertificationServiceStruct.AddCertificationTypeSkill`

```go
func (s *CertificationServiceStruct) AddCertificationTypeSkill(ctx context.Context, in *models.AddCertificationTypeSkillInput) (*models.AddCertificationTypeSkillResult, error)
```

Требует `admin`, проверяет идентификаторы и уровень, затем связывает вид сертификата с выдаваемым навыком.

### `CertificationServiceStruct.RemoveCertificationTypeSkill`

```go
func (s *CertificationServiceStruct) RemoveCertificationTypeSkill(ctx context.Context, in *models.RemoveCertificationTypeSkillInput) error
```

Требует `admin` и деактивирует связь вида сертификата с навыком.

### `CertificationServiceStruct.ListCertificationTypeSkills`

```go
func (s *CertificationServiceStruct) ListCertificationTypeSkills(ctx context.Context, in *models.ListCertificationTypeSkillsInput) (*models.ListCertificationTypeSkillsResult, error)
```

Проверяет право чтения справочника и возвращает навыки вида, при необходимости только активные.

### `CertificationServiceStruct.UploadWorkProfileCertification`

```go
func (s *CertificationServiceStruct) UploadWorkProfileCertification(ctx context.Context, in *models.UploadWorkProfileCertificationInput) (*models.UploadWorkProfileCertificationResult, error)
```

Проверяет реквизиты и даты, затем `ensureCertificationCanBeUploaded`: вид должен быть активным, обязательный файл присутствовать, срок быть будущим, рабочий профиль — не `INACTIVE`/`SUSPENDED`, а исполнитель — владельцем, администратором или кадровой ролью. Сертификат создается как `PENDING`.

### `CertificationServiceStruct.VerifyWorkProfileCertification`

```go
func (s *CertificationServiceStruct) VerifyWorkProfileCertification(ctx context.Context, in *models.VerifyWorkProfileCertificationInput) (*models.VerifyWorkProfileCertificationResult, error)
```

Требует кадровую роль или администратора. Идемпотентно переводит сертификат в `VERIFIED`, фиксирует проверяющего и создает активные выдачи всех навыков действующих связей вида сертификата.

### `CertificationServiceStruct.RejectWorkProfileCertification`

```go
func (s *CertificationServiceStruct) RejectWorkProfileCertification(ctx context.Context, in *models.RejectWorkProfileCertificationInput) (*models.RejectWorkProfileCertificationResult, error)
```

Требует кадровую роль или администратора и непустую причину; переводит ожидающий сертификат в `REJECTED`.

### `CertificationServiceStruct.RevokeWorkProfileCertification`

```go
func (s *CertificationServiceStruct) RevokeWorkProfileCertification(ctx context.Context, in *models.RevokeWorkProfileCertificationInput) (*models.RevokeWorkProfileCertificationResult, error)
```

Требует кадровую роль или администратора и причину; переводит сертификат в `REVOKED` и отзывает активные выдачи, созданные этим сертификатом.

### `CertificationServiceStruct.ExpireWorkProfileCertifications`

```go
func (s *CertificationServiceStruct) ExpireWorkProfileCertifications(ctx context.Context, in *models.ExpireWorkProfileCertificationsInput) (*models.ExpireWorkProfileCertificationsResult, error)
```

Системная пакетная операция выбирает до заданного предела проверенные сертификаты с прошедшим сроком, переводит их в `EXPIRED` и отзывает связанные навыки.

### `CertificationServiceStruct.ListWorkProfileCertifications`

```go
func (s *CertificationServiceStruct) ListWorkProfileCertifications(ctx context.Context, in *models.ListWorkProfileCertificationsInput) (*models.ListWorkProfileCertificationsResult, error)
```

Проверяет право чтения рабочего профиля, применяет фильтры вида и состояния и возвращает страницу сертификатов.

### `CertificationServiceStruct.GrantManualWorkProfileSkill`

```go
func (s *CertificationServiceStruct) GrantManualWorkProfileSkill(ctx context.Context, in *models.GrantManualWorkProfileSkillInput) (*models.GrantManualWorkProfileSkillResult, error)
```

Требует администратора или кадровую роль, проверяет навык, срок и причину и создает ручную выдачу `MANUAL`.

### `CertificationServiceStruct.RevokeWorkProfileSkillGrant`

```go
func (s *CertificationServiceStruct) RevokeWorkProfileSkillGrant(ctx context.Context, in *models.RevokeWorkProfileSkillGrantInput) (*models.RevokeWorkProfileSkillGrantResult, error)
```

Требует администратора или кадровую роль и причину; деактивирует выдачу и устанавливает `RevokedAt`.

### `CertificationServiceStruct.ListEffectiveWorkProfileSkills`

```go
func (s *CertificationServiceStruct) ListEffectiveWorkProfileSkills(ctx context.Context, in *models.ListEffectiveWorkProfileSkillsInput) (*models.ListEffectiveWorkProfileSkillsResult, error)
```

После проверки чтения возвращает только активные и неистекшие выдачи рабочего профиля.

### `CertificationServiceStruct.BatchListEffectiveWorkProfileSkills`

```go
func (s *CertificationServiceStruct) BatchListEffectiveWorkProfileSkills(ctx context.Context, in *models.BatchListEffectiveWorkProfileSkillsInput) (*models.BatchListEffectiveWorkProfileSkillsResult, error)
```

Принимает ограниченный уникальный список профилей. Разрешен администратору и внутреннему вызову; возвращает карту навыков по идентификаторам профилей.

### `CertificationServiceStruct.CheckWorkProfileHasSkills`

```go
func (s *CertificationServiceStruct) CheckWorkProfileHasSkills(ctx context.Context, in *models.CheckWorkProfileHasSkillsInput) (*models.CheckWorkProfileHasSkillsResult, error)
```

Проверяет право чтения и сравнивает действующие выдачи с `RequiredSkillIDs`; возвращает разрешение и отсутствующие навыки.

### `ensureCertificationCanBeUploaded`, `ensureCertificationTypeAcceptsUpload`, `ensureCanUploadCertification`, `ensureWorkProfileAcceptsCertification`

```go
func (s *CertificationServiceStruct) ensureCertificationCanBeUploaded(ctx context.Context, method string, in *models.UploadWorkProfileCertificationInput) error
```

```go
func ensureCertificationTypeAcceptsUpload(certificationType *models.CertificationType, in *models.UploadWorkProfileCertificationInput) error
```

```go
func ensureCanUploadCertification(method string, actorUserID *uuid.UUID, roles []string, details *models.WorkProfileDetails) error
```

```go
func ensureWorkProfileAcceptsCertification(method string, workProfile *models.WorkProfile) error
```

Последовательно загружают вид и профиль, проверяют активность вида, обязательность файла, будущий срок, права владельца/администратора/кадровой роли и допустимое состояние рабочего профиля.

### `CertificationServiceStruct.ensureCanReadWorkProfile`, `CertificationServiceStruct.actorDepartmentID`

Реализуют те же правила чтения: внутренний вызов, владелец, администратор, кадровая роль или диспетчер совпадающего подразделения.

### `requireCatalogReader`, `requireAdmin`, `requireAdminOrHR`, `isInternalCall`

```go
func requireCatalogReader(method string, actorUserID *uuid.UUID, roles []string) error
```

```go
func requireAdmin(method string, roles []string) error
```

```go
func requireAdminOrHR(method string, roles []string) error
```

```go
func isInternalCall(actorUserID *uuid.UUID, roles []string) bool
```

Проверяют роли для чтения справочника, административных действий и квалификаций. Внутренним считается вызов без пользователя и ролей.

### `withIdempotency`, `hashRequest`, `runCommand`, `runLoggedCommand`

```go
func withIdempotency[T any](
    ctx context.Context,
    repo *repository.Repository,
    operation string,
    actorKey string,
    request any,
    fn func(context.Context) (*T, uuid.UUID, error),
) (*T, error)
```

```go
func hashRequest(request any) (string, error)
```

```go
func runCommand[T any](
    ctx context.Context,
    repo *repository.Repository,
    method string,
    actorUserID *uuid.UUID,
    request any,
    command func(context.Context) (*T, uuid.UUID, error),
) (*T, error)
```

```go
func runLoggedCommand[T any](
    ctx context.Context,
    logger *zap.Logger,
    repo *repository.Repository,
    method string,
    actorUserID *uuid.UUID,
    request any,
    fields []zap.Field,
    command func(context.Context) (*T, uuid.UUID, error),
    successFields func(*T) []zap.Field,
) (*T, error)
```

`hashRequest` вычисляет SHA-256 JSON-запроса. `withIdempotency` выполняет новую команду в транзакции либо возвращает сохраненный ответ/конфликт/состояние обработки. `runCommand` добавляет имя операции и исполнителя, а `runLoggedCommand` также пишет начало, успех или ошибку.

### `validationError`, `hasRole`, `isAdmin`, `isDispatcher`, `isHR`, `actorKey`, `isSelf`, `permissionDenied`, `wrapServiceError`

```go
func validationError(method string, err error) error
```

```go
func hasRole(roles []string, allowed ...string) bool
```

```go
func isAdmin(roles []string) bool
```

```go
func isDispatcher(roles []string) bool
```

```go
func isHR(roles []string) bool
```

```go
func actorKey(actorUserID *uuid.UUID) string
```

```go
func isSelf(actorUserID *uuid.UUID, userID uuid.UUID) bool
```

```go
func permissionDenied(method string) error
```

```go
func wrapServiceError(method string, err error) error
```

Формируют единообразные ошибки и реализуют нечувствительную к регистру проверку ролей. Системный исполнитель получает ключ `system`.

### `startOperation`, `logValidationFailed`, `logPermissionDenied`, `logOperationFailed`, `logOperationSuccess`, `runLoggedQuery`

```go
func startOperation(ctx context.Context, logger *zap.Logger, method string, fields ...zap.Field) (*zap.Logger, time.Time)
```

```go
func logValidationFailed(logger *zap.Logger, method string, start time.Time, err error, fields ...zap.Field)
```

```go
func logPermissionDenied(logger *zap.Logger, method string, start time.Time, fields ...zap.Field)
```

```go
func logOperationFailed(logger *zap.Logger, method string, start time.Time, err error, fields ...zap.Field)
```

```go
func logOperationSuccess(logger *zap.Logger, method string, start time.Time, fields ...zap.Field)
```

```go
func runLoggedQuery[T any](
    ctx context.Context,
    logger *zap.Logger,
    method string,
    fields []zap.Field,
    query func() (*T, error),
    successFields func(*T) []zap.Field,
) (*T, error)
```

Добавляют `request_id`, время выполнения и поля операции в структурированный журнал. `runLoggedQuery` объединяет выполнение читающего запроса, оборачивание ошибки и запись результата.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
