# Сервис профилей (Profile Service)

## Общее описание и общий принцип работы

`Profile Service` хранит личные данные пользователя и отдельный рабочий профиль сотрудника. Личный профиль содержит имя, телефон, изображение и предпочитаемый способ связи. Рабочий профиль связывает человека с подразделением, должностью, табельным номером, рабочим состоянием, сертификатами и профессиональными навыками.

Сервис проверяет существование учетной записи через `UserAccountChecker`, активность подразделения через `DepartmentChecker`, а изменения записывает вместе с событиями в `outbox_events`. Изменяющие операции используют ключ идемпотентности сроком 24 часа.

Права распределены так:

- пользователь читает и изменяет собственный личный профиль;
- `admin` управляет личными и рабочими профилями и справочником сертификатов;
- `dispatcher` читает рабочие профили только своего подразделения;
- `hr` и `qualification_verifier` проверяют сертификаты и управляют квалификациями;
- внутренний вызов без пользователя и ролей может читать данные, необходимые другим сервисам.

Проверенный сертификат создает выдачи навыков, связанные с типом сертификата. Отклонение не создает навыков, отзыв или истечение сертификата отзывает связанные выдачи. Ручная выдача имеет `SourceType=MANUAL`, а выдача от сертификата — `CERTIFICATION`.

## Модели

### Перечисления

| Тип | Значения | Назначение |
|---|---|---|
| `PreferredContactMethod` | `EMAIL`, `PHONE`, `PUSH` | Предпочитаемый способ связи. |
| `WorkProfileStatus` | `ACTIVE`, `INACTIVE`, `ON_SHIFT`, `OFF_SHIFT`, `SUSPENDED` | Состояние рабочего профиля. |
| `UserProfileSortBy` | `created_at`, `updated_at`, `full_name` | Сортировка личных профилей. |
| `WorkProfileSortBy` | `created_at`, `updated_at`, `full_name`, `position`, `status`, `employee_number` | Сортировка рабочих профилей. |
| `SortOrder` | `asc`, `desc` | Направление сортировки. |
| `CanJoinBrigadeReason` | `ALLOWED`, `NO_WORK_PROFILE`, `PROFILE_INACTIVE`, `PROFILE_SUSPENDED`, `PROFILE_OFF_SHIFT`, `DEPARTMENT_MISMATCH` | Причина разрешения или запрета вступления в бригаду. |
| `OutboxEventStatus` | `PENDING`, `PROCESSING`, `SENT`, `FAILED` | Состояние доставки события. |
| `CertificationStatus` | `PENDING`, `VERIFIED`, `REJECTED`, `EXPIRED`, `REVOKED` | Состояние сертификата. |
| `SkillGrantSourceType` | `MANUAL`, `CERTIFICATION` | Источник выдачи навыка. |

### Основные сущности

| Структура | Поле | Тип Go | Назначение |
|---|---|---|---|
| `UserProfile` | `ID`, `UserID` | `uuid.UUID` | Профиль и учетная запись. |
| `UserProfile` | `FullName` | `string` | Полное имя длиной 2–255 символов. |
| `UserProfile` | `Phone` | `*string` | Телефон в международном формате. |
| `UserProfile` | `AvatarFileID` | `*uuid.UUID` | Файл изображения. |
| `UserProfile` | `PreferredContactMethod` | `PreferredContactMethod` | Способ связи; `PHONE` требует телефон. |
| `UserProfile` | `CreatedAt`, `UpdatedAt` | `time.Time` | Создание и изменение. |
| `WorkProfile` | `ID`, `UserProfileID`, `DepartmentID` | `uuid.UUID` | Рабочий профиль, личный профиль и подразделение. |
| `WorkProfile` | `EmployeeNumber` | `*string` | Табельный номер. |
| `WorkProfile` | `Position` | `string` | Должность. |
| `WorkProfile` | `Status` | `WorkProfileStatus` | Рабочее состояние. |
| `WorkProfile` | `DeactivatedAt` | `*time.Time` | Время деактивации. |
| `WorkProfile` | `CreatedAt`, `UpdatedAt` | `time.Time` | Создание и изменение. |
| `WorkProfileDetails` | `WorkProfile`, `UserProfile` | указатели | Объединенные рабочие и личные данные. |
| `WorkProfileStatusHistory` | `ID`, `WorkProfileID` | `uuid.UUID` | Запись и рабочий профиль. |
| `WorkProfileStatusHistory` | `FromStatus`, `ToStatus` | указатель и значение | Предыдущее и новое состояние. |
| `WorkProfileStatusHistory` | `Reason` | `string` | Причина. |
| `WorkProfileStatusHistory` | `ChangedByUserID`, `RequestID`, `CreatedAt` | указатели, время | Автор, запрос и время перехода. |
| `OutboxEvent` | `ID`, `AggregateID` | `uuid.UUID` | Событие и сущность. |
| `OutboxEvent` | `AggregateType`, `EventType` | `string` | Вид сущности и события. |
| `OutboxEvent` | `Payload` | `[]byte` | JSON-данные. |
| `OutboxEvent` | `Status`, `Attempts`, `LastError` | состояние, число, строка | Ход доставки. |
| `OutboxEvent` | `NextAttemptAt`, `LockedAt`, `CreatedAt`, `SentAt` | время | Планирование и обработка. |

### Сертификаты и навыки

| Структура | Поля и назначение |
|---|---|
| `CertificationType` | `ID` — вид; `Code`, `Name`, `Description` — справочные данные; `DefaultValidityDays` — срок по умолчанию; `RequiresFile` — обязательность файла; `Active` — доступность; `CreatedAt`, `UpdatedAt` — время. |
| `CertificationTypeSkill` | `ID`, `CertificationTypeID`, `SkillID` — связь; `ProficiencyLevel` — уровень; `Active` — действие; `CreatedAt`, `UpdatedAt` — время. |
| `WorkProfileCertification` | `ID`, `WorkProfileID`, `CertificationTypeID` — связи; `CertificateNumber`, `Issuer`, `IssuedAt`, `ExpiresAt` — реквизиты; `Status` — состояние; `CertificateFileID` — документ; `VerifiedByUserID`, `VerifiedAt` — проверка; `RejectionReason` — причина отказа; `CreatedAt`, `UpdatedAt` — время. |
| `WorkProfileSkillGrant` | `ID`, `WorkProfileID`, `SkillID` — выдача; `SourceType`, `SourceID` — источник; `ProficiencyLevel`, `ValidUntil` — уровень и срок; `Active`, `CreatedAt`, `RevokedAt` — состояние и время. |

### Запросы личного профиля

| Структура | Поля и назначение |
|---|---|
| `CreateUserProfileInput` | `UserID`, `FullName`, `Phone`, `AvatarFileID`, `PreferredContactMethod`; `ActorUserID`, `ActorRoles`. |
| `GetUserProfileByIDInput` | `ID`, `ActorUserID`, `ActorRoles`. |
| `GetUserProfileByUserIDInput` | `UserID`, `ActorUserID`, `ActorRoles`. |
| `GetMyUserProfileInput` | `ActorUserID`. |
| `ListUserProfilesInput` | `Query`, `SortBy`, `SortOrder`, `Limit`, `Offset`, данные исполнителя. |
| `UpdateUserProfileInput` | `ID`; изменяемые `FullName`, `Phone`, `AvatarFileID`, `PreferredContactMethod`; флаги `ClearPhone`, `ClearAvatarFileID`; данные исполнителя. |

Результаты содержат `UserProfile`; список содержит `UserProfiles` и `Total`.

Явные типы результатов: `CreateUserProfileResult`, `GetUserProfileByIDResult`, `GetUserProfileByUserIDResult`, `GetMyUserProfileResult` и `UpdateUserProfileResult` содержат `UserProfile`; `ListUserProfilesResult` содержит `UserProfiles` и `Total`.

### Запросы рабочего профиля

| Структура | Поля и назначение |
|---|---|
| `CreateWorkProfileInput` | `UserProfileID`, `DepartmentID`, `EmployeeNumber`, `Position`, данные исполнителя. |
| `GetWorkProfileByIDInput`, `GetWorkProfileByUserIDInput` | идентификатор профиля или пользователя и данные исполнителя. |
| `ListWorkProfilesInput` | `DepartmentID`, `Status`, `Query`, сортировка, страница и данные исполнителя. |
| `UpdateWorkProfileInput` | `ID`, `EmployeeNumber`, `ClearEmployeeNumber`, `Position`, данные исполнителя. |
| `DeactivateWorkProfileInput` | `ID`, `Reason`, данные исполнителя. |
| `ChangeWorkProfileDepartmentInput` | `ID`, новый `DepartmentID`, `Reason`, данные исполнителя. |
| `SetWorkProfileStatusInput` | `ID`, `Status`, `Reason`, данные исполнителя. |
| `GetWorkProfileStatusHistoryInput` | `WorkProfileID`, `Limit`, `Offset`, данные исполнителя. |

Результаты содержат `WorkProfileDetails`; история содержит `History` и `Total`.

Типы `CreateWorkProfileResult`, `GetWorkProfileByIDResult`, `GetWorkProfileByUserIDResult`, `UpdateWorkProfileResult`, `DeactivateWorkProfileResult`, `ChangeWorkProfileDepartmentResult` и `SetWorkProfileStatusResult` содержат `Details`. `ListWorkProfilesResult` содержит `WorkProfiles` и `Total`, а `GetWorkProfileStatusHistoryResult` — `History` и `Total`.

### Внутренние запросы

| Структура | Поля и назначение |
|---|---|
| `ResolveWorkingDepartmentInput` | `UserID` — пользователь. |
| `ResolveWorkingDepartmentResult` | `UserProfileID`, `WorkProfileID`, `UserID`, `DepartmentID`, `WorkProfileStatus`, `CanOperate` — найденная рабочая принадлежность и возможность выполнять операции. |
| `CheckProfileCanJoinBrigadeInput` | один из `UserID`/`WorkProfileID` и `BrigadeDepartmentID`. |
| `CheckProfileCanJoinBrigadeResult` | идентификаторы профилей, пользователя и подразделения, `Allowed` и `Reason`. |

### Запросы сертификатов и навыков

| Структура | Поля и назначение |
|---|---|
| `CreateCertificationTypeInput` | `Code`, `Name`, `Description`, `DefaultValidityDays`, `RequiresFile`, данные исполнителя. |
| `UpdateCertificationTypeInput` | `ID`; изменяемые справочные поля; `ClearDescription`, `ClearValidityDays`; данные исполнителя. |
| `ListCertificationTypesInput` | `Active`, `Query`, `Limit`, `Offset`, данные исполнителя. |
| `AddCertificationTypeSkillInput` | `CertificationTypeID`, `SkillID`, `ProficiencyLevel`, данные исполнителя. |
| `RemoveCertificationTypeSkillInput` | `CertificationTypeID`, `SkillID`, данные исполнителя. |
| `ListCertificationTypeSkillsInput` | `CertificationTypeID`, `ActiveOnly`, данные исполнителя. |
| `UploadWorkProfileCertificationInput` | профиль, вид, номер, издатель, даты, файл и данные исполнителя. |
| `VerifyWorkProfileCertificationInput` | `ID`, данные проверяющего. Результат содержит сертификат и `SkillGrants`. |
| `RejectWorkProfileCertificationInput` | `ID`, обязательный `RejectionReason`, данные проверяющего. |
| `RevokeWorkProfileCertificationInput` | `ID`, `Reason`, данные исполнителя. Результат содержит сертификат и `RevokedGrants`. |
| `ExpireWorkProfileCertificationsInput` | `Limit`, данные системного исполнителя. Результат содержит истекшие сертификаты и отозванные навыки. |
| `ListWorkProfileCertificationsInput` | профиль, фильтры вида и состояния, страница, данные исполнителя. |
| `GrantManualWorkProfileSkillInput` | профиль, навык, уровень, срок, причина, данные исполнителя. |
| `RevokeWorkProfileSkillGrantInput` | `ID`, `Reason`, данные исполнителя. |
| `ListEffectiveWorkProfileSkillsInput` | `WorkProfileID`, данные исполнителя. |
| `BatchListEffectiveWorkProfileSkillsInput` | уникальный список `WorkProfileIDs` и данные исполнителя; результат — карта выдач по профилю. |
| `CheckWorkProfileHasSkillsInput` | профиль, `RequiredSkillIDs`, данные исполнителя; результат — `Allowed` и `MissingSkillIDs`. |

Результирующие типы квалификаций: `CreateCertificationTypeResult`, `UpdateCertificationTypeResult`, `ListCertificationTypesResult`, `AddCertificationTypeSkillResult`, `ListCertificationTypeSkillsResult`, `UploadWorkProfileCertificationResult`, `VerifyWorkProfileCertificationResult`, `RejectWorkProfileCertificationResult`, `RevokeWorkProfileCertificationResult`, `ExpireWorkProfileCertificationsResult`, `ListWorkProfileCertificationsResult`, `GrantManualWorkProfileSkillResult`, `RevokeWorkProfileSkillGrantResult`, `ListEffectiveWorkProfileSkillsResult`, `BatchListEffectiveWorkProfileSkillsResult` и `CheckWorkProfileHasSkillsResult`. Их поля описаны в строках соответствующих входных моделей: сущность, список, `Total`, карта либо результат проверки.

## Функции

Имя функции открывает её реализацию в ветке `test`; структуры параметров и результатов описаны в конце README.

### func [NewService](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L82)

```go
func NewService(repo *repository.Repository, deps Dependencies, logger *zap.Logger) *Service
```

Типы: [Dependencies](#type-dependencies), [Repository](#type-repository), [Service](#type-service).

Структуры: [Dependencies](#type-dependencies).

Подставляет безопасный журнал при `nil` и собирает службы личных, рабочих, внутренних профилей и квалификаций с зависимостями `UserAccountChecker` и `DepartmentChecker`.

### func [NewUserProfileServiceStruct](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/user_profile_service.go#L18)

```go
func NewUserProfileServiceStruct(repo *repository.Repository, userChecker UserAccountChecker, logger *zap.Logger) *UserProfileServiceStruct
```

Типы: [Repository](#type-repository), [UserAccountChecker](#type-useraccountchecker), [UserProfileServiceStruct](#type-userprofileservicestruct).

Структуры: [UserAccountChecker](#type-useraccountchecker), [UserProfileServiceStruct](#type-userprofileservicestruct).

Создают специализированные службы и сохраняют необходимые зависимости; каждый конструктор защищает методы от отсутствующего журнала.

### func [NewWorkProfileServiceStruct](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/work_profile_service.go#L18)

```go
func NewWorkProfileServiceStruct(repo *repository.Repository, departmentChecker DepartmentChecker, logger *zap.Logger) *WorkProfileServiceStruct
```

Типы: [DepartmentChecker](#type-departmentchecker), [Repository](#type-repository), [WorkProfileServiceStruct](#type-workprofileservicestruct).

Структуры: [DepartmentChecker](#type-departmentchecker), [WorkProfileServiceStruct](#type-workprofileservicestruct).

Создают специализированные службы и сохраняют необходимые зависимости; каждый конструктор защищает методы от отсутствующего журнала.

### func [NewProfileInternalServiceStruct](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/internal_service.go#L16)

```go
func NewProfileInternalServiceStruct(repo *repository.Repository, logger *zap.Logger) *ProfileInternalServiceStruct
```

Типы: [ProfileInternalServiceStruct](#type-profileinternalservicestruct), [Repository](#type-repository).

Структуры: [ProfileInternalServiceStruct](#type-profileinternalservicestruct).

Создают специализированные службы и сохраняют необходимые зависимости; каждый конструктор защищает методы от отсутствующего журнала.

### func [NewCertificationServiceStruct](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L19)

```go
func NewCertificationServiceStruct(repo *repository.Repository, logger *zap.Logger) *CertificationServiceStruct
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [Repository](#type-repository).

Структуры: [CertificationServiceStruct](#type-certificationservicestruct).

Создают специализированные службы и сохраняют необходимые зависимости; каждый конструктор защищает методы от отсутствующего журнала.

### func [isWorkerStatusTransitionAllowed](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/work_profile_service.go#L336)

```go
func isWorkerStatusTransitionAllowed(from models.WorkProfileStatus, to models.WorkProfileStatus) bool
```

Ограничивает самостоятельные переходы работника теми парами состояний, которые явно перечислены в коде; остальные переходы доступны только администратору.

### func (*CertificationServiceStruct) [ensureCertificationCanBeUploaded](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L494)

```go
func (s *CertificationServiceStruct) ensureCertificationCanBeUploaded(ctx context.Context, method string, in *models.UploadWorkProfileCertificationInput) error
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [UploadWorkProfileCertificationInput](#type-uploadworkprofilecertificationinput).

Структуры: [UploadWorkProfileCertificationInput](#type-uploadworkprofilecertificationinput).

Последовательно загружают вид и профиль, проверяют активность вида, обязательность файла, будущий срок, права владельца/администратора/кадровой роли и допустимое состояние рабочего профиля.

### func [ensureCertificationTypeAcceptsUpload](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L513)

```go
func ensureCertificationTypeAcceptsUpload(certificationType *models.CertificationType, in *models.UploadWorkProfileCertificationInput) error
```

Типы: [CertificationType](#type-certificationtype), [UploadWorkProfileCertificationInput](#type-uploadworkprofilecertificationinput).

Структуры: [CertificationType](#type-certificationtype), [UploadWorkProfileCertificationInput](#type-uploadworkprofilecertificationinput).

Последовательно загружают вид и профиль, проверяют активность вида, обязательность файла, будущий срок, права владельца/администратора/кадровой роли и допустимое состояние рабочего профиля.

### func [ensureCanUploadCertification](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L526)

```go
func ensureCanUploadCertification(method string, actorUserID *uuid.UUID, roles []string, details *models.WorkProfileDetails) error
```

Типы: [WorkProfileDetails](#type-workprofiledetails).

Структуры: [WorkProfileDetails](#type-workprofiledetails).

Последовательно загружают вид и профиль, проверяют активность вида, обязательность файла, будущий срок, права владельца/администратора/кадровой роли и допустимое состояние рабочего профиля.

### func [ensureWorkProfileAcceptsCertification](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L533)

```go
func ensureWorkProfileAcceptsCertification(method string, workProfile *models.WorkProfile) error
```

Типы: [WorkProfile](#type-workprofile).

Структуры: [WorkProfile](#type-workprofile).

Последовательно загружают вид и профиль, проверяют активность вида, обязательность файла, будущий срок, права владельца/администратора/кадровой роли и допустимое состояние рабочего профиля.

### func [requireCatalogReader](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L568)

```go
func requireCatalogReader(method string, actorUserID *uuid.UUID, roles []string) error
```

Проверяют роли для чтения справочника, административных действий и квалификаций. Внутренним считается вызов без пользователя и ролей.

### func [requireAdmin](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L575)

```go
func requireAdmin(method string, roles []string) error
```

Проверяют роли для чтения справочника, административных действий и квалификаций. Внутренним считается вызов без пользователя и ролей.

### func [requireAdminOrHR](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L582)

```go
func requireAdminOrHR(method string, roles []string) error
```

Проверяют роли для чтения справочника, административных действий и квалификаций. Внутренним считается вызов без пользователя и ролей.

### func [isInternalCall](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L601)

```go
func isInternalCall(actorUserID *uuid.UUID, roles []string) bool
```

Проверяют роли для чтения справочника, административных действий и квалификаций. Внутренним считается вызов без пользователя и ролей.

### func [withIdempotency](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/idempotency.go#L19)

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

Типы: [Repository](#type-repository).

`hashRequest` вычисляет SHA-256 JSON-запроса. `withIdempotency` выполняет новую команду в транзакции либо возвращает сохраненный ответ/конфликт/состояние обработки. `runCommand` добавляет имя операции и исполнителя, а `runLoggedCommand` также пишет начало, успех или ошибку.

### func [hashRequest](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/idempotency.go#L73)

```go
func hashRequest(request any) (string, error)
```

`hashRequest` вычисляет SHA-256 JSON-запроса. `withIdempotency` выполняет новую команду в транзакции либо возвращает сохраненный ответ/конфликт/состояние обработки. `runCommand` добавляет имя операции и исполнителя, а `runLoggedCommand` также пишет начало, успех или ошибку.

### func [runCommand](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L201)

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

Типы: [Repository](#type-repository).

`hashRequest` вычисляет SHA-256 JSON-запроса. `withIdempotency` выполняет новую команду в транзакции либо возвращает сохраненный ответ/конфликт/состояние обработки. `runCommand` добавляет имя операции и исполнителя, а `runLoggedCommand` также пишет начало, успех или ошибку.

### func [runLoggedCommand](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L216)

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

Типы: [Repository](#type-repository).

`hashRequest` вычисляет SHA-256 JSON-запроса. `withIdempotency` выполняет новую команду в транзакции либо возвращает сохраненный ответ/конфликт/состояние обработки. `runCommand` добавляет имя операции и исполнителя, а `runLoggedCommand` также пишет начало, успех или ошибку.

### func [validationError](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L95)

```go
func validationError(method string, err error) error
```

Формируют единообразные ошибки и реализуют нечувствительную к регистру проверку ролей. Системный исполнитель получает ключ `system`.

### func [hasRole](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L99)

```go
func hasRole(roles []string, allowed ...string) bool
```

Формируют единообразные ошибки и реализуют нечувствительную к регистру проверку ролей. Системный исполнитель получает ключ `system`.

### func [isAdmin](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L110)

```go
func isAdmin(roles []string) bool
```

Формируют единообразные ошибки и реализуют нечувствительную к регистру проверку ролей. Системный исполнитель получает ключ `system`.

### func [isDispatcher](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L114)

```go
func isDispatcher(roles []string) bool
```

Формируют единообразные ошибки и реализуют нечувствительную к регистру проверку ролей. Системный исполнитель получает ключ `system`.

### func [isHR](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L118)

```go
func isHR(roles []string) bool
```

Формируют единообразные ошибки и реализуют нечувствительную к регистру проверку ролей. Системный исполнитель получает ключ `system`.

### func [actorKey](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L122)

```go
func actorKey(actorUserID *uuid.UUID) string
```

Формируют единообразные ошибки и реализуют нечувствительную к регистру проверку ролей. Системный исполнитель получает ключ `system`.

### func [isSelf](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L129)

```go
func isSelf(actorUserID *uuid.UUID, userID uuid.UUID) bool
```

Формируют единообразные ошибки и реализуют нечувствительную к регистру проверку ролей. Системный исполнитель получает ключ `system`.

### func [permissionDenied](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L133)

```go
func permissionDenied(method string) error
```

Формируют единообразные ошибки и реализуют нечувствительную к регистру проверку ролей. Системный исполнитель получает ключ `system`.

### func [wrapServiceError](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L137)

```go
func wrapServiceError(method string, err error) error
```

Формируют единообразные ошибки и реализуют нечувствительную к регистру проверку ролей. Системный исполнитель получает ключ `system`.

### func [startOperation](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L144)

```go
func startOperation(ctx context.Context, logger *zap.Logger, method string, fields ...zap.Field) (*zap.Logger, time.Time)
```

Добавляют `request_id`, время выполнения и поля операции в структурированный журнал. `runLoggedQuery` объединяет выполнение читающего запроса, оборачивание ошибки и запись результата.

### func [logValidationFailed](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L155)

```go
func logValidationFailed(logger *zap.Logger, method string, start time.Time, err error, fields ...zap.Field)
```

Добавляют `request_id`, время выполнения и поля операции в структурированный журнал. `runLoggedQuery` объединяет выполнение читающего запроса, оборачивание ошибки и запись результата.

### func [logPermissionDenied](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L163)

```go
func logPermissionDenied(logger *zap.Logger, method string, start time.Time, fields ...zap.Field)
```

Добавляют `request_id`, время выполнения и поля операции в структурированный журнал. `runLoggedQuery` объединяет выполнение читающего запроса, оборачивание ошибки и запись результата.

### func [logOperationFailed](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L168)

```go
func logOperationFailed(logger *zap.Logger, method string, start time.Time, err error, fields ...zap.Field)
```

Добавляют `request_id`, время выполнения и поля операции в структурированный журнал. `runLoggedQuery` объединяет выполнение читающего запроса, оборачивание ошибки и запись результата.

### func [logOperationSuccess](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L176)

```go
func logOperationSuccess(logger *zap.Logger, method string, start time.Time, fields ...zap.Field)
```

Добавляют `request_id`, время выполнения и поля операции в структурированный журнал. `runLoggedQuery` объединяет выполнение читающего запроса, оборачивание ошибки и запись результата.

### func [runLoggedQuery](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/service.go#L181)

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

### func (*UserProfileServiceStruct) [CreateUserProfile](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/user_profile_service.go#L25)

```go
func (s *UserProfileServiceStruct) CreateUserProfile(ctx context.Context, in *models.CreateUserProfileInput) (*models.CreateUserProfileResult, error)
```

Типы: [CreateUserProfileInput](#type-createuserprofileinput), [CreateUserProfileResult](#type-createuserprofileresult), [UserProfileServiceStruct](#type-userprofileservicestruct).

Проверяет UUID, имя, телефон и способ связи. Создавать профиль может сам пользователь или `admin`; при создании администратором дополнительно проверяется существование учетной записи. Команда идемпотентно создает профиль и событие.


### func (*UserProfileServiceStruct) [GetUserProfileByID](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/user_profile_service.go#L60)

```go
func (s *UserProfileServiceStruct) GetUserProfileByID(ctx context.Context, in *models.GetUserProfileByIDInput) (*models.GetUserProfileByIDResult, error)
```

Типы: [GetUserProfileByIDInput](#type-getuserprofilebyidinput), [GetUserProfileByIDResult](#type-getuserprofilebyidresult), [UserProfileServiceStruct](#type-userprofileservicestruct).

Загружает профиль по UUID и после получения владельца разрешает чтение только ему или администратору.


### func (*UserProfileServiceStruct) [GetUserProfileByUserID](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/user_profile_service.go#L83)

```go
func (s *UserProfileServiceStruct) GetUserProfileByUserID(ctx context.Context, in *models.GetUserProfileByUserIDInput) (*models.GetUserProfileByUserIDResult, error)
```

Типы: [GetUserProfileByUserIDInput](#type-getuserprofilebyuseridinput), [GetUserProfileByUserIDResult](#type-getuserprofilebyuseridresult), [UserProfileServiceStruct](#type-userprofileservicestruct).

До обращения к хранилищу требует совпадения исполнителя с `UserID` либо роль `admin`.


### func (*UserProfileServiceStruct) [GetMyUserProfile](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/user_profile_service.go#L106)

```go
func (s *UserProfileServiceStruct) GetMyUserProfile(ctx context.Context, in *models.GetMyUserProfileInput) (*models.GetMyUserProfileResult, error)
```

Типы: [GetMyUserProfileInput](#type-getmyuserprofileinput), [GetMyUserProfileResult](#type-getmyuserprofileresult), [UserProfileServiceStruct](#type-userprofileservicestruct).

Требует ненулевой `ActorUserID`, ищет профиль по нему и преобразует результат в `GetMyUserProfileResult`.


### func (*UserProfileServiceStruct) [ListUserProfiles](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/user_profile_service.go#L128)

```go
func (s *UserProfileServiceStruct) ListUserProfiles(ctx context.Context, in *models.ListUserProfilesInput) (*models.ListUserProfilesResult, error)
```

Типы: [ListUserProfilesInput](#type-listuserprofilesinput), [ListUserProfilesResult](#type-listuserprofilesresult), [UserProfileServiceStruct](#type-userprofileservicestruct).

Разрешен только администратору. Нормализует сортировку и страницу, применяет текстовый поиск и возвращает список с общим количеством.


### func (*UserProfileServiceStruct) [UpdateUserProfile](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/user_profile_service.go#L151)

```go
func (s *UserProfileServiceStruct) UpdateUserProfile(ctx context.Context, in *models.UpdateUserProfileInput) (*models.UpdateUserProfileResult, error)
```

Типы: [UpdateUserProfileInput](#type-updateuserprofileinput), [UpdateUserProfileResult](#type-updateuserprofileresult), [UserProfileServiceStruct](#type-userprofileservicestruct).

Проверяет изменяемые поля, загружает текущий профиль и разрешает изменение владельцу или администратору. Идемпотентная команда обновляет данные; отдельные флаги явно очищают телефон и изображение.


### func (*WorkProfileServiceStruct) [CreateWorkProfile](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/work_profile_service.go#L25)

```go
func (s *WorkProfileServiceStruct) CreateWorkProfile(ctx context.Context, in *models.CreateWorkProfileInput) (*models.CreateWorkProfileResult, error)
```

Типы: [CreateWorkProfileInput](#type-createworkprofileinput), [CreateWorkProfileResult](#type-createworkprofileresult), [WorkProfileServiceStruct](#type-workprofileservicestruct).

Требует `admin`, существующий личный профиль и активное подразделение. После проверок идемпотентно создает рабочий профиль и его начальную историю.


### func (*WorkProfileServiceStruct) [GetWorkProfileByID](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/work_profile_service.go#L65)

```go
func (s *WorkProfileServiceStruct) GetWorkProfileByID(ctx context.Context, in *models.GetWorkProfileByIDInput) (*models.GetWorkProfileByIDResult, error)
```

Типы: [GetWorkProfileByIDInput](#type-getworkprofilebyidinput), [GetWorkProfileByIDResult](#type-getworkprofilebyidresult), [WorkProfileServiceStruct](#type-workprofileservicestruct).

Загружают объединенные данные и вызывают `ensureCanReadWorkProfile`: владелец, `admin`, кадровая роль и диспетчер того же подразделения имеют доступ.


### func (*WorkProfileServiceStruct) [GetWorkProfileByUserID](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/work_profile_service.go#L88)

```go
func (s *WorkProfileServiceStruct) GetWorkProfileByUserID(ctx context.Context, in *models.GetWorkProfileByUserIDInput) (*models.GetWorkProfileByUserIDResult, error)
```

Типы: [GetWorkProfileByUserIDInput](#type-getworkprofilebyuseridinput), [GetWorkProfileByUserIDResult](#type-getworkprofilebyuseridresult), [WorkProfileServiceStruct](#type-workprofileservicestruct).

Загружают объединенные данные и вызывают `ensureCanReadWorkProfile`: владелец, `admin`, кадровая роль и диспетчер того же подразделения имеют доступ.


### func (*WorkProfileServiceStruct) [ListWorkProfiles](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/work_profile_service.go#L111)

```go
func (s *WorkProfileServiceStruct) ListWorkProfiles(ctx context.Context, in *models.ListWorkProfilesInput) (*models.ListWorkProfilesResult, error)
```

Типы: [ListWorkProfilesInput](#type-listworkprofilesinput), [ListWorkProfilesResult](#type-listworkprofilesresult), [WorkProfileServiceStruct](#type-workprofileservicestruct).

Администратор сохраняет переданный фильтр. Диспетчер обязан иметь рабочий профиль; его подразделение вычисляется и принудительно подставляется в запрос. Остальным доступ запрещен.


### func (*WorkProfileServiceStruct) [UpdateWorkProfile](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/work_profile_service.go#L150)

```go
func (s *WorkProfileServiceStruct) UpdateWorkProfile(ctx context.Context, in *models.UpdateWorkProfileInput) (*models.UpdateWorkProfileResult, error)
```

Типы: [UpdateWorkProfileInput](#type-updateworkprofileinput), [UpdateWorkProfileResult](#type-updateworkprofileresult), [WorkProfileServiceStruct](#type-workprofileservicestruct).

Требует `admin`, проверяет табельный номер и должность и идемпотентно выполняет частичное обновление.


### func (*WorkProfileServiceStruct) [DeactivateWorkProfile](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/work_profile_service.go#L179)

```go
func (s *WorkProfileServiceStruct) DeactivateWorkProfile(ctx context.Context, in *models.DeactivateWorkProfileInput) (*models.DeactivateWorkProfileResult, error)
```

Типы: [DeactivateWorkProfileInput](#type-deactivateworkprofileinput), [DeactivateWorkProfileResult](#type-deactivateworkprofileresult), [WorkProfileServiceStruct](#type-workprofileservicestruct).

Требует `admin` и причину, переводит профиль в `INACTIVE`, устанавливает время деактивации, историю и событие.


### func (*WorkProfileServiceStruct) [ChangeWorkProfileDepartment](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/work_profile_service.go#L208)

```go
func (s *WorkProfileServiceStruct) ChangeWorkProfileDepartment(ctx context.Context, in *models.ChangeWorkProfileDepartmentInput) (*models.ChangeWorkProfileDepartmentResult, error)
```

Типы: [ChangeWorkProfileDepartmentInput](#type-changeworkprofiledepartmentinput), [ChangeWorkProfileDepartmentResult](#type-changeworkprofiledepartmentresult), [WorkProfileServiceStruct](#type-workprofileservicestruct).

Требует `admin`, проверяет активность нового подразделения и идемпотентно переносит профиль с фиксацией причины.


### func (*WorkProfileServiceStruct) [SetWorkProfileStatus](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/work_profile_service.go#L244)

```go
func (s *WorkProfileServiceStruct) SetWorkProfileStatus(ctx context.Context, in *models.SetWorkProfileStatusInput) (*models.SetWorkProfileStatusResult, error)
```

Типы: [SetWorkProfileStatusInput](#type-setworkprofilestatusinput), [SetWorkProfileStatusResult](#type-setworkprofilestatusresult), [WorkProfileServiceStruct](#type-workprofileservicestruct).

Администратор может устанавливать поддерживаемое состояние. Сам работник ограничен переходами, которые разрешает `isWorkerStatusTransitionAllowed`; команда фиксирует историю и событие.


### func (*WorkProfileServiceStruct) [GetWorkProfileStatusHistory](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/work_profile_service.go#L269)

```go
func (s *WorkProfileServiceStruct) GetWorkProfileStatusHistory(ctx context.Context, in *models.GetWorkProfileStatusHistoryInput) (*models.GetWorkProfileStatusHistoryResult, error)
```

Типы: [GetWorkProfileStatusHistoryInput](#type-getworkprofilestatushistoryinput), [GetWorkProfileStatusHistoryResult](#type-getworkprofilestatushistoryresult), [WorkProfileServiceStruct](#type-workprofileservicestruct).

Загружает профиль для проверки прав и возвращает страницу истории его состояний.


### func (*WorkProfileServiceStruct) [ensureCanReadWorkProfile](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/work_profile_service.go#L298)

```go
func (s *WorkProfileServiceStruct) ensureCanReadWorkProfile(ctx context.Context, actorUserID *uuid.UUID, roles []string, details *models.WorkProfileDetails) error
```

Типы: [WorkProfileDetails](#type-workprofiledetails), [WorkProfileServiceStruct](#type-workprofileservicestruct).

Разрешает владельца, администратора и кадровую роль. Для диспетчера вычисляет его подразделение и сравнивает с подразделением читаемого профиля.


### func (*WorkProfileServiceStruct) [actorDepartmentID](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/work_profile_service.go#L315)

```go
func (s *WorkProfileServiceStruct) actorDepartmentID(ctx context.Context, actorUserID *uuid.UUID) (uuid.UUID, error)
```

Типы: [WorkProfileServiceStruct](#type-workprofileservicestruct).

Требует `ActorUserID`, вызывает `ResolveWorkingDepartment` и возвращает `DepartmentID`.


### func (*WorkProfileServiceStruct) [ensureDepartmentActive](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/work_profile_service.go#L326)

```go
func (s *WorkProfileServiceStruct) ensureDepartmentActive(ctx context.Context, departmentID uuid.UUID, method string) error
```

Типы: [WorkProfileServiceStruct](#type-workprofileservicestruct).

Если проверяющий подразделения задан, вызывает его; ошибку оборачивает именем операции.


### func (*ProfileInternalServiceStruct) [ResolveWorkingDepartment](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/internal_service.go#L23)

```go
func (s *ProfileInternalServiceStruct) ResolveWorkingDepartment(ctx context.Context, in *models.ResolveWorkingDepartmentInput) (*models.ResolveWorkingDepartmentResult, error)
```

Типы: [ProfileInternalServiceStruct](#type-profileinternalservicestruct), [ResolveWorkingDepartmentInput](#type-resolveworkingdepartmentinput), [ResolveWorkingDepartmentResult](#type-resolveworkingdepartmentresult).

По `UserID` возвращает личный и рабочий профиль, подразделение, состояние и рассчитанный `CanOperate`.


### func (*ProfileInternalServiceStruct) [CheckProfileCanJoinBrigade](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/internal_service.go#L45)

```go
func (s *ProfileInternalServiceStruct) CheckProfileCanJoinBrigade(ctx context.Context, in *models.CheckProfileCanJoinBrigadeInput) (*models.CheckProfileCanJoinBrigadeResult, error)
```

Типы: [CheckProfileCanJoinBrigadeInput](#type-checkprofilecanjoinbrigadeinput), [CheckProfileCanJoinBrigadeResult](#type-checkprofilecanjoinbrigaderesult), [ProfileInternalServiceStruct](#type-profileinternalservicestruct).

Ищет профиль по пользователю или рабочему профилю и возвращает не ошибку доступа, а `Allowed` с точной причиной: отсутствие/состояние профиля либо несовпадение подразделения.


### func (*CertificationServiceStruct) [CreateCertificationType](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L26)

```go
func (s *CertificationServiceStruct) CreateCertificationType(ctx context.Context, in *models.CreateCertificationTypeInput) (*models.CreateCertificationTypeResult, error)
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [CreateCertificationTypeInput](#type-createcertificationtypeinput), [CreateCertificationTypeResult](#type-createcertificationtyperesult).

Требует `admin`, проверяет код, название и положительный срок и идемпотентно создает вид сертификата.


### func (*CertificationServiceStruct) [UpdateCertificationType](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L55)

```go
func (s *CertificationServiceStruct) UpdateCertificationType(ctx context.Context, in *models.UpdateCertificationTypeInput) (*models.UpdateCertificationTypeResult, error)
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [UpdateCertificationTypeInput](#type-updatecertificationtypeinput), [UpdateCertificationTypeResult](#type-updatecertificationtyperesult).

Требует `admin`, хотя бы одно изменение и корректные значения. Флаги очистки позволяют отличить очистку от отсутствия поля.


### func (*CertificationServiceStruct) [ListCertificationTypes](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L84)

```go
func (s *CertificationServiceStruct) ListCertificationTypes(ctx context.Context, in *models.ListCertificationTypesInput) (*models.ListCertificationTypesResult, error)
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [ListCertificationTypesInput](#type-listcertificationtypesinput), [ListCertificationTypesResult](#type-listcertificationtypesresult).

Разрешает администратору, кадровой роли, диспетчеру и внутреннему вызову читать справочник с фильтрами и страницей.


### func (*CertificationServiceStruct) [AddCertificationTypeSkill](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L107)

```go
func (s *CertificationServiceStruct) AddCertificationTypeSkill(ctx context.Context, in *models.AddCertificationTypeSkillInput) (*models.AddCertificationTypeSkillResult, error)
```

Типы: [AddCertificationTypeSkillInput](#type-addcertificationtypeskillinput), [AddCertificationTypeSkillResult](#type-addcertificationtypeskillresult), [CertificationServiceStruct](#type-certificationservicestruct).

Требует `admin`, проверяет идентификаторы и уровень, затем связывает вид сертификата с выдаваемым навыком.


### func (*CertificationServiceStruct) [RemoveCertificationTypeSkill](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L139)

```go
func (s *CertificationServiceStruct) RemoveCertificationTypeSkill(ctx context.Context, in *models.RemoveCertificationTypeSkillInput) error
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [RemoveCertificationTypeSkillInput](#type-removecertificationtypeskillinput).

Требует `admin` и деактивирует связь вида сертификата с навыком.


### func (*CertificationServiceStruct) [ListCertificationTypeSkills](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L170)

```go
func (s *CertificationServiceStruct) ListCertificationTypeSkills(ctx context.Context, in *models.ListCertificationTypeSkillsInput) (*models.ListCertificationTypeSkillsResult, error)
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [ListCertificationTypeSkillsInput](#type-listcertificationtypeskillsinput), [ListCertificationTypeSkillsResult](#type-listcertificationtypeskillsresult).

Проверяет право чтения справочника и возвращает навыки вида, при необходимости только активные.


### func (*CertificationServiceStruct) [UploadWorkProfileCertification](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L193)

```go
func (s *CertificationServiceStruct) UploadWorkProfileCertification(ctx context.Context, in *models.UploadWorkProfileCertificationInput) (*models.UploadWorkProfileCertificationResult, error)
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [UploadWorkProfileCertificationInput](#type-uploadworkprofilecertificationinput), [UploadWorkProfileCertificationResult](#type-uploadworkprofilecertificationresult).

Проверяет реквизиты и даты, затем `ensureCertificationCanBeUploaded`: вид должен быть активным, обязательный файл присутствовать, срок быть будущим, рабочий профиль — не `INACTIVE`/`SUSPENDED`, а исполнитель — владельцем, администратором или кадровой ролью. Сертификат создается как `PENDING`.


### func (*CertificationServiceStruct) [VerifyWorkProfileCertification](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L225)

```go
func (s *CertificationServiceStruct) VerifyWorkProfileCertification(ctx context.Context, in *models.VerifyWorkProfileCertificationInput) (*models.VerifyWorkProfileCertificationResult, error)
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [VerifyWorkProfileCertificationInput](#type-verifyworkprofilecertificationinput), [VerifyWorkProfileCertificationResult](#type-verifyworkprofilecertificationresult).

Требует кадровую роль или администратора. Идемпотентно переводит сертификат в `VERIFIED`, фиксирует проверяющего и создает активные выдачи всех навыков действующих связей вида сертификата.


### func (*CertificationServiceStruct) [RejectWorkProfileCertification](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L254)

```go
func (s *CertificationServiceStruct) RejectWorkProfileCertification(ctx context.Context, in *models.RejectWorkProfileCertificationInput) (*models.RejectWorkProfileCertificationResult, error)
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [RejectWorkProfileCertificationInput](#type-rejectworkprofilecertificationinput), [RejectWorkProfileCertificationResult](#type-rejectworkprofilecertificationresult).

Требует кадровую роль или администратора и непустую причину; переводит ожидающий сертификат в `REJECTED`.


### func (*CertificationServiceStruct) [RevokeWorkProfileCertification](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L283)

```go
func (s *CertificationServiceStruct) RevokeWorkProfileCertification(ctx context.Context, in *models.RevokeWorkProfileCertificationInput) (*models.RevokeWorkProfileCertificationResult, error)
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [RevokeWorkProfileCertificationInput](#type-revokeworkprofilecertificationinput), [RevokeWorkProfileCertificationResult](#type-revokeworkprofilecertificationresult).

Требует кадровую роль или администратора и причину; переводит сертификат в `REVOKED` и отзывает активные выдачи, созданные этим сертификатом.


### func (*CertificationServiceStruct) [ExpireWorkProfileCertifications](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L312)

```go
func (s *CertificationServiceStruct) ExpireWorkProfileCertifications(ctx context.Context, in *models.ExpireWorkProfileCertificationsInput) (*models.ExpireWorkProfileCertificationsResult, error)
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [ExpireWorkProfileCertificationsInput](#type-expireworkprofilecertificationsinput), [ExpireWorkProfileCertificationsResult](#type-expireworkprofilecertificationsresult).

Системная пакетная операция выбирает до заданного предела проверенные сертификаты с прошедшим сроком, переводит их в `EXPIRED` и отзывает связанные навыки.


### func (*CertificationServiceStruct) [ListWorkProfileCertifications](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L338)

```go
func (s *CertificationServiceStruct) ListWorkProfileCertifications(ctx context.Context, in *models.ListWorkProfileCertificationsInput) (*models.ListWorkProfileCertificationsResult, error)
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [ListWorkProfileCertificationsInput](#type-listworkprofilecertificationsinput), [ListWorkProfileCertificationsResult](#type-listworkprofilecertificationsresult).

Проверяет право чтения рабочего профиля, применяет фильтры вида и состояния и возвращает страницу сертификатов.


### func (*CertificationServiceStruct) [GrantManualWorkProfileSkill](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L361)

```go
func (s *CertificationServiceStruct) GrantManualWorkProfileSkill(ctx context.Context, in *models.GrantManualWorkProfileSkillInput) (*models.GrantManualWorkProfileSkillResult, error)
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [GrantManualWorkProfileSkillInput](#type-grantmanualworkprofileskillinput), [GrantManualWorkProfileSkillResult](#type-grantmanualworkprofileskillresult).

Требует администратора или кадровую роль, проверяет навык, срок и причину и создает ручную выдачу `MANUAL`.


### func (*CertificationServiceStruct) [RevokeWorkProfileSkillGrant](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L393)

```go
func (s *CertificationServiceStruct) RevokeWorkProfileSkillGrant(ctx context.Context, in *models.RevokeWorkProfileSkillGrantInput) (*models.RevokeWorkProfileSkillGrantResult, error)
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [RevokeWorkProfileSkillGrantInput](#type-revokeworkprofileskillgrantinput), [RevokeWorkProfileSkillGrantResult](#type-revokeworkprofileskillgrantresult).

Требует администратора или кадровую роль и причину; деактивирует выдачу и устанавливает `RevokedAt`.


### func (*CertificationServiceStruct) [ListEffectiveWorkProfileSkills](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L422)

```go
func (s *CertificationServiceStruct) ListEffectiveWorkProfileSkills(ctx context.Context, in *models.ListEffectiveWorkProfileSkillsInput) (*models.ListEffectiveWorkProfileSkillsResult, error)
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [ListEffectiveWorkProfileSkillsInput](#type-listeffectiveworkprofileskillsinput), [ListEffectiveWorkProfileSkillsResult](#type-listeffectiveworkprofileskillsresult).

После проверки чтения возвращает только активные и неистекшие выдачи рабочего профиля.


### func (*CertificationServiceStruct) [BatchListEffectiveWorkProfileSkills](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L445)

```go
func (s *CertificationServiceStruct) BatchListEffectiveWorkProfileSkills(ctx context.Context, in *models.BatchListEffectiveWorkProfileSkillsInput) (*models.BatchListEffectiveWorkProfileSkillsResult, error)
```

Типы: [BatchListEffectiveWorkProfileSkillsInput](#type-batchlisteffectiveworkprofileskillsinput), [BatchListEffectiveWorkProfileSkillsResult](#type-batchlisteffectiveworkprofileskillsresult), [CertificationServiceStruct](#type-certificationservicestruct).

Принимает ограниченный уникальный список профилей. Разрешен администратору и внутреннему вызову; возвращает карту навыков по идентификаторам профилей.


### func (*CertificationServiceStruct) [CheckWorkProfileHasSkills](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L468)

```go
func (s *CertificationServiceStruct) CheckWorkProfileHasSkills(ctx context.Context, in *models.CheckWorkProfileHasSkillsInput) (*models.CheckWorkProfileHasSkillsResult, error)
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct), [CheckWorkProfileHasSkillsInput](#type-checkworkprofilehasskillsinput), [CheckWorkProfileHasSkillsResult](#type-checkworkprofilehasskillsresult).

Проверяет право чтения и сравнивает действующие выдачи с `RequiredSkillIDs`; возвращает разрешение и отсутствующие навыки.


### func (*CertificationServiceStruct) [ensureCanReadWorkProfile](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L542)

```go
func (s *CertificationServiceStruct) ensureCanReadWorkProfile(ctx context.Context, workProfileID uuid.UUID, actorUserID *uuid.UUID, roles []string) error
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct).

Реализуют те же правила чтения: внутренний вызов, владелец, администратор, кадровая роль или диспетчер совпадающего подразделения.


### func (*CertificationServiceStruct) [actorDepartmentID](https://github.com/FIZZI-77/automatic_system/blob/test/Profile_Service/src/core/service/certification_service.go#L589)

```go
func (s *CertificationServiceStruct) actorDepartmentID(ctx context.Context, actorUserID *uuid.UUID) (uuid.UUID, error)
```

Типы: [CertificationServiceStruct](#type-certificationservicestruct).

Реализуют те же правила чтения: внутренний вызов, владелец, администратор, кадровая роль или диспетчер совпадающего подразделения.


## Структура БД

### Таблица `user_profiles`

| Поле | Тип | Назначение |
|---|---|---|
| `id`, `user_id` | `uuid` | Профиль и уникальная учетная запись. |
| `full_name` | `varchar(255)` | Полное имя. |
| `phone` | `varchar(32)` | Телефон вида `+` и 8–15 цифр. |
| `avatar_file_id` | `uuid` | Файл изображения. |
| `preferred_contact_method` | `varchar(16)` | `EMAIL`, `PHONE` или `PUSH`. |
| `created_at`, `updated_at` | `timestamptz` | Создание и изменение. |

### Таблица `work_profiles`

| Поле | Тип | Назначение |
|---|---|---|
| `id` | `uuid` | Первичный ключ. |
| `user_profile_id` | `uuid` | Уникальный личный профиль. |
| `department_id` | `uuid` | Подразделение. |
| `employee_number` | `varchar(64)` | Табельный номер, уникальный в подразделении среди заданных значений. |
| `position` | `varchar(128)` | Должность. |
| `status` | `varchar(32)` | Рабочее состояние. |
| `deactivated_at` | `timestamptz` | Время деактивации. |
| `created_at`, `updated_at` | `timestamptz` | Создание и изменение. |

### Таблица `work_profile_status_history`

| Поле | Тип | Назначение |
|---|---|---|
| `id`, `work_profile_id` | `uuid` | Запись и профиль. |
| `from_status`, `to_status` | `varchar(32)` | Разные прежнее и новое состояния. |
| `reason` | `text` | Причина. |
| `changed_by_user_id` | `uuid` | Автор. |
| `request_id` | `varchar(128)` | Запрос. |
| `created_at` | `timestamptz` | Время. |

### Таблица `idempotency_keys`

| Поле | Тип | Назначение |
|---|---|---|
| `id` | `uuid` | Запись. |
| `actor_key` | `varchar(128)` | Исполнитель. |
| `operation` | `varchar(100)` | Операция. |
| `idempotency_key`, `request_hash` | `varchar(128)` | Ключ и хеш. |
| `status` | `varchar(32)` | Состояние обработки. |
| `response` | `jsonb` | Сохраненный ответ. |
| `error` | `text` | Ошибка. |
| `resource_type` | `varchar(100)` | Вид ресурса. |
| `resource_id` | `uuid` | Ресурс. |
| `created_at`, `updated_at`, `expires_at` | `timestamptz` | Создание, изменение и срок. |

### Таблица `outbox_events`

| Поле | Тип | Назначение |
|---|---|---|
| `id`, `aggregate_id` | `uuid` | Событие и сущность. |
| `aggregate_type`, `event_type` | `varchar(100)` | Виды сущности и события. |
| `payload` | `jsonb` | Данные. |
| `status` | `varchar(50)` | Состояние доставки. |
| `attempts` | `integer` | Неотрицательное число попыток. |
| `last_error` | `text` | Ошибка. |
| `next_attempt_at`, `locked_at`, `created_at`, `sent_at` | `timestamptz` | Времена обработки. |

### Таблица `certification_types`

| Поле | Тип | Назначение |
|---|---|---|
| `id` | `uuid` | Вид сертификата. |
| `code` | `varchar(64)` | Код, уникальный без учета регистра. |
| `name` | `varchar(255)` | Название. |
| `description` | `text` | Описание. |
| `default_validity_days` | `integer` | Положительный срок действия. |
| `requires_file`, `active` | `boolean` | Обязательность файла и активность. |
| `created_at`, `updated_at` | `timestamptz` | Создание и изменение. |

### Таблица `certification_type_skills`

| Поле | Тип | Назначение |
|---|---|---|
| `id`, `certification_type_id`, `skill_id` | `uuid` | Связь вида и навыка. |
| `proficiency_level` | `varchar(64)` | Уровень. |
| `active` | `boolean` | Действует ли связь. |
| `created_at`, `updated_at` | `timestamptz` | Создание и изменение. |

### Таблица `work_profile_certifications`

| Поле | Тип | Назначение |
|---|---|---|
| `id`, `work_profile_id`, `certification_type_id` | `uuid` | Сертификат, профиль и вид. |
| `certificate_number` | `varchar(128)` | Номер. |
| `issuer` | `varchar(255)` | Издатель. |
| `issued_at`, `expires_at` | `date` | Даты выдачи и окончания. |
| `status` | `varchar(32)` | Состояние. |
| `certificate_file_id` | `uuid` | Файл. |
| `verified_by_user_id` | `uuid` | Проверивший пользователь. |
| `verified_at` | `timestamptz` | Время проверки. |
| `rejection_reason` | `text` | Причина отклонения. |
| `created_at`, `updated_at` | `timestamptz` | Создание и изменение. |

### Таблица `work_profile_skill_grants`

| Поле | Тип | Назначение |
|---|---|---|
| `id`, `work_profile_id`, `skill_id` | `uuid` | Выдача, профиль и навык. |
| `source_type` | `varchar(32)` | `MANUAL` или `CERTIFICATION`. |
| `source_id` | `uuid` | Сертификат-источник; обязателен для `CERTIFICATION`. |
| `proficiency_level` | `varchar(64)` | Уровень. |
| `valid_until` | `timestamptz` | Срок действия. |
| `active` | `boolean` | Действует ли выдача. |
| `created_at`, `revoked_at` | `timestamptz` | Создание и отзыв. |

### Таблица `processed_events`

| Поле | Тип | Назначение |
|---|---|---|
| `event_id` | `uuid` | Первичный ключ обработанного события. |
| `event_type` | `varchar(128)` | Тип события. |
| `source_service` | `varchar(128)` | Сервис-источник. |
| `processed_at` | `timestamptz` | Время обработки. |

## Структуры параметров и результатов

### type AddCertificationTypeSkillInput

```go
type AddCertificationTypeSkillInput struct {
	CertificationTypeID uuid.UUID
	SkillID             uuid.UUID
	ProficiencyLevel    *string
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}
```

### type AddCertificationTypeSkillResult

```go
type AddCertificationTypeSkillResult struct {
	CertificationTypeSkill *CertificationTypeSkill
}
```

### type BatchListEffectiveWorkProfileSkillsInput

```go
type BatchListEffectiveWorkProfileSkillsInput struct {
	WorkProfileIDs []uuid.UUID
	ActorUserID    *uuid.UUID
	ActorRoles     []string
}
```

### type BatchListEffectiveWorkProfileSkillsResult

```go
type BatchListEffectiveWorkProfileSkillsResult struct {
	SkillGrantsByWorkProfileID map[uuid.UUID][]*WorkProfileSkillGrant
}
```

### type CertificationServiceStruct

```go
type CertificationServiceStruct struct {
	repo   *repository.Repository
	logger *zap.Logger
}
```

### type CertificationType

```go
type CertificationType struct {
	ID                  uuid.UUID `json:"id"`
	Code                string    `json:"code"`
	Name                string    `json:"name"`
	Description         *string   `json:"description,omitempty"`
	DefaultValidityDays *int32    `json:"default_validity_days,omitempty"`
	RequiresFile        bool      `json:"requires_file"`
	Active              bool      `json:"active"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}
```

### type ChangeWorkProfileDepartmentInput

```go
type ChangeWorkProfileDepartmentInput struct {
	ID           uuid.UUID
	DepartmentID uuid.UUID
	Reason       string
	ActorUserID  *uuid.UUID
	ActorRoles   []string
}
```

### type ChangeWorkProfileDepartmentResult

```go
type ChangeWorkProfileDepartmentResult struct {
	Details *WorkProfileDetails
}
```

### type CheckProfileCanJoinBrigadeInput

```go
type CheckProfileCanJoinBrigadeInput struct {
	UserID              *uuid.UUID
	WorkProfileID       *uuid.UUID
	BrigadeDepartmentID uuid.UUID
}
```

### type CheckProfileCanJoinBrigadeResult

```go
type CheckProfileCanJoinBrigadeResult struct {
	UserProfileID uuid.UUID
	WorkProfileID uuid.UUID
	UserID        uuid.UUID
	DepartmentID  uuid.UUID
	Allowed       bool
	Reason        CanJoinBrigadeReason
}
```

### type CheckWorkProfileHasSkillsInput

```go
type CheckWorkProfileHasSkillsInput struct {
	WorkProfileID    uuid.UUID
	RequiredSkillIDs []uuid.UUID
	ActorUserID      *uuid.UUID
	ActorRoles       []string
}
```

### type CheckWorkProfileHasSkillsResult

```go
type CheckWorkProfileHasSkillsResult struct {
	Allowed         bool
	MissingSkillIDs []uuid.UUID
}
```

### type CreateCertificationTypeInput

```go
type CreateCertificationTypeInput struct {
	Code                string
	Name                string
	Description         *string
	DefaultValidityDays *int32
	RequiresFile        bool
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}
```

### type CreateCertificationTypeResult

```go
type CreateCertificationTypeResult struct {
	CertificationType *CertificationType
}
```

### type CreateUserProfileInput

```go
type CreateUserProfileInput struct {
	UserID                 uuid.UUID
	FullName               string
	Phone                  *string
	AvatarFileID           *uuid.UUID
	PreferredContactMethod PreferredContactMethod
	ActorUserID            *uuid.UUID
	ActorRoles             []string
}
```

### type CreateUserProfileResult

```go
type CreateUserProfileResult struct {
	UserProfile *UserProfile
}
```

### type CreateWorkProfileInput

```go
type CreateWorkProfileInput struct {
	UserProfileID  uuid.UUID
	DepartmentID   uuid.UUID
	EmployeeNumber *string
	Position       string
	ActorUserID    *uuid.UUID
	ActorRoles     []string
}
```

### type CreateWorkProfileResult

```go
type CreateWorkProfileResult struct {
	Details *WorkProfileDetails
}
```

### type DeactivateWorkProfileInput

```go
type DeactivateWorkProfileInput struct {
	ID          uuid.UUID
	Reason      string
	ActorUserID *uuid.UUID
	ActorRoles  []string
}
```

### type DeactivateWorkProfileResult

```go
type DeactivateWorkProfileResult struct {
	Details *WorkProfileDetails
}
```

### type DepartmentChecker

```go
type DepartmentChecker struct {
	client departmentv1.DepartmentServiceClient
}
```

### type Dependencies

```go
type Dependencies struct {
	UserAccountChecker UserAccountChecker
	DepartmentChecker  DepartmentChecker
}
```

### type ExpireWorkProfileCertificationsInput

```go
type ExpireWorkProfileCertificationsInput struct {
	Limit       int32
	ActorUserID *uuid.UUID
	ActorRoles  []string
}
```

### type ExpireWorkProfileCertificationsResult

```go
type ExpireWorkProfileCertificationsResult struct {
	ExpiredCertifications []*WorkProfileCertification
	RevokedGrants         []*WorkProfileSkillGrant
}
```

### type GetMyUserProfileInput

```go
type GetMyUserProfileInput struct {
	ActorUserID *uuid.UUID
}
```

### type GetMyUserProfileResult

```go
type GetMyUserProfileResult struct {
	UserProfile *UserProfile
}
```

### type GetUserProfileByIDInput

```go
type GetUserProfileByIDInput struct {
	ID          uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
}
```

### type GetUserProfileByIDResult

```go
type GetUserProfileByIDResult struct {
	UserProfile *UserProfile
}
```

### type GetUserProfileByUserIDInput

```go
type GetUserProfileByUserIDInput struct {
	UserID      uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
}
```

### type GetUserProfileByUserIDResult

```go
type GetUserProfileByUserIDResult struct {
	UserProfile *UserProfile
}
```

### type GetWorkProfileByIDInput

```go
type GetWorkProfileByIDInput struct {
	ID          uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
}
```

### type GetWorkProfileByIDResult

```go
type GetWorkProfileByIDResult struct {
	Details *WorkProfileDetails
}
```

### type GetWorkProfileByUserIDInput

```go
type GetWorkProfileByUserIDInput struct {
	UserID      uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
}
```

### type GetWorkProfileByUserIDResult

```go
type GetWorkProfileByUserIDResult struct {
	Details *WorkProfileDetails
}
```

### type GetWorkProfileStatusHistoryInput

```go
type GetWorkProfileStatusHistoryInput struct {
	WorkProfileID uuid.UUID
	Limit         int32
	Offset        int32
	ActorUserID   *uuid.UUID
	ActorRoles    []string
}
```

### type GetWorkProfileStatusHistoryResult

```go
type GetWorkProfileStatusHistoryResult struct {
	History []*WorkProfileStatusHistory
	Total   int64
}
```

### type GrantManualWorkProfileSkillInput

```go
type GrantManualWorkProfileSkillInput struct {
	WorkProfileID    uuid.UUID
	SkillID          uuid.UUID
	ProficiencyLevel *string
	ValidUntil       *time.Time
	Reason           string
	ActorUserID      *uuid.UUID
	ActorRoles       []string
}
```

### type GrantManualWorkProfileSkillResult

```go
type GrantManualWorkProfileSkillResult struct {
	SkillGrant *WorkProfileSkillGrant
}
```

### type ListCertificationTypeSkillsInput

```go
type ListCertificationTypeSkillsInput struct {
	CertificationTypeID uuid.UUID
	ActiveOnly          bool
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}
```

### type ListCertificationTypeSkillsResult

```go
type ListCertificationTypeSkillsResult struct {
	Skills []*CertificationTypeSkill
}
```

### type ListCertificationTypesInput

```go
type ListCertificationTypesInput struct {
	Active      *bool
	Query       *string
	Limit       int32
	Offset      int32
	ActorUserID *uuid.UUID
	ActorRoles  []string
}
```

### type ListCertificationTypesResult

```go
type ListCertificationTypesResult struct {
	CertificationTypes []*CertificationType
	Total              int64
}
```

### type ListEffectiveWorkProfileSkillsInput

```go
type ListEffectiveWorkProfileSkillsInput struct {
	WorkProfileID uuid.UUID
	ActorUserID   *uuid.UUID
	ActorRoles    []string
}
```

### type ListEffectiveWorkProfileSkillsResult

```go
type ListEffectiveWorkProfileSkillsResult struct {
	SkillGrants []*WorkProfileSkillGrant
}
```

### type ListUserProfilesInput

```go
type ListUserProfilesInput struct {
	Query       *string
	SortBy      UserProfileSortBy
	SortOrder   SortOrder
	Limit       int32
	Offset      int32
	ActorUserID *uuid.UUID
	ActorRoles  []string
}
```

### type ListUserProfilesResult

```go
type ListUserProfilesResult struct {
	UserProfiles []*UserProfile
	Total        int64
}
```

### type ListWorkProfileCertificationsInput

```go
type ListWorkProfileCertificationsInput struct {
	WorkProfileID       uuid.UUID
	CertificationTypeID *uuid.UUID
	Status              *CertificationStatus
	Limit               int32
	Offset              int32
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}
```

### type ListWorkProfileCertificationsResult

```go
type ListWorkProfileCertificationsResult struct {
	Certifications []*WorkProfileCertification
	Total          int64
}
```

### type ListWorkProfilesInput

```go
type ListWorkProfilesInput struct {
	DepartmentID *uuid.UUID
	Status       *WorkProfileStatus
	Query        *string
	SortBy       WorkProfileSortBy
	SortOrder    SortOrder
	Limit        int32
	Offset       int32
	ActorUserID  *uuid.UUID
	ActorRoles   []string
}
```

### type ListWorkProfilesResult

```go
type ListWorkProfilesResult struct {
	WorkProfiles []*WorkProfileDetails
	Total        int64
}
```

### type ProfileInternalServiceStruct

```go
type ProfileInternalServiceStruct struct {
	repo   *repository.Repository
	logger *zap.Logger
}
```

### type RejectWorkProfileCertificationInput

```go
type RejectWorkProfileCertificationInput struct {
	ID              uuid.UUID
	RejectionReason string
	ActorUserID     *uuid.UUID
	ActorRoles      []string
}
```

### type RejectWorkProfileCertificationResult

```go
type RejectWorkProfileCertificationResult struct {
	Certification *WorkProfileCertification
}
```

### type RemoveCertificationTypeSkillInput

```go
type RemoveCertificationTypeSkillInput struct {
	CertificationTypeID uuid.UUID
	SkillID             uuid.UUID
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}
```

### type Repository

```go
type Repository struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
	UserProfileRepository
	WorkProfileRepository
	CertificationRepository
}
```

### type ResolveWorkingDepartmentInput

```go
type ResolveWorkingDepartmentInput struct {
	UserID uuid.UUID
}
```

### type ResolveWorkingDepartmentResult

```go
type ResolveWorkingDepartmentResult struct {
	UserProfileID     uuid.UUID
	WorkProfileID     uuid.UUID
	UserID            uuid.UUID
	DepartmentID      uuid.UUID
	WorkProfileStatus WorkProfileStatus
	CanOperate        bool
}
```

### type RevokeWorkProfileCertificationInput

```go
type RevokeWorkProfileCertificationInput struct {
	ID          uuid.UUID
	Reason      string
	ActorUserID *uuid.UUID
	ActorRoles  []string
}
```

### type RevokeWorkProfileCertificationResult

```go
type RevokeWorkProfileCertificationResult struct {
	Certification *WorkProfileCertification
	RevokedGrants []*WorkProfileSkillGrant
}
```

### type RevokeWorkProfileSkillGrantInput

```go
type RevokeWorkProfileSkillGrantInput struct {
	ID          uuid.UUID
	Reason      string
	ActorUserID *uuid.UUID
	ActorRoles  []string
}
```

### type RevokeWorkProfileSkillGrantResult

```go
type RevokeWorkProfileSkillGrantResult struct {
	SkillGrant *WorkProfileSkillGrant
}
```

### type Service

```go
type Service struct {
	UserProfileService
	WorkProfileService
	ProfileInternalService
	CertificationService
}
```

### type SetWorkProfileStatusInput

```go
type SetWorkProfileStatusInput struct {
	ID          uuid.UUID
	Status      WorkProfileStatus
	Reason      string
	ActorUserID *uuid.UUID
	ActorRoles  []string
}
```

### type SetWorkProfileStatusResult

```go
type SetWorkProfileStatusResult struct {
	Details *WorkProfileDetails
}
```

### type UpdateCertificationTypeInput

```go
type UpdateCertificationTypeInput struct {
	ID                  uuid.UUID
	Code                *string
	Name                *string
	Description         *string
	ClearDescription    bool
	DefaultValidityDays *int32
	ClearValidityDays   bool
	RequiresFile        *bool
	Active              *bool
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}
```

### type UpdateCertificationTypeResult

```go
type UpdateCertificationTypeResult struct {
	CertificationType *CertificationType
}
```

### type UpdateUserProfileInput

```go
type UpdateUserProfileInput struct {
	ID                     uuid.UUID
	FullName               *string
	Phone                  *string
	ClearPhone             bool
	AvatarFileID           *uuid.UUID
	ClearAvatarFileID      bool
	PreferredContactMethod *PreferredContactMethod
	ActorUserID            *uuid.UUID
	ActorRoles             []string
}
```

### type UpdateUserProfileResult

```go
type UpdateUserProfileResult struct {
	UserProfile *UserProfile
}
```

### type UpdateWorkProfileInput

```go
type UpdateWorkProfileInput struct {
	ID                  uuid.UUID
	EmployeeNumber      *string
	ClearEmployeeNumber bool
	Position            *string
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}
```

### type UpdateWorkProfileResult

```go
type UpdateWorkProfileResult struct {
	Details *WorkProfileDetails
}
```

### type UploadWorkProfileCertificationInput

```go
type UploadWorkProfileCertificationInput struct {
	WorkProfileID       uuid.UUID
	CertificationTypeID uuid.UUID
	CertificateNumber   *string
	Issuer              *string
	IssuedAt            *time.Time
	ExpiresAt           *time.Time
	CertificateFileID   *uuid.UUID
	ActorUserID         *uuid.UUID
	ActorRoles          []string
}
```

### type UploadWorkProfileCertificationResult

```go
type UploadWorkProfileCertificationResult struct {
	Certification *WorkProfileCertification
}
```

### type UserAccountChecker

```go
type UserAccountChecker interface {
	EnsureUserExists(ctx context.Context, userID uuid.UUID) error
}
```

### type UserProfileServiceStruct

```go
type UserProfileServiceStruct struct {
	repo        *repository.Repository
	userChecker UserAccountChecker
	logger      *zap.Logger
}
```

### type VerifyWorkProfileCertificationInput

```go
type VerifyWorkProfileCertificationInput struct {
	ID          uuid.UUID
	ActorUserID *uuid.UUID
	ActorRoles  []string
}
```

### type VerifyWorkProfileCertificationResult

```go
type VerifyWorkProfileCertificationResult struct {
	Certification *WorkProfileCertification
	SkillGrants   []*WorkProfileSkillGrant
}
```

### type WorkProfile

```go
type WorkProfile struct {
	ID             uuid.UUID         `json:"id"`
	UserProfileID  uuid.UUID         `json:"user_profile_id"`
	DepartmentID   uuid.UUID         `json:"department_id"`
	EmployeeNumber *string           `json:"employee_number,omitempty"`
	Position       string            `json:"position"`
	Status         WorkProfileStatus `json:"status"`
	DeactivatedAt  *time.Time        `json:"deactivated_at,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}
```

### type WorkProfileDetails

```go
type WorkProfileDetails struct {
	WorkProfile *WorkProfile `json:"work_profile"`
	UserProfile *UserProfile `json:"user_profile"`
}
```

### type WorkProfileServiceStruct

```go
type WorkProfileServiceStruct struct {
	repo              *repository.Repository
	departmentChecker DepartmentChecker
	logger            *zap.Logger
}
```
