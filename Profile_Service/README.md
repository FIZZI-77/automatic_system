# Profile Service

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

### `NewService`

Подставляет безопасный журнал при `nil` и собирает службы личных, рабочих, внутренних профилей и квалификаций с зависимостями `UserAccountChecker` и `DepartmentChecker`.

### `NewUserProfileServiceStruct`, `NewWorkProfileServiceStruct`, `NewProfileInternalServiceStruct`, `NewCertificationServiceStruct`

Создают специализированные службы и сохраняют необходимые зависимости; каждый конструктор защищает методы от отсутствующего журнала.

### `UserProfileServiceStruct.CreateUserProfile`

Проверяет UUID, имя, телефон и способ связи. Создавать профиль может сам пользователь или `admin`; при создании администратором дополнительно проверяется существование учетной записи. Команда идемпотентно создает профиль и событие.

### `UserProfileServiceStruct.GetUserProfileByID`

Загружает профиль по UUID и после получения владельца разрешает чтение только ему или администратору.

### `UserProfileServiceStruct.GetUserProfileByUserID`

До обращения к хранилищу требует совпадения исполнителя с `UserID` либо роль `admin`.

### `UserProfileServiceStruct.GetMyUserProfile`

Требует ненулевой `ActorUserID`, ищет профиль по нему и преобразует результат в `GetMyUserProfileResult`.

### `UserProfileServiceStruct.ListUserProfiles`

Разрешен только администратору. Нормализует сортировку и страницу, применяет текстовый поиск и возвращает список с общим количеством.

### `UserProfileServiceStruct.UpdateUserProfile`

Проверяет изменяемые поля, загружает текущий профиль и разрешает изменение владельцу или администратору. Идемпотентная команда обновляет данные; отдельные флаги явно очищают телефон и изображение.

### `WorkProfileServiceStruct.CreateWorkProfile`

Требует `admin`, существующий личный профиль и активное подразделение. После проверок идемпотентно создает рабочий профиль и его начальную историю.

### `WorkProfileServiceStruct.GetWorkProfileByID`, `WorkProfileServiceStruct.GetWorkProfileByUserID`

Загружают объединенные данные и вызывают `ensureCanReadWorkProfile`: владелец, `admin`, кадровая роль и диспетчер того же подразделения имеют доступ.

### `WorkProfileServiceStruct.ListWorkProfiles`

Администратор сохраняет переданный фильтр. Диспетчер обязан иметь рабочий профиль; его подразделение вычисляется и принудительно подставляется в запрос. Остальным доступ запрещен.

### `WorkProfileServiceStruct.UpdateWorkProfile`

Требует `admin`, проверяет табельный номер и должность и идемпотентно выполняет частичное обновление.

### `WorkProfileServiceStruct.DeactivateWorkProfile`

Требует `admin` и причину, переводит профиль в `INACTIVE`, устанавливает время деактивации, историю и событие.

### `WorkProfileServiceStruct.ChangeWorkProfileDepartment`

Требует `admin`, проверяет активность нового подразделения и идемпотентно переносит профиль с фиксацией причины.

### `WorkProfileServiceStruct.SetWorkProfileStatus`

Администратор может устанавливать поддерживаемое состояние. Сам работник ограничен переходами, которые разрешает `isWorkerStatusTransitionAllowed`; команда фиксирует историю и событие.

### `WorkProfileServiceStruct.GetWorkProfileStatusHistory`

Загружает профиль для проверки прав и возвращает страницу истории его состояний.

### `WorkProfileServiceStruct.ensureCanReadWorkProfile`

Разрешает владельца, администратора и кадровую роль. Для диспетчера вычисляет его подразделение и сравнивает с подразделением читаемого профиля.

### `WorkProfileServiceStruct.actorDepartmentID`

Требует `ActorUserID`, вызывает `ResolveWorkingDepartment` и возвращает `DepartmentID`.

### `WorkProfileServiceStruct.ensureDepartmentActive`

Если проверяющий подразделения задан, вызывает его; ошибку оборачивает именем операции.

### `isWorkerStatusTransitionAllowed`

Ограничивает самостоятельные переходы работника теми парами состояний, которые явно перечислены в коде; остальные переходы доступны только администратору.

### `ProfileInternalServiceStruct.ResolveWorkingDepartment`

По `UserID` возвращает личный и рабочий профиль, подразделение, состояние и рассчитанный `CanOperate`.

### `ProfileInternalServiceStruct.CheckProfileCanJoinBrigade`

Ищет профиль по пользователю или рабочему профилю и возвращает не ошибку доступа, а `Allowed` с точной причиной: отсутствие/состояние профиля либо несовпадение подразделения.

### `CertificationServiceStruct.CreateCertificationType`

Требует `admin`, проверяет код, название и положительный срок и идемпотентно создает вид сертификата.

### `CertificationServiceStruct.UpdateCertificationType`

Требует `admin`, хотя бы одно изменение и корректные значения. Флаги очистки позволяют отличить очистку от отсутствия поля.

### `CertificationServiceStruct.ListCertificationTypes`

Разрешает администратору, кадровой роли, диспетчеру и внутреннему вызову читать справочник с фильтрами и страницей.

### `CertificationServiceStruct.AddCertificationTypeSkill`

Требует `admin`, проверяет идентификаторы и уровень, затем связывает вид сертификата с выдаваемым навыком.

### `CertificationServiceStruct.RemoveCertificationTypeSkill`

Требует `admin` и деактивирует связь вида сертификата с навыком.

### `CertificationServiceStruct.ListCertificationTypeSkills`

Проверяет право чтения справочника и возвращает навыки вида, при необходимости только активные.

### `CertificationServiceStruct.UploadWorkProfileCertification`

Проверяет реквизиты и даты, затем `ensureCertificationCanBeUploaded`: вид должен быть активным, обязательный файл присутствовать, срок быть будущим, рабочий профиль — не `INACTIVE`/`SUSPENDED`, а исполнитель — владельцем, администратором или кадровой ролью. Сертификат создается как `PENDING`.

### `CertificationServiceStruct.VerifyWorkProfileCertification`

Требует кадровую роль или администратора. Идемпотентно переводит сертификат в `VERIFIED`, фиксирует проверяющего и создает активные выдачи всех навыков действующих связей вида сертификата.

### `CertificationServiceStruct.RejectWorkProfileCertification`

Требует кадровую роль или администратора и непустую причину; переводит ожидающий сертификат в `REJECTED`.

### `CertificationServiceStruct.RevokeWorkProfileCertification`

Требует кадровую роль или администратора и причину; переводит сертификат в `REVOKED` и отзывает активные выдачи, созданные этим сертификатом.

### `CertificationServiceStruct.ExpireWorkProfileCertifications`

Системная пакетная операция выбирает до заданного предела проверенные сертификаты с прошедшим сроком, переводит их в `EXPIRED` и отзывает связанные навыки.

### `CertificationServiceStruct.ListWorkProfileCertifications`

Проверяет право чтения рабочего профиля, применяет фильтры вида и состояния и возвращает страницу сертификатов.

### `CertificationServiceStruct.GrantManualWorkProfileSkill`

Требует администратора или кадровую роль, проверяет навык, срок и причину и создает ручную выдачу `MANUAL`.

### `CertificationServiceStruct.RevokeWorkProfileSkillGrant`

Требует администратора или кадровую роль и причину; деактивирует выдачу и устанавливает `RevokedAt`.

### `CertificationServiceStruct.ListEffectiveWorkProfileSkills`

После проверки чтения возвращает только активные и неистекшие выдачи рабочего профиля.

### `CertificationServiceStruct.BatchListEffectiveWorkProfileSkills`

Принимает ограниченный уникальный список профилей. Разрешен администратору и внутреннему вызову; возвращает карту навыков по идентификаторам профилей.

### `CertificationServiceStruct.CheckWorkProfileHasSkills`

Проверяет право чтения и сравнивает действующие выдачи с `RequiredSkillIDs`; возвращает разрешение и отсутствующие навыки.

### `ensureCertificationCanBeUploaded`, `ensureCertificationTypeAcceptsUpload`, `ensureCanUploadCertification`, `ensureWorkProfileAcceptsCertification`

Последовательно загружают вид и профиль, проверяют активность вида, обязательность файла, будущий срок, права владельца/администратора/кадровой роли и допустимое состояние рабочего профиля.

### `CertificationServiceStruct.ensureCanReadWorkProfile`, `CertificationServiceStruct.actorDepartmentID`

Реализуют те же правила чтения: внутренний вызов, владелец, администратор, кадровая роль или диспетчер совпадающего подразделения.

### `requireCatalogReader`, `requireAdmin`, `requireAdminOrHR`, `isInternalCall`

Проверяют роли для чтения справочника, административных действий и квалификаций. Внутренним считается вызов без пользователя и ролей.

### `withIdempotency`, `hashRequest`, `runCommand`, `runLoggedCommand`

`hashRequest` вычисляет SHA-256 JSON-запроса. `withIdempotency` выполняет новую команду в транзакции либо возвращает сохраненный ответ/конфликт/состояние обработки. `runCommand` добавляет имя операции и исполнителя, а `runLoggedCommand` также пишет начало, успех или ошибку.

### `validationError`, `hasRole`, `isAdmin`, `isDispatcher`, `isHR`, `actorKey`, `isSelf`, `permissionDenied`, `wrapServiceError`

Формируют единообразные ошибки и реализуют нечувствительную к регистру проверку ролей. Системный исполнитель получает ключ `system`.

### `startOperation`, `logValidationFailed`, `logPermissionDenied`, `logOperationFailed`, `logOperationSuccess`, `runLoggedQuery`

Добавляют `request_id`, время выполнения и поля операции в структурированный журнал. `runLoggedQuery` объединяет выполнение читающего запроса, оборачивание ошибки и запись результата.

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
