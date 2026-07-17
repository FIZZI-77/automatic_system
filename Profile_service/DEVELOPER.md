# Profile Service — developer documentation

Profile Service владеет пользовательскими и рабочими профилями, привязкой работника к департаменту, статусом рабочего профиля, квалификациями, сертификатами и эффективными навыками работника. Auth Service владеет учетной записью и ролями, Department Service владеет департаментами, Brigade Service владеет бригадами и справочником навыков. Profile Service хранит их UUID как логические ссылки.

## Слои сервиса

- `models` — доменные структуры, enum-статусы, input/result DTO, ошибки и валидаторы.
- `src/core/service` — бизнес-логика Profile: проверки доступа, lifecycle профилей, квалификации, вычисление effective skills.
- `src/core/repository` — PostgreSQL queries через `pgxpool`, транзакции, idempotency/outbox.
- `src/cmd/server` — точка будущего запуска сервиса. Сейчас слой транспорта в Profile Service еще не доведен до уровня остальных сервисов.
- `scheme` — SQL migrations. Таблицы и индексы лежат в отдельных файлах.
- `pkg` — инфраструктура: logger, request id, idempotency, PostgreSQL config, graceful closer.

## Доменные границы

В системе есть два разных профиля:

- `UserProfile` — гражданский/пользовательский профиль. Нужен любому пользователю: ФИО, телефон, аватар, preferred contact method.
- `WorkProfile` — рабочий профиль. Это отдельная сущность поверх `UserProfile`, которая появляется только если пользователь является работником. В нем лежат department, employee number, position и рабочий статус.

Такое разделение важно: пользователь может существовать без рабочего профиля, а рабочая логика не должна загрязнять обычный пользовательский профиль.

## Основные структуры `models`

- `UserProfile`
  - `ID` — UUID профиля.
  - `UserID` — UUID учетной записи в Auth Service.
  - `FullName`, `Phone`, `AvatarFileID`.
  - `PreferredContactMethod` — `EMAIL`, `PHONE`, `PUSH`.
  - `CreatedAt`, `UpdatedAt`.
- `WorkProfile`
  - `ID` — UUID рабочего профиля.
  - `UserProfileID` — связь с user profile.
  - `DepartmentID` — единственный департамент работника. Бизнес-правило: один рабочий может иметь только один департамент.
  - `EmployeeNumber`, `Position`.
  - `Status` — `ACTIVE`, `INACTIVE`, `ON_SHIFT`, `OFF_SHIFT`, `SUSPENDED`.
  - `DeactivatedAt`, timestamps.
- `WorkProfileDetails` — read model, объединяющая `WorkProfile` и `UserProfile`.
- `WorkProfileStatusHistory` — аудит изменения рабочего статуса.
- `CertificationType` — справочник типов квалификаций/сертификатов.
- `CertificationTypeSkill` — связь типа сертификата с навыком из каталога Brigade Service.
- `WorkProfileCertification` — конкретный сертификат работника.
- `WorkProfileSkillGrant` — выданный работнику навык. Источник может быть `MANUAL` или `CERTIFICATION`.
- `OutboxEvent` — интеграционное событие для eventual consistency.

## User profile service methods

### `CreateUserProfile(ctx, *CreateUserProfileInput) -> CreateUserProfileResult`

Принимает `user_id`, `full_name`, optional phone/avatar, preferred contact method, actor context.

Логика:

1. Валидирует input.
2. Проверяет, что actor имеет право создать профиль для указанного `user_id`.
3. Не допускает второй `UserProfile` для одного `user_id`.
4. Создает профиль.
5. Возвращает `UserProfile`.

### `GetUserProfileByID(ctx, *GetUserProfileByIDInput) -> GetUserProfileByIDResult`

Принимает profile `id` и actor context.

Логика: читает профиль, проверяет права просмотра, возвращает `UserProfile`.

### `GetUserProfileByUserID(ctx, *GetUserProfileByUserIDInput) -> GetUserProfileByUserIDResult`

Принимает `user_id`. Используется, когда внешний слой знает пользователя, но не знает profile id.

Логика: ищет профиль по `user_id`, проверяет доступ, возвращает профиль.

### `GetMyUserProfile(ctx, *GetMyUserProfileInput) -> GetMyUserProfileResult`

Принимает только `actor_user_id`.

Логика: возвращает профиль текущего пользователя. Клиент не должен передавать чужой `user_id` для сценария “мой профиль”.

### `ListUserProfiles(ctx, *ListUserProfilesInput) -> ListUserProfilesResult`

Принимает search query, sort, pagination, actor context.

Логика: доступно администраторам/внутренним ролям, нормализует limit/offset/sort, возвращает список и total.

### `UpdateUserProfile(ctx, *UpdateUserProfileInput) -> UpdateUserProfileResult`

Принимает profile `id` и optional поля: full name, phone, avatar, preferred contact method.

Логика: проверяет права, обновляет только переданные поля, учитывает clear flags (`ClearPhone`, `ClearAvatarFileID`), возвращает актуальный профиль.

## Work profile service methods

### `CreateWorkProfile(ctx, *CreateWorkProfileInput) -> CreateWorkProfileResult`

Принимает `user_profile_id`, `department_id`, optional `employee_number`, `position`, actor context.

Логика:

1. Проверяет права actor.
2. Валидирует input.
3. Проверяет наличие `UserProfile`.
4. Не допускает второй активный/существующий `WorkProfile` для одного `UserProfile`.
5. Закрепляет работника за одним департаментом.
6. Создает рабочий профиль.
7. Возвращает `WorkProfileDetails`.

### `GetWorkProfileByID(ctx, *GetWorkProfileByIDInput) -> GetWorkProfileByIDResult`

Принимает work profile `id`.

Логика: читает рабочий профиль вместе с `UserProfile`, проверяет права просмотра, возвращает details.

### `GetWorkProfileByUserID(ctx, *GetWorkProfileByUserIDInput) -> GetWorkProfileByUserIDResult`

Принимает `user_id`.

Логика: находит `UserProfile`, затем связанный `WorkProfile`, возвращает details. Используется внешними сервисами, которым известен пользователь.

### `ListWorkProfiles(ctx, *ListWorkProfilesInput) -> ListWorkProfilesResult`

Принимает фильтры department/status/query, sort, pagination, actor context.

Логика: администратор может видеть шире, dispatcher/manager обычно ограничивается департаментом. Возвращает список `WorkProfileDetails` и total.

### `UpdateWorkProfile(ctx, *UpdateWorkProfileInput) -> UpdateWorkProfileResult`

Принимает work profile `id` и optional поля `employee_number`, `position`.

Логика: проверяет права, обновляет только переданные поля, clear flag очищает employee number, возвращает details.

### `DeactivateWorkProfile(ctx, *DeactivateWorkProfileInput) -> DeactivateWorkProfileResult`

Принимает work profile `id`, reason, actor context.

Логика: переводит профиль в `INACTIVE`, заполняет `deactivated_at`, пишет status history. Данные не удаляются физически.

### `ChangeWorkProfileDepartment(ctx, *ChangeWorkProfileDepartmentInput) -> ChangeWorkProfileDepartmentResult`

Принимает work profile `id`, новый `department_id`, reason, actor context.

Логика: проверяет права, меняет единственный департамент работника, пишет историю/событие. Перед сменой нужно учитывать последствия: активное членство в бригаде старого департамента должно быть синхронизировано через Brigade Service.

### `SetWorkProfileStatus(ctx, *SetWorkProfileStatusInput) -> SetWorkProfileStatusResult`

Принимает work profile `id`, новый статус, reason, actor context.

Логика: валидирует transition, обновляет статус, пишет `WorkProfileStatusHistory`, возвращает details.

### `GetWorkProfileStatusHistory(ctx, *GetWorkProfileStatusHistoryInput) -> GetWorkProfileStatusHistoryResult`

Принимает `work_profile_id`, limit/offset, actor context.

Логика: проверяет доступ, возвращает историю статусов и total.

## Internal profile service methods

### `ResolveWorkingDepartment(ctx, *ResolveWorkingDepartmentInput) -> ResolveWorkingDepartmentResult`

Принимает `user_id`.

Логика: находит рабочий профиль пользователя, возвращает `department_id`, статус и `can_operate`. Используется другими сервисами, чтобы не доверять department id из тела клиентского запроса.

### `CheckProfileCanJoinBrigade(ctx, *CheckProfileCanJoinBrigadeInput) -> CheckProfileCanJoinBrigadeResult`

Принимает `user_id` или `work_profile_id`, а также `brigade_department_id`.

Логика:

1. Находит рабочий профиль.
2. Проверяет, что профиль активен/может работать.
3. Проверяет совпадение департамента работника и бригады.
4. Возвращает `Allowed` и reason: `ALLOWED`, `NO_WORK_PROFILE`, `PROFILE_INACTIVE`, `PROFILE_SUSPENDED`, `PROFILE_OFF_SHIFT`, `DEPARTMENT_MISMATCH`.

## Certification service methods

### `CreateCertificationType(ctx, *CreateCertificationTypeInput) -> CreateCertificationTypeResult`

Создает тип квалификации: `code`, `name`, optional description, default validity days, requires file.

Логика: доступно администратору/уполномоченной роли, `code` должен быть уникальным и стабильным.

### `UpdateCertificationType(ctx, *UpdateCertificationTypeInput) -> UpdateCertificationTypeResult`

Обновляет тип квалификации и active flag. Clear flags очищают nullable поля.

### `ListCertificationTypes(ctx, *ListCertificationTypesInput) -> ListCertificationTypesResult`

Возвращает каталог типов квалификаций с фильтром active/query и пагинацией.

### `AddCertificationTypeSkill(ctx, *AddCertificationTypeSkillInput) -> AddCertificationTypeSkillResult`

Связывает тип сертификата с `skill_id` из каталога навыков Brigade Service.

Логика: после подтверждения сертификата работник получает все active skills, связанные с этим certification type.

### `RemoveCertificationTypeSkill(ctx, *RemoveCertificationTypeSkillInput)`

Деактивирует связь типа сертификата и навыка. Уже выданные grants требуют отдельной политики: либо остаются до истечения, либо пересчитываются отдельной задачей.

### `ListCertificationTypeSkills(ctx, *ListCertificationTypeSkillsInput) -> ListCertificationTypeSkillsResult`

Возвращает навыки, которые дает конкретный certification type.

### `UploadWorkProfileCertification(ctx, *UploadWorkProfileCertificationInput) -> UploadWorkProfileCertificationResult`

Принимает work profile, certification type, certificate number, issuer, dates, file id.

Логика:

1. Проверяет права: работник может загрузить свой сертификат, администратор — для любого работника.
2. Проверяет certification type и `requires_file`.
3. Создает сертификат в статусе `PENDING`.
4. Возвращает `WorkProfileCertification`.

### `VerifyWorkProfileCertification(ctx, *VerifyWorkProfileCertificationInput) -> VerifyWorkProfileCertificationResult`

Принимает certification `id` и actor context.

Логика:

1. Проверяет права verifier.
2. Проверяет, что сертификат в статусе `PENDING`.
3. Переводит сертификат в `VERIFIED`, заполняет verifier и timestamp.
4. Берет active skills у certification type.
5. Создает `WorkProfileSkillGrant` с source `CERTIFICATION` и source id сертификата.
6. Возвращает сертификат и выданные grants.

Это и есть метод смены статуса скиллов от сертификата: skill становится эффективным не через отдельный “pending skill”, а через подтверждение сертификата и создание active grants.

### `RejectWorkProfileCertification(ctx, *RejectWorkProfileCertificationInput) -> RejectWorkProfileCertificationResult`

Принимает certification `id` и reason.

Логика: переводит `PENDING` сертификат в `REJECTED`, сохраняет reason. Grants не создаются.

### `RevokeWorkProfileCertification(ctx, *RevokeWorkProfileCertificationInput) -> RevokeWorkProfileCertificationResult`

Принимает certification `id`, reason, actor context.

Логика: переводит сертификат в `REVOKED`, деактивирует grants, у которых `source_type=CERTIFICATION` и `source_id` равен certification id, возвращает revoked grants.

### `ExpireWorkProfileCertifications(ctx, *ExpireWorkProfileCertificationsInput) -> ExpireWorkProfileCertificationsResult`

Пакетно переводит просроченные verified certifications в `EXPIRED` и деактивирует связанные grants. Метод рассчитан на cron/worker/internal use.

### `ListWorkProfileCertifications(ctx, *ListWorkProfileCertificationsInput) -> ListWorkProfileCertificationsResult`

Возвращает сертификаты рабочего профиля с фильтрами certification type/status и пагинацией.

### `GrantManualWorkProfileSkill(ctx, *GrantManualWorkProfileSkillInput) -> GrantManualWorkProfileSkillResult`

Выдает работнику навык вручную. Источник grant — `MANUAL`.

Логика: доступно только уполномоченным ролям, требует reason, может иметь `valid_until`.

### `RevokeWorkProfileSkillGrant(ctx, *RevokeWorkProfileSkillGrantInput) -> RevokeWorkProfileSkillGrantResult`

Деактивирует конкретный grant, заполняет `revoked_at`. Используется для ручных и точечных отзывов.

### `ListEffectiveWorkProfileSkills(ctx, *ListEffectiveWorkProfileSkillsInput) -> ListEffectiveWorkProfileSkillsResult`

Возвращает active grants рабочего профиля, которые не истекли.

### `BatchListEffectiveWorkProfileSkills(ctx, *BatchListEffectiveWorkProfileSkillsInput) -> BatchListEffectiveWorkProfileSkillsResult`

Возвращает effective skills сразу для нескольких work profile IDs. Метод нужен для Brigade Service/внутренних подборов, чтобы не делать N+1 запросов.

### `CheckWorkProfileHasSkills(ctx, *CheckWorkProfileHasSkillsInput) -> CheckWorkProfileHasSkillsResult`

Принимает work profile и список required skill IDs.

Логика: сравнивает required skills с active grants, возвращает `Allowed` и список `MissingSkillIDs`.

## Repository layer

Repository не принимает бизнес-решения. Он делает SQL, транзакции и маппинг.

Транзакции обязательны для операций:

- создание/смена work profile + status history + outbox;
- verify certification + создание grants;
- revoke/expire certification + отзыв grants;
- batch operations, где нужно сохранить консистентность нескольких таблиц.

## Бизнес-правила

- Один `UserProfile` на один `user_id`.
- Один `WorkProfile` на один `UserProfile`.
- Один `WorkProfile` имеет один текущий `department_id`.
- Auth Service — источник истины по пользователю, email, ролям и JWT.
- Department Service — источник истины по департаментам.
- Brigade Service — источник истины по бригадам и каталогу навыков; Profile хранит `skill_id` как логическую ссылку.
- Сертификат в `PENDING` не дает навыков.
- Сертификат в `VERIFIED` дает active grants.
- `REJECTED` не дает grants.
- `REVOKED`/`EXPIRED` должны деактивировать grants, выданные этим сертификатом.
- Manual grant живет независимо от сертификатов и отзывается отдельным методом.

## Текущие ограничения

В Profile Service уже есть модели, валидаторы, repository и service layer. Транспортный слой и полноценный server bootstrap нужно довести отдельно, чтобы сервис был симметричен Auth/Department/Ticket/Brigade.

## Как расширять сервис

1. Зафиксировать доменное правило в этом документе.
2. Добавить структуры input/result в `models`.
3. Добавить валидацию.
4. Добавить service method и repository method.
5. Если меняется схема — добавить migration, отдельно table и indexes.
6. Добавить handler/mapper, когда транспортный слой будет готов.
7. Покрыть unit tests service layer и repository tests.
