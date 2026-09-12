# API Gateway

## Общее описание и общий принцип работы

`API Gateway` — единая внешняя HTTP-точка системы. Он принимает JSON-запрос, проверяет заголовки и права, преобразует данные в сообщения gRPC, вызывает нужный внутренний сервис и переводит ответ обратно в JSON. Шлюз не хранит предметные данные и не заменяет бизнес-правила целевых сервисов.

Обработка защищенного запроса проходит так:

1. `RequestID` принимает или создает `X-Request-ID` и добавляет его в контекст и ответ.
2. `IdempotencyKey` переносит `Idempotency-Key` в контекст gRPC.
3. Ограничитель частоты использует Redis и ключ клиента или пользователя.
4. `RequestLogger` записывает структурированные сведения о запросе.
5. `AuthMiddleware` извлекает Bearer JWT, проверяет подпись, алгоритм, издателя, получателя и срок действия.
6. Обработчик разбирает JSON, берет идентификатор и роли только из проверенного контекста, создает gRPC-запрос и вызывает внутренний сервис.
7. `handleGRPCError` переводит код gRPC в безопасный HTTP-ответ без внутренних деталей.

Глобальное ограничение — 300 запросов в минуту с запасом 100; проверки состояния исключены. Для публичных операций авторизации действует отдельный предел 20/мин с запасом 10 по адресу клиента и пути, для защищенных операций авторизации — 30/мин с запасом 10 по пользователю и пути.

## Модели

Модели в каталоге `models` являются внешними HTTP-представлениями. Они не создают отдельную предметную модель и не сохраняются шлюзом. Имена `Request` описывают тело запроса, имена `Response` — JSON-ответ, а сущности без суффикса — представление ответа внутреннего сервиса.

### Общие правила полей

| Поле или группа | Назначение |
|---|---|
| `id`, `*_id` | Строковые UUID сущностей. Значения пользователя и ролей для защищенных операций берутся из JWT, а не из доверяемого клиентского поля. |
| `limit`, `offset` | Размер страницы и смещение; окончательные ограничения проверяет целевой сервис. |
| `created_at`, `updated_at`, `*_at` | Время в строковом или Unix-представлении, преобразуемое соответствующим модулем. |
| поля-указатели | Отличают отсутствующее значение от явного нуля, `false` или пустой операции очистки. |
| `actor_*` | Не принимаются как доверенные данные: формируются шлюзом из контекста авторизации. |

### Авторизация — `models/auth.go`

| Модель | Поля и назначение |
|---|---|
| `RegisterRequest` | `Email`, `Password`, `DeviceID`, `DeviceName` — учетные данные и устройство регистрации. |
| `RegisterResponse` | идентификатор пользователя и признак необходимости подтверждения. |
| `LoginRequest` | адрес почты, пароль, устройство и сведения клиента. |
| `LoginResponse` | доступный и обновляющий токены, срок, сеанс и пользователь. |
| `RefreshRequest`, `RefreshResponse` | обновляющий токен/сеанс и новая пара токенов. |
| `LogoutResponse`, `LogoutAllResponse` | результат завершения одного или всех сеансов. |
| `MeResponse` | идентификатор, почта, состояние подтверждения и роли пользователя. |
| `ChangePasswordRequest` | старый и новый пароль. |
| `SendVerificationEmailRequest`, `VerifyEmailRequest` | адрес или одноразовый токен подтверждения. |
| `RequestPasswordResetRequest`, `ResetPasswordRequest` | адрес почты либо токен и новый пароль. |
| `ErrorResponse`, `ValidationErrorResponse` | безопасный код, сообщение и сведения об ошибках проверки. |

### Заявки — `models/ticket.go`

| Модель | Поля и назначение |
|---|---|
| `TicketCategory` | идентификатор, код, название, описание, активность и времена. |
| `Ticket` | заявка, подразделение, категория, автор, бригада, объект, текст, состояние, приоритет, адрес, координаты и времена переходов. |
| `TicketStatusHistory` | прежнее/новое состояние, автор, комментарий и время. |
| `CreateTicketRequest` | подразделение, категория, заголовок, описание, приоритет, адрес, координаты и необязательный `AssetID`. |
| `GetTicketRequest` | `TicketID`. |
| `ListTicketRequest` | фильтры, период, сортировка и страница. |
| `UpdateTicketRequest` | изменяемые поля заявки и необязательная связь с объектом. |
| `ChangeTicketStatusRequest`, `AssignBrigadeRequest`, `CancelTicketRequest`, `CompleteTicketRequest` | идентификаторы, новое состояние/бригада, комментарий или причина. |
| `GetTicketStatusHistoryRequest` | заявка и страница истории. |
| `WorkReport`, `CreateWorkReportRequest`, `ListWorkReportsRequest` | отчет, описание, файлы, признак итогового отчета и получение списка. |
| запросы категорий | создание, получение, список, изменение и удаление категории. |
| ответы | содержат соответствующую заявку, категорию, отчет, список и `Total`. |

### Бригады — `models/brigade.go`

| Группа моделей | Поля и назначение |
|---|---|
| `Brigade`, `BrigadeResponse`, `ListBrigadesResponse` | подразделение, название, описание, состояние, специализация, времена и список с общим количеством. |
| `BrigadeMember` | пользователь, профиль, роль, активность, личная доступность и времена участия. |
| `Skill`, `BrigadeSkill` | справочник навыков и связь с бригадой. |
| `BrigadeSchedule`, `BrigadeScheduleItem` | день недели, начало, конец, часовой пояс и период действия. |
| `BrigadeZone` | бригада, подразделение, название, GeoJSON, приоритет и активность. |
| модели истории | переходы состояния бригады, состава, ролей и доступности с причиной, автором и временем. |
| запросы бригады | создание, получение, список, изменение, деактивация, архивирование, состояние и история. |
| запросы состава | добавление/удаление, роль, доступность, список, история и поиск по пользователю. |
| запросы навыков | создание/изменение/деактивация справочника и добавление/удаление навыка бригады. |
| запросы расписания и зон | замена/чтение расписания, создание/изменение/удаление зон, проверка точки и поиск подходящих бригад. |

### Профили — `models/profile.go`

| Группа моделей | Поля и назначение |
|---|---|
| `UserProfile` | пользователь, имя, телефон, изображение, способ связи и времена. |
| `WorkProfile`, `WorkProfileDetails` | подразделение, табельный номер, должность, состояние и объединенные личные данные. |
| `WorkProfileStatusHistory` | переход, причина, автор, запрос и время. |
| `CertificationType`, `CertificationTypeSkill` | вид сертификата и выдаваемые им навыки. |
| `WorkProfileCertification` | реквизиты, даты, состояние, файл, проверяющий и причина отказа. |
| `WorkProfileSkillGrant`, `EffectiveWorkProfileSkills` | навык, источник, уровень, срок и действующие выдачи. |
| запросы личного профиля | создание, поиск, собственный профиль, список и изменение. |
| запросы рабочего профиля | создание, поиск, список, изменение, подразделение, состояние и история. |
| запросы квалификаций | справочник, связи навыков, загрузка/проверка/отзыв сертификатов и ручные навыки. |
| ответы | соответствующие сущности, списки, общие количества и отсутствующие навыки. |

### Остальные предметные модули

| Файл | Модели и поля |
|---|---|
| `models/department.go` | `Department` и запросы создания, получения, списка, изменения, удаления: идентификатор, название, описание, состояние, сортировка и страница. |
| `models/location.go` | `Position`, `CurrentLocation`, `GeoZone`, `NearbyBrigade` и запросы записи, истории, поиска рядом и управления зонами: субъект, координаты, последовательность, скорость, точность, время и GeoJSON. |
| `models/routing.go` | точки, ограничения транспорта, параметры, кандидаты и запросы построения маршрута/матрицы, ранжирования, сохранения, перерасчета, состояния и списка. |
| `models/dispatch.go` | запросы предварительного подбора, резервирования, подтверждения, автоматического назначения, чтения, списка и отмены; содержат заявку, бригаду, срок резерва, причину и страницу. |
| `models/asset.go` | идентификаторы объекта, создание/изменение, состояние, поиск рядом, происшествия, ремонты, осмотры, планы обслуживания и перерасчет риска. |
| `models/file.go` | `File` и запросы загрузки, привязки, получения ссылки, списка и удаления: владелец, имя, MIME-тип, размер, контрольная сумма, хранилище и ресурс. |
| `models/sla.go` | правила, заявка и запросы создания/изменения/удаления/списка: категория, приоритет, сроки реакции/решения, активность и страница. |
| `models/notification.go` | список уведомлений, прочтение, настройки каналов, устройство, шаблон и доставки. |
| `models/audit.go` | получение записи и список по исполнителю, действию, сущности, времени и странице. |
| `models/analytics.go` | общий фильтр времени/подразделения/категории/приоритета и запросы срезов, объектов и задержек. |
| `models/report.go` | создание, получение и список формируемых файлов отчета. |

Подробная семантика предметных полей находится в README соответствующего сервиса; шлюз сохраняет эти значения при преобразовании HTTP в gRPC.

### Полный указатель транспортных структур

Ниже перечислены все структуры каталога `models`. Указатель дополняет таблицы выше: точный состав полей определяется указанным файлом, а их предметное назначение раскрыто в соответствующем разделе и README целевого сервиса.

| Файл | Структуры |
|---|---|
| `models/analytics.go` | `AnalyticsFilter`, `AnalyticsRequest`, `OperationalLatencyRequest`, `AnalyticsBreakdownRequest`, `AssetAnalyticsRequest`. |
| `models/asset.go` | `AssetIDRequest`, `ResolveAssetRequest`, `CreateAssetRequest`, `UpdateAssetRequest`, `ChangeAssetStatusRequest`, `ListAssetsRequest`, `NearbyAssetsRequest`, `AssetIncidentRequest`, `AssetRepairRequest`, `AssetInspectionRequest`, `MaintenancePlanRequest`, `DueMaintenanceRequest`, `RecalculateAssetRisksRequest`. |
| `models/audit.go` | `GetAuditEntryRequest`, `ListAuditEntriesRequest`. |
| `models/auth.go` | `RegisterRequest`, `RegisterResponse`, `LoginRequest`, `LoginResponse`, `RefreshRequest`, `RefreshResponse`, `LogoutResponse`, `LogoutAllResponse`, `MeResponse`, `ChangePasswordRequest`, `ChangePasswordResponse`, `SendVerificationEmailRequest`, `SendVerificationEmailResponse`, `VerifyEmailRequest`, `VerifyEmailResponse`, `RequestPasswordResetRequest`, `RequestPasswordResetResponse`, `ResetPasswordRequest`, `ResetPasswordResponse`, `ErrorResponse`, `ValidationErrorResponse`. |
| `models/department.go` | `Department`, `CreateDepartmentRequest`, `CreateDepartmentResponse`, `GetDepartmentByIDRequest`, `GetDepartmentByIDResponse`, `ListDepartmentsRequest`, `ListDepartmentsResponse`, `UpdateDepartmentRequest`, `UpdateDepartmentResponse`, `DeleteDepartmentRequest`, `DeleteDepartmentResponse`. |
| `models/dispatch.go` | `PreviewDispatchRequest`, `ReserveBrigadeRequest`, `ConfirmDispatchRequest`, `AutoDispatchRequest`, `GetDispatchRequest`, `ListDispatchesRequest`, `CancelDispatchRequest`. |
| `models/file.go` | `File`, `CreateFileUploadRequest`, `LinkFileRequest`, `FileIDRequest`, `ListResourceFilesRequest`. |
| `models/location.go` | `Position`, `CurrentLocation`, `GeoZone`, `NearbyBrigade`, `RecordPositionRequest`, `GetCurrentLocationRequest`, `GetCurrentLocationsRequest`, `ListPositionHistoryRequest`, `FindNearbyBrigadesRequest`, `CreateGeoZoneRequest`, `UpdateGeoZoneRequest`, `DeleteGeoZoneRequest`, `ListGeoZonesRequest`, `CheckPointInZonesRequest`. |
| `models/notification.go` | `NotificationListRequest`, `NotificationIDRequest`, `NotificationPreferencesRequest`, `RegisterDeviceRequest`, `DeleteDeviceRequest`, `UpsertNotificationTemplateRequest`, `ListNotificationTemplatesRequest`, `ListDeliveriesRequest`. |
| `models/report.go` | `CreateReportRequest`, `GetReportRequest`, `ListReportsRequest`. |
| `models/routing.go` | `RoutingPoint`, `RoutingVehicleConstraints`, `RoutingOptions`, `BuildRouteRequest`, `BuildMatrixRequest`, `RoutingCandidate`, `RankCandidatesRequest`, `CreateRoutingRouteRequest`, `GetRoutingRouteRequest`, `RecalculateRoutingRouteRequest`, `SetRoutingRouteStatusRequest`, `ListRoutingRoutesRequest`. |
| `models/sla.go` | `CreateSLARuleRequest`, `UpdateSLARuleRequest`, `SLAIDRequest`, `TicketIDRequest`, `ListSLARulesRequest`, `ListTicketSLAsRequest`. |
| `models/ticket.go` | `TicketCategory`, `Ticket`, `TicketStatusHistory`, `CreateTicketRequest`, `CreateTicketResponse`, `GetTicketRequest`, `GetTicketResponse`, `ListTicketRequest`, `ListTicketResponse`, `UpdateTicketRequest`, `UpdateTicketResponse`, `ChangeTicketStatusRequest`, `ChangeTicketStatusResponse`, `AssignBrigadeRequest`, `AssignBrigadeResponse`, `CancelTicketRequest`, `CancelTicketResponse`, `CompleteTicketRequest`, `CompleteTicketResponse`, `GetTicketStatusHistoryRequest`, `GetTicketStatusHistoryResponse`, `WorkReport`, `CreateWorkReportRequest`, `ListWorkReportsRequest`, `CreateCategoryRequest`, `CreateCategoryResponse`, `GetCategoryRequest`, `GetCategoryResponse`, `ListCategoriesRequest`, `ListCategoriesResponse`, `UpdateCategoryRequest`, `UpdateCategoryResponse`, `DeleteCategoryRequest`, `DeleteCategoryResponse`. |

Структуры `models/brigade.go` сгруппированы так: предметные данные — `Brigade`, `BrigadeMember`, `Skill`, `BrigadeSkill`, `BrigadeSchedule`, `BrigadeScheduleItem`, `BrigadeZone`, `BrigadeStatusHistory`, `BrigadeMemberHistory`, `BrigadeMemberStatusHistory`; запросы — `CreateBrigadeRequest`, `GetBrigadeByIDRequest`, `ListBrigadesRequest`, `UpdateBrigadeRequest`, `BrigadeReasonRequest`, `SetBrigadeStatusRequest`, `BrigadePageRequest`, `AddBrigadeMemberRequest`, `BrigadeMemberMutationRequest`, `ChangeBrigadeMemberRoleRequest`, `SetBrigadeMemberAvailabilityRequest`, `ListBrigadeMembersRequest`, `BrigadeMemberHistoryRequest`, `GetBrigadeByUserIDRequest`, `CreateSkillRequest`, `UpdateSkillRequest`, `IDRequest`, `ListSkillsRequest`, `BrigadeSkillRequest`, `ListBrigadeSkillsRequest`, `SetBrigadeScheduleRequest`, `ListBrigadeScheduleRequest`, `CreateBrigadeZoneRequest`, `UpdateBrigadeZoneRequest`, `ListBrigadeZonesRequest`, `CheckBrigadeCoversPointRequest`, `FindBrigadesByPointRequest`, `GetAvailableBrigadesRequest`, `CheckBrigadeCanHandleTicketRequest`; ответы — `BrigadeResponse`, `ListBrigadesResponse`, `BrigadeMemberResponse`, `ListBrigadeMembersResponse`, `BrigadeStatusHistoryResponse`, `BrigadeMemberHistoryResponse`, `BrigadeMemberStatusHistoryResponse`, `GetBrigadeByUserIDResponse`, `SkillResponse`, `ListSkillsResponse`, `BrigadeSkillResponse`, `ListBrigadeSkillsResponse`, `BrigadeScheduleResponse`, `BrigadeZoneResponse`, `ListBrigadeZonesResponse`, `CheckBrigadeCoversPointResponse`, `CheckBrigadeCanHandleTicketResponse`.

Структуры `models/profile.go` сгруппированы так: предметные данные — `UserProfile`, `WorkProfile`, `WorkProfileDetails`, `WorkProfileStatusHistory`, `CertificationType`, `CertificationTypeSkill`, `WorkProfileCertification`, `WorkProfileSkillGrant`, `EffectiveWorkProfileSkills`; запросы — `CreateUserProfileRequest`, `GetUserProfileByIDRequest`, `GetUserProfileByUserIDRequest`, `ListUserProfilesRequest`, `UpdateUserProfileRequest`, `CreateWorkProfileRequest`, `GetWorkProfileByIDRequest`, `GetWorkProfileByUserIDRequest`, `ListWorkProfilesRequest`, `UpdateWorkProfileRequest`, `DeactivateWorkProfileRequest`, `ChangeWorkProfileDepartmentRequest`, `SetWorkProfileStatusRequest`, `WorkProfileStatusHistoryRequest`, `ResolveWorkingDepartmentRequest`, `CheckProfileCanJoinBrigadeRequest`, `CreateCertificationTypeRequest`, `UpdateCertificationTypeRequest`, `ListCertificationTypesRequest`, `CertificationTypeSkillRequest`, `ListCertificationTypeSkillsRequest`, `UploadWorkProfileCertificationRequest`, `CertificationIDRequest`, `RejectWorkProfileCertificationRequest`, `RevokeWorkProfileCertificationRequest`, `ExpireWorkProfileCertificationsRequest`, `ListWorkProfileCertificationsRequest`, `GrantManualWorkProfileSkillRequest`, `RevokeWorkProfileSkillGrantRequest`, `ListEffectiveWorkProfileSkillsRequest`, `BatchListEffectiveWorkProfileSkillsRequest`, `CheckWorkProfileHasSkillsRequest`; ответы — `UserProfileResponse`, `ListUserProfilesResponse`, `WorkProfileDetailsResponse`, `ListWorkProfilesResponse`, `WorkProfileStatusHistoryResponse`, `ResolveWorkingDepartmentResponse`, `CheckProfileCanJoinBrigadeResponse`, `CertificationTypeResponse`, `ListCertificationTypesResponse`, `CertificationTypeSkillResponse`, `RemoveCertificationTypeSkillResponse`, `ListCertificationTypeSkillsResponse`, `WorkProfileCertificationResponse`, `VerifyWorkProfileCertificationResponse`, `RevokeWorkProfileCertificationResponse`, `ExpireWorkProfileCertificationsResponse`, `ListWorkProfileCertificationsResponse`, `WorkProfileSkillGrantResponse`, `ListEffectiveWorkProfileSkillsResponse`, `BatchListEffectiveWorkProfileSkillsResponse`, `CheckWorkProfileHasSkillsResponse`.

## Функции

### `NewHandler`

Принимает обработчики всех внутренних сервисов, `AuthMiddleware` и `RedisRateLimiter`, сохраняет их в общем `Handler`.

### `Handler.InitRouters`

Создает `gin.Engine`, настраивает CORS из `CORS_ALLOWED_ORIGINS`, обработку `OPTIONS`, общие промежуточные обработчики, проверки `/health`, `/livez`, `/readyz`, публичные и защищенные группы маршрутов. На защищенные группы устанавливает JWT; WebSocket использует отдельную проверку токена.

### `handleGRPCError`

Преобразует `InvalidArgument` в 400, `Unauthenticated` в 401, `PermissionDenied` в 403, `NotFound` в 404, `AlreadyExists`/`Aborted`/`FailedPrecondition` в 409, `Canceled` в 408, `DeadlineExceeded` в 504, `Unavailable` в 503, остальные ошибки в 500.

### `writeAPIError`

Возвращает JSON с полями `code` и `error` и переданным HTTP-кодом.

### `NewAuthMiddleware`

Читает открытый ключ, проверяет его пригодность и сохраняет ожидаемые `issuer` и `audience`.

### `AuthMiddleware.Handle`

Извлекает Bearer-токен, проверяет JWT и помещает `user_id`, роли и остальные подтвержденные признаки в `gin.Context`. При любой ошибке завершает запрос с 401.

### `AuthMiddleware.HandleWebSocket`

Выполняет ту же проверку для соединения WebSocket с учетом поддерживаемого способа передачи токена.

### `extractBearerToken`

Требует заголовок вида `Bearer <token>`, обрезает пробелы и возвращает только токен.

### `RequestID`, `requestid.New`, `requestid.WithContext`, `requestid.FromContext`, `requestid.UnaryClientInterceptor`

Принимают корректный `X-Request-ID` либо создают новый, кладут его в HTTP- и Go-контекст и передают как метаданные gRPC.

### `IdempotencyKey`, `idempotency.WithContext`, `idempotency.FromContext`, `idempotency.UnaryClientInterceptor`

Проверяют и переносят ключ идемпотентности из HTTP-заголовка во внутренний вызов.

### `RequestLogger`

Записывает метод, путь, код, длительность, адрес клиента и идентификатор запроса после завершения обработки.

### `NewRedisRateLimiter`

Создает распределенный ограничитель на Redis, нормализует префикс и сохраняет настройку обхода для нагрузочных проверок.

### `RedisRateLimiter.Middleware`

Нормализует правило, вычисляет ключ клиента, вызывает `allow`, выставляет заголовки лимита и при превышении возвращает 429. Ошибка Redis обрабатывается согласно реализованной политике шлюза.

### `RedisRateLimiter.allow`

Атомарно выполняет Lua-сценарий Redis, возвращая разрешение, оставшийся запас и время до восстановления.

### `RateLimitConfig.normalize`, `redisInt`

Подставляют безопасные значения правила и преобразуют числовой ответ Redis в `int64`.

### `retry.UnaryClientInterceptor`

Повторяет только безопасные читающие операции и изменяющие операции с ключом идемпотентности. Учитывает контекст, задержки и только временные коды gRPC.

### `retry.shouldRetry`, `retry.isReadOnlyMethod`, `retry.isIdempotentMutation`, `retry.isRetryable`

Определяют допустимость повтора по методу, наличию ключа и коду ошибки.

### Обработчики авторизации

`NewAuthHandler` сохраняет клиент. `Register`, `Login`, `Refresh`, `VerifyEmail`, `RequestPasswordReset` и `ResetPassword` разбирают публичные запросы. `Logout`, `LogoutAll`, `GetUserAuthInfo`, `ChangePassword`, `SendVerificationEmail` используют подтвержденного пользователя. `GetJWKS` отдает набор открытых ключей. Каждый метод создает gRPC-запрос и передает ошибку в `handleGRPCError`.

### Обработчики заявок и отчетов

`NewTicketHandler` сохраняет клиентов заявок и бригад. `CreateTicket`, `GetTicket`, `ListTicket`, `UpdateTicket`, `ChangeTicketStatus`, `AssignBrigade`, `CancelTicket`, `CompleteTicket`, `GetTicketStatusHistory` обслуживают жизненный цикл заявки. `CreateWorkReport` и `ListWorkReports` при роли работника сначала определяют его активную бригаду. Методы категорий вызывают одноименные операции Ticket Service. `bindJSON`, `buildListTicketsRequest`, `buildUpdateTicketRequest` и преобразователи формируют строгий запрос.

### Обработчики бригад

`NewBrigadeHandler` сохраняет клиент. Методы от `CreateBrigade` до `CheckBrigadeCanHandleTicket` один к одному соответствуют операциям README `Brigade_Service`. `brigadeRequestContext` и `gatewayActorContext` добавляют подтвержденного исполнителя, `brigadeResponse` переводит ответ, а функции `ToProto*`/`FromProto*` преобразуют перечисления, сущности, списки, расписание и историю без бизнес-решений.

### Обработчики профилей

`NewProfileHandler` сохраняет клиент. Методы личных и рабочих профилей, сертификатов и навыков соответствуют README `Profile_Service`. `profileRequestContext` добавляет исполнителя, `profileResponse` возвращает JSON, а преобразователи `ToProto*`/`FromProto*` сохраняют необязательные поля, времена, перечисления и вложенные списки.

### Обработчики маршрутизации и назначения

`RoutingHandler.BuildRoute`, `BuildMatrix`, `RankCandidates`, `CreateRoute`, `GetRoute`, `RecalculateRoute`, `SetRouteStatus`, `ListRoutes` преобразуют координаты и параметры и вызывают Routing Service. `DispatchHandler.Preview`, `Reserve`, `Confirm`, `Auto`, `Get`, `List`, `Cancel` обслуживают подбор и подтверждение бригады. Контекстные функции передают исполнителя и идентификатор запроса.

### Обработчики местоположения и объектов

`LocationHandler` записывает позицию, читает текущее положение и историю, ищет бригады рядом и управляет геозонами. `AssetHandler` создает, ищет, разрешает по координате, изменяет объекты, регистрирует происшествия, ремонты, осмотры, планы и прогнозы. Вспомогательные функции преобразуют координаты, время и перечисления.

### Обработчики файлов, SLA, уведомлений, аудита и аналитики

`FileHandler` управляет загрузкой, подтверждением, связями, ссылками и удалением. `SLAHandler` управляет правилами и состоянием сроков заявок. `NotificationHandler` обслуживает уведомления, настройки, устройства, шаблоны, доставки и WebSocket. `AuditHandler` читает журнал. `AnalyticsHandler` вызывает все аналитические срезы и преобразует общий фильтр. `ReportHandler` создает, читает, отменяет, повторяет и скачивает формируемые отчеты.

## Структура БД

`API Gateway` не содержит SQL-миграций и не подключается к собственной базе данных. Redis используется только для распределенного ограничения частоты, а предметные и идемпотентные записи принадлежат внутренним сервисам.
