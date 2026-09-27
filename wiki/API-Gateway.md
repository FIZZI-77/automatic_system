# API-шлюз (API Gateway)

## Ответственность

Единая внешняя HTTP-точка. Преобразует JSON/HTTP в gRPC, проверяет identity и права, нормализует transport errors. Предметные данные не хранит.

## Ключевое поведение

- Middleware chain включает Request ID, idempotency metadata, Redis-backed rate limiting, structured request logging и JWT verification.
- Создаёт gRPC clients ко всем 15 backend domain services.
- Global limit: 300 requests/minute + burst 100; auth flows имеют отдельные более строгие limits.
- HTTP DTO живут в `models`, но не образуют самостоятельный persisted domain.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | Redis — rate limiting и live notification mechanics. |
| Синхронные взаимодействия | Auth, Profile, Department, Brigade, Ticket, Dispatch, Location, Routing, Asset, File, SLA, Notification, Audit, Analytics, Report. |
| Kafka | Gateway не является Kafka domain publisher. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Сигнатуры обработчиков, промежуточных функций и маршруты приведены в [справочнике API Gateway](https://automaticsystem.youtrack.cloud/articles/ACS-A-43/Kod-i-marshruty-API-Gateway).

### `NewHandler`

```go
func NewHandler(
    authHandler *AuthHandler,
    ticketHandler *TicketHandler,
    departmentHandler *DepartmentHandler,
    brigadeHandler *BrigadeHandler,
    profileHandler *ProfileHandler,
    locationHandler *LocationHandler,
    routingHandler *RoutingHandler,
    dispatchHandler *DispatchHandler,
    fileHandler *FileHandler,
    slaHandler *SLAHandler,
    notificationHandler *NotificationHandler,
    auditHandler *AuditHandler,
    analyticsHandler *AnalyticsHandler,
    reportHandler *ReportHandler,
    assetHandler *AssetHandler,
    authMiddleware *middleware.AuthMiddleware,
    rateLimiter *middleware.RedisRateLimiter,
) *Handler
```

Принимает обработчики всех внутренних сервисов, `AuthMiddleware` и `RedisRateLimiter`, сохраняет их в общем `Handler`.

### `Handler.InitRouters`

```go
func (h *Handler) InitRouters() *gin.Engine
```

Создает `gin.Engine`, настраивает CORS из `CORS_ALLOWED_ORIGINS`, обработку `OPTIONS`, общие промежуточные обработчики, проверки `/health`, `/livez`, `/readyz`, публичные и защищенные группы маршрутов. На защищенные группы устанавливает JWT; WebSocket использует отдельную проверку токена.

### `handleGRPCError`

```go
func handleGRPCError(c *gin.Context, err error)
```

Преобразует `InvalidArgument` в 400, `Unauthenticated` в 401, `PermissionDenied` в 403, `NotFound` в 404, `AlreadyExists`/`Aborted`/`FailedPrecondition` в 409, `Canceled` в 408, `DeadlineExceeded` в 504, `Unavailable` в 503, остальные ошибки в 500.

### `writeAPIError`

```go
func writeAPIError(c *gin.Context, statusCode int, code, message string)
```

Возвращает JSON с полями `code` и `error` и переданным HTTP-кодом.

### `NewAuthMiddleware`

```go
func NewAuthMiddleware(publicKeyPath string, issuer string, audience string) (*AuthMiddleware, error)
```

Читает открытый ключ, проверяет его пригодность и сохраняет ожидаемые `issuer` и `audience`.

### `AuthMiddleware.Handle`

```go
func (m *AuthMiddleware) Handle() gin.HandlerFunc
```

Извлекает Bearer-токен, проверяет JWT и помещает `user_id`, роли и остальные подтвержденные признаки в `gin.Context`. При любой ошибке завершает запрос с 401.

### `AuthMiddleware.HandleWebSocket`

```go
func (m *AuthMiddleware) HandleWebSocket() gin.HandlerFunc
```

Выполняет ту же проверку для соединения WebSocket с учетом поддерживаемого способа передачи токена.

### `extractBearerToken`

```go
func extractBearerToken(header string) (string, error)
```

Требует заголовок вида `Bearer <token>`, обрезает пробелы и возвращает только токен.

### `RequestID`, `requestid.New`, `requestid.WithContext`, `requestid.FromContext`, `requestid.UnaryClientInterceptor`

```go
func RequestID() gin.HandlerFunc
```

```go
func New() string
```

```go
func WithContext(ctx context.Context, requestID string) context.Context
```

```go
func FromContext(ctx context.Context) (string, bool)
```

```go
func UnaryClientInterceptor(
    ctx context.Context,
    method string,
    req interface{},
    reply interface{},
    cc *grpc.ClientConn,
    invoker grpc.UnaryInvoker,
    opts ...grpc.CallOption,
) error
```

```go
func WithContext(ctx context.Context, key string) context.Context
```

```go
func FromContext(ctx context.Context) (string, bool)
```

```go
func UnaryClientInterceptor(
    ctx context.Context,
    method string,
    req interface{},
    reply interface{},
    cc *grpc.ClientConn,
    invoker grpc.UnaryInvoker,
    opts ...grpc.CallOption,
) error
```

```go
func UnaryClientInterceptor(
    ctx context.Context,
    method string,
    req interface{},
    reply interface{},
    cc *grpc.ClientConn,
    invoker grpc.UnaryInvoker,
    opts ...grpc.CallOption,
) error
```

Принимают корректный `X-Request-ID` либо создают новый, кладут его в HTTP- и Go-контекст и передают как метаданные gRPC.

### `IdempotencyKey`, `idempotency.WithContext`, `idempotency.FromContext`, `idempotency.UnaryClientInterceptor`

```go
func IdempotencyKey() gin.HandlerFunc
```

Проверяют и переносят ключ идемпотентности из HTTP-заголовка во внутренний вызов.

### `RequestLogger`

```go
func RequestLogger() gin.HandlerFunc
```

Записывает метод, путь, код, длительность, адрес клиента и идентификатор запроса после завершения обработки.

### `NewRedisRateLimiter`

```go
func NewRedisRateLimiter(client redis.UniversalClient, prefix string, bypassLoadTests bool) *RedisRateLimiter
```

Создает распределенный ограничитель на Redis, нормализует префикс и сохраняет настройку обхода для нагрузочных проверок.

### `RedisRateLimiter.Middleware`

```go
func (l *RedisRateLimiter) Middleware(config RateLimitConfig) gin.HandlerFunc
```

Нормализует правило, вычисляет ключ клиента, вызывает `allow`, выставляет заголовки лимита и при превышении возвращает 429. Ошибка Redis обрабатывается согласно реализованной политике шлюза.

### `RedisRateLimiter.allow`

```go
func (l *RedisRateLimiter) allow(ctx context.Context, key string, config RateLimitConfig) (bool, int, time.Duration, error)
```

Атомарно выполняет Lua-сценарий Redis, возвращая разрешение, оставшийся запас и время до восстановления.

### `RateLimitConfig.normalize`, `redisInt`

```go
func redisInt(value any) (int64, error)
```

```go
func (c *RateLimitConfig) normalize()
```

Подставляют безопасные значения правила и преобразуют числовой ответ Redis в `int64`.

### `retry.UnaryClientInterceptor`

Повторяет только безопасные читающие операции и изменяющие операции с ключом идемпотентности. Учитывает контекст, задержки и только временные коды gRPC.

### `retry.shouldRetry`, `retry.isReadOnlyMethod`, `retry.isIdempotentMutation`, `retry.isRetryable`

```go
func shouldRetry(ctx context.Context, method string) bool
```

```go
func isReadOnlyMethod(method string) bool
```

```go
func isIdempotentMutation(method string) bool
```

```go
func isRetryable(err error) bool
```

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

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/API_Gateway/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/API_Gateway/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
