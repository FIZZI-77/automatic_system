# Сервис аутентификации (Auth Service)

## Ответственность

Учетные записи, роли, sessions, access/refresh tokens, email verification, password reset.

## Ключевое поведение

- Passwords сохраняются только как bcrypt hash.
- Refresh и one-time tokens хранятся как SHA-256/base64url hash, а не в исходном виде.
- Access JWT подписывается RSA private key; документированное время access token — 15 минут.
- Write flows поддерживают idempotency; значимые изменения сохраняют outbox event в той же transaction.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL; SMTP для почтовых flows. |
| Синхронные взаимодействия | Создаёт client к Profile Service. |
| Kafka | Publisher: `auth.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Полные сигнатуры и структуры параметров приведены в [справочнике функций Auth Service](https://automaticsystem.youtrack.cloud/articles/ACS-A-33/Kod-i-funkcii-Auth-Service).

### `NewAuthServiceStruct`

```go
func NewAuthServiceStruct(
repo *repository.Repo,
privateKey *rsa.PrivateKey,
keyID string,
mailService MailService,
profiles ProfileProvisioner,
logger *zap.Logger,
) *AuthServiceStruct
```

Создает основную реализацию прикладного слоя. Принимает объединенный репозиторий,
закрытый ключ RSA, идентификатор ключа, отправщик писем, клиент создания профиля
и журнал `zap`. Функция только сохраняет зависимости; их доступность здесь не
проверяется.

### `Register`

```go
func (a *AuthServiceStruct) Register(ctx context.Context, in models.RegisterInput) (*models.RegisterResult, error)
```

**Принимает:** `RegisterInput`. **Возвращает:** `RegisterResult`.

1. Нормализует почту и имя, проверяет формат и длины.
2. Выполняет операцию под ключом идемпотентности, если ключ присутствует.
3. Проверяет отсутствие пользователя с такой почтой.
4. Строит хеш пароля `bcrypt` и создает активного пользователя с
   неподтвержденной почтой.
5. Вызывает `ProfileProvisioner.CreateUserProfile`, передавая идентификатор и
   `Username` как полное имя профиля.
6. Если профиль создать не удалось, в отдельном контексте с пределом 5 секунд
   удаляет только что созданную регистрацию. При сбое компенсации объединяет
   обе ошибки.
7. Возвращает идентификатор, почту и `EmailVerified=false`.

### `Login`

```go
func (a *AuthServiceStruct) Login(ctx context.Context, in models.LoginInput) (*models.LoginResult, error)
```

**Принимает:** `LoginInput`. **Возвращает:** `LoginResult`.

1. Проверяет почту, пароль, идентификатор клиента, IP и данные клиента.
2. Находит пользователя по почте и запрещает вход отсутствующей или неактивной
   учетной записи.
3. Сравнивает пароль с хешем `bcrypt`.
4. Создает сессию сроком на 30 суток.
5. Получает роли пользователя и выпускает токен доступа.
6. Создает 32 случайных байта для токена обновления, сохраняет только его хеш.
7. Если любой шаг после создания сессии завершается ошибкой, вызывает
   `cleanupFailedLogin` и отзывает незавершенную сессию.
8. Возвращает оба исходных токена, сроки, идентификатор сессии и `Bearer`.

### `Refresh`

```go
func (a *AuthServiceStruct) Refresh(ctx context.Context, in models.RefreshInput) (*models.RefreshResult, error)
```

**Принимает:** `RefreshInput`. **Возвращает:** `RefreshResult`.

1. Проверяет вход и вычисляет хеш переданного токена.
2. Находит запись по хешу и отклоняет отсутствующий, просроченный или уже
   замененный токен.
3. Загружает сессию. Проверяет отзыв, срок действия, пользователя и точное
   совпадение `ClientID`.
4. Получает актуальные роли и выпускает новый токен доступа.
5. Создает новый токен обновления. Его срок ограничивается сроком сессии.
6. `MarkUsedAndReplaceToken` одной транзакцией помечает прежний токен
   использованным и отозванным, связывает его с новым и сохраняет новый.
7. Возвращает новую пару токенов для той же сессии.

`IP` и `UserAgent` в этом сценарии валидируются, но текущая реализация не
сравнивает их с сохраненными значениями и не обновляет ими сессию.

### `Logout`

```go
func (a *AuthServiceStruct) Logout(ctx context.Context, in models.LogoutInput) error
```

Проверяет идентификаторы пользователя и сессии, загружает сессию и убеждается,
что она принадлежит этому пользователю. Затем транзакционно отзывает сессию и
все ее токены обновления и создает событие `auth.session.logged_out`.

### `cleanupFailedLogin`

```go
func (a *AuthServiceStruct) cleanupFailedLogin(ctx context.Context, sessionID uuid.UUID, logger *zap.Logger)
```

Служебная компенсация незавершенного входа. Создает независимый от отмены
исходного запроса контекст на 2 секунды и вызывает ту же транзакцию выхода.
Ошибка компенсации только записывается в журнал, поскольку основной метод уже
возвращает исходную ошибку.

### `LogoutAll`

```go
func (a *AuthServiceStruct) LogoutAll(ctx context.Context, in models.LogoutAllInput) (uint32, error)
```

Проверяет `UserID`, убеждается в существовании пользователя и транзакционно
отзывает все его сессии и токены обновления. Возвращает число измененных сессий
как `uint32` и создает событие `auth.user.logged_out_all`.

### `GetUserAuthInfo`

```go
func (a *AuthServiceStruct) GetUserAuthInfo(ctx context.Context, userID uuid.UUID) (*models.UserAuthInfo, error)
```

Загружает пользователя и отдельно его роли. Возвращает идентификатор, почту,
роли, активность и состояние подтверждения почты. Поле `Permissions` в
текущем коде остается пустым.

### `GetJWKS`

```go
func (a *AuthServiceStruct) GetJWKS(ctx context.Context) (string, error)
```

Преобразует открытую часть настроенного ключа RSA в JWK, задает ей `kid`,
алгоритм `RS256` и назначение `sig`, добавляет ключ в набор и возвращает
набор как JSON. Закрытая часть ключа в ответ не включается.

### `ChangePassword`

```go
func (a *AuthServiceStruct) ChangePassword(ctx context.Context, in models.ChangePasswordInput) (*models.ChangePasswordResult, error)
```

1. Проверяет пользователя, сессию, оба пароля и их различие.
2. Запускает идемпотентную транзакционную операцию.
3. Загружает пользователя и проверяет старый пароль через `bcrypt`.
4. Хеширует новый пароль.
5. Репозиторий одной транзакцией обновляет хеш, отзывает либо все сессии, либо
   только указанную сессию и соответствующие токены обновления.
6. Создает событие `auth.user.password_changed` и возвращает число завершенных
   сессий.

### `SendVerification`

```go
func (a *AuthServiceStruct) SendVerification(ctx context.Context, in models.SendVerificationEmailInput) (*models.SendVerificationEmailResult, error)
```

1. Проверяет пользователя и необязательный адрес.
2. Загружает фактический адрес из записи пользователя и запрещает повторное
   подтверждение.
3. Помечает использованными все прежние неиспользованные токены подтверждения.
4. Создает новый случайный одноразовый токен, сохраняет хеш со сроком 24 часа.
5. Передает исходное значение почтовому слою.
6. Возвращает срок ссылки. Из-за внешней отправки письма используется отдельный
   вариант идемпотентности, не удерживающий транзакцию базы во время SMTP.

### `VerifyEmail`

```go
func (a *AuthServiceStruct) VerifyEmail(ctx context.Context, in models.VerifyEmailInput) (*models.VerifyEmailResult, error)
```

Вычисляет хеш токена, находит токен типа `email_verification`, проверяет
отсутствие `UsedAt` и срок действия. После проверки пользователя транзакционно
помечает токен использованным, выставляет `users.email_verified=true` и
создает событие `auth.user.email_verified`.

### `RequestPasswordReset`

```go
func (a *AuthServiceStruct) RequestPasswordReset(ctx context.Context, in models.RequestPasswordResetInput) (*models.RequestPasswordResetResult, error)
```

Нормализует и проверяет почту. Если пользователь не найден, возвращает успешный
ответ с нулевым сроком, не раскрывая наличие учетной записи. Для существующего
пользователя отзывает прежние токены восстановления, создает новый токен на
30 минут, сохраняет его хеш и отправляет исходное значение по почте.

### `ResetPassword`

```go
func (a *AuthServiceStruct) ResetPassword(ctx context.Context, in models.ResetPasswordInput) (*models.ResetPasswordResult, error)
```

Проверяет токен и новый пароль, затем выполняет идемпотентную операцию. Находит
токен типа `password_reset` по хешу, проверяет использование и срок, загружает
пользователя и хеширует новый пароль. Репозиторий одной транзакцией помечает
токен использованным, меняет пароль, отзывает все сессии и токены обновления и
создает событие `auth.user.password_reset`.

### `generateAccessToken`

```go
func (a *AuthServiceStruct) generateAccessToken(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID, roles []string) (string, int64, error)
```

Создает `JWT` с полями `sub` (пользователь), `sid` (сессия), `roles`,
`exp`, `iat`, `iss=auth-jwt` и `aud=api-gateway`. Подписывает его
`RS256` закрытым ключом и возвращает строку токена и срок действия.

### `generateRefreshToken` и `generateOpaqueToken`

```go
func (a *AuthServiceStruct) generateRefreshToken(ctx context.Context) (raw string, hash string, exp int64, err error)
```

```go
func (a *AuthServiceStruct) generateOpaqueToken(ctx context.Context) (raw string, hash string, err error)
```

Обе функции получают 32 криптографически случайных байта, кодируют исходное
значение как `base64url` и строят такой же кодированный хеш `SHA-256`.
`generateRefreshToken` дополнительно возвращает срок через 30 суток.

### `withIdempotency`

```go
func (a *AuthServiceStruct) withIdempotency(
ctx context.Context,
operation string,
actorKey string,
request any,
fn func(context.Context) (any, uuid.UUID, error),
) (any, error)
```

Если в контексте нет ключа идемпотентности, сразу выполняет переданную функцию.
Иначе вычисляет устойчивый хеш JSON-запроса и передает выполнение
`RunIdempotentTx`. Уже существующая запись проверяется на совпадение запроса:
`COMPLETED` возвращает сохраненный JSON, `PROCESSING` и `FAILED` дают
соответствующие ошибки. Срок записи — 24 часа.

### `withExternalSideEffectIdempotency`

```go
func (a *AuthServiceStruct) withExternalSideEffectIdempotency(
ctx context.Context,
operation string,
actorKey string,
request any,
fn func(context.Context) (any, uuid.UUID, error),
) (any, error)
```

Вариант для отправки писем и других внешних действий. Сначала отдельно создает
запись `PROCESSING`, затем выполняет действие вне транзакции. При ошибке
помечает запись `FAILED`; при успехе сериализует ответ и помечает запись
`COMPLETED`. Это не гарантирует строго однократную отправку при аварии между
SMTP и записью результата; комментарий в коде предусматривает перенос писем в
надежную очередь исходящих событий.

### `cachedResult`

```go
func cachedResult[T any](result any) (*T, error)
```

Приводит обычный или восстановленный из JSON результат к требуемому типу. Если
указатель уже имеет нужный тип, возвращает его без преобразования; иначе
выполняет промежуточную сериализацию и разбор JSON.

### `hashRequest`

```go
func hashRequest(request any) (string, error)
```

Сериализует запрос в JSON, вычисляет `SHA-256` и возвращает шестнадцатеричную
строку. Хеш позволяет обнаружить повторное использование одного ключа
идемпотентности с другими данными.

### `NewSMTPMailService`

```go
func NewSMTPMailService(cfg SMTPMailConfig, logger *zap.Logger) (*SMTPMailService, error)
```

Проверяет обязательные `Host`, `Port`, `FromEmail` и
`FrontendBaseURL`. Для отсутствующего или неположительного `Timeout`
устанавливает 10 секунд и создает почтовую реализацию.

### `SendVerificationEmail` и `SendPasswordResetEmail`

```go
func (s *SMTPMailService) SendVerificationEmail(ctx context.Context, toEmail string, token string) error
```

```go
func (s *SMTPMailService) SendPasswordResetEmail(ctx context.Context, toEmail string, token string) error
```

Строят соответственно пути `/verify-email` и `/reset-password` с параметром
`token`, формируют русские текстовую и HTML-версии письма и передают их в
`send`.

### `buildURL`

```go
func (s *SMTPMailService) buildURL(ctx context.Context, path string, params map[string]string) (string, error)
```

Разбирает `FrontendBaseURL`, удаляет завершающий косой знак, добавляет путь и
кодирует параметры стандартными средствами `net/url`. Возвращает полностью
собранную ссылку.

### `send`

```go
func (s *SMTPMailService) send(ctx context.Context, to []string, subject string, textBody string, htmlBody string) error
```

Сначала вызывает `buildMessage`, затем `sendSMTP`. Ошибки снабжаются
контекстом этапа; успешная отправка записывается в журнал.

### `buildMessage`

```go
func (s *SMTPMailService) buildMessage(to []string, subject string, textBody string, htmlBody string) ([]byte, error)
```

Формирует сообщение `multipart/alternative`: заголовки отправителя,
получателей и темы, текстовую часть и HTML-часть. Русские имя отправителя и тема
кодируются по MIME. Граница частей строится из текущего времени.

### `sendSMTP`

```go
func (s *SMTPMailService) sendSMTP(ctx context.Context, to []string, msg []byte) error
```

1. Открывает соединение с ограничением `Timeout`.
2. При `UseTLS` сразу использует TLS; иначе создает обычное соединение.
3. При `UseStartTLS` проверяет поддержку команды и повышает защиту соединения.
4. Если задано имя пользователя, выполняет `PlainAuth`.
5. Передает отправителя, каждого получателя и тело сообщения.
6. Закрывает поток данных, отправляет `QUIT` и закрывает клиент.

### `NewService` и `NewAuthService`

```go
func NewService(
repo *repository.Repository,
privateKey *rsa.PrivateKey,
keyID string,
mailService MailService,
profileProvisioner ProfileProvisioner,
logger *zap.Logger,
) *Service
```

```go
func NewAuthService(
repo *repository.Repo,
privateKey *rsa.PrivateKey,
keyID string,
mailService MailService,
profileProvisioner ProfileProvisioner,
logger *zap.Logger,
) *Service
```

`NewService` заменяет отсутствующий журнал на `zap.NewNop()`, создает
`AuthServiceStruct` и объединяет прикладной и почтовый интерфейсы в
`Service`. `NewAuthService` является совместимым псевдонимом и просто
вызывает `NewService`.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
