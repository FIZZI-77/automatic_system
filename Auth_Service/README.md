# Сервис аутентификации (Auth Service)

## Общее описание и общий принцип работы

`Auth_Service` управляет учетными записями, паролями, ролями, пользовательскими
сессиями и токенами. Сервис также подтверждает электронную почту, восстанавливает
пароль и предоставляет открытый ключ, которым шлюз проверяет подпись токена
доступа.

Основной порядок обработки запроса:

1. Обработчик gRPC преобразует запрос во входную модель.
2. Метод прикладного слоя нормализует и проверяет входные данные.
3. Репозиторий читает или изменяет PostgreSQL. Связанные изменения выполняются
   в одной транзакции.
4. Метод возвращает модель результата либо предметную ошибку из
   `models/errors.go`.
5. Значимые изменения записываются в `outbox_events` и затем публикуются
   отдельным издателем событий.

Пароль хранится только как хеш `bcrypt`. Токены обновления и одноразовые
токены также не сохраняются в исходном виде: в базе находится результат
`SHA-256`, закодированный как `base64url`. Токен доступа представляет собой
`JWT`, подписанный закрытым ключом RSA. Он действует 15 минут. Сессия и токен
обновления обычно действуют 30 суток, ссылка подтверждения почты — 24 часа,
ссылка восстановления пароля — 30 минут.

Повторяемые изменяющие запросы могут использовать ключ идемпотентности. Для
одинакового ключа и одинаковых данных сервис возвращает сохраненный результат,
а повторное применение того же ключа к другим данным завершает ошибкой
`ErrIdempotencyConflict`.

## Модели

### Перечисление `TokenType`

| Значение | Назначение |
|---|---|
| `email_verification` | Подтверждение электронной почты. |
| `password_reset` | Восстановление пароля. |

### `OneTimeToken`

| Поле | Тип Go | Назначение |
|---|---|---|
| `ID` | `uuid.UUID` | Идентификатор одноразового токена. |
| `UserID` | `uuid.UUID` | Пользователь, для которого создан токен. |
| `TokenHash` | `string` | Хеш секретного значения; исходное значение в базе не хранится. |
| `Type` | `TokenType` | Назначение токена. |
| `ExpiresAt` | `time.Time` | Момент окончания срока действия. |
| `UsedAt` | `*time.Time` | Момент использования; `nil` означает, что токен еще не применен. |
| `CreatedAt` | `time.Time` | Момент создания записи. |

### Входные и выходные модели

В этом разделе описаны структуры `RegisterInput`, `RegisterResult`, `LoginInput`, `LoginResult`, `RefreshInput`, `RefreshResult`, `LogoutInput`, `LogoutAllInput`, `ChangePasswordInput`, `ChangePasswordResult`, `SendVerificationEmailInput`, `SendVerificationEmailResult`, `VerifyEmailInput`, `VerifyEmailResult`, `RequestPasswordResetInput`, `RequestPasswordResetResult`, `ResetPasswordInput` и `ResetPasswordResult`.

| Структура и поле | Тип Go | Назначение |
|---|---|---|
| `RegisterInput.Email` | `string` | Электронная почта новой учетной записи. |
| `RegisterInput.Password` | `string` | Исходный пароль, передаваемый только для проверки и хеширования. |
| `RegisterInput.Username` | `string` | Имя пользователя и исходное полное имя создаваемого профиля. |
| `RegisterResult.UserID` | `string` | Идентификатор созданного пользователя в строковом виде. |
| `RegisterResult.Email` | `string` | Нормализованная электронная почта. |
| `RegisterResult.EmailVerified` | `bool` | Признак подтверждения почты; после регистрации равен `false`. |
| `LoginInput.Email` | `string` | Электронная почта для поиска пользователя. |
| `LoginInput.Password` | `string` | Пароль для сравнения с хешем. |
| `LoginInput.ClientID` | `string` | Идентификатор клиентского приложения или устройства. |
| `LoginInput.IP` | `string` | IP-адрес клиента. |
| `LoginInput.UserAgent` | `string` | Строка с данными о клиентском приложении. |
| `LoginResult.AccessToken` | `string` | Подписанный токен доступа. |
| `LoginResult.RefreshToken` | `string` | Исходное значение токена обновления, выдаваемое клиенту один раз. |
| `LoginResult.AccessExpiresAtUnix` | `int64` | Окончание действия токена доступа в секундах Unix. |
| `LoginResult.RefreshExpiresAtUnix` | `int64` | Окончание действия токена обновления в секундах Unix. |
| `LoginResult.SessionID` | `uuid.UUID` | Идентификатор созданной сессии. |
| `LoginResult.TokenType` | `string` | Схема авторизации; метод возвращает `Bearer`. |
| `RefreshInput.RefreshToken` | `string` | Действующий исходный токен обновления. |
| `RefreshInput.ClientID` | `string` | Идентификатор клиента, который должен совпасть с сессией. |
| `RefreshInput.IP` | `string` | Текущий IP-адрес; проверяется формат, но значение не записывается в сессию. |
| `RefreshInput.UserAgent` | `string` | Данные клиента; проверяются на непустое значение. |
| `RefreshResult.*` | как в `LoginResult` | Новая пара токенов, их сроки и прежний идентификатор сессии. |
| `LogoutInput.UserID` | `uuid.UUID` | Пользователь, которому должна принадлежать завершаемая сессия. |
| `LogoutInput.SessionID` | `uuid.UUID` | Завершаемая сессия. |
| `LogoutAllInput.UserID` | `uuid.UUID` | Пользователь, все сессии которого требуется завершить. |
| `ChangePasswordInput.UserID` | `uuid.UUID` | Пользователь, меняющий пароль. |
| `ChangePasswordInput.OldPassword` | `string` | Текущий пароль для подтверждения операции. |
| `ChangePasswordInput.NewPassword` | `string` | Новый пароль. |
| `ChangePasswordInput.SessionID` | `uuid.UUID` | Текущая сессия. |
| `ChangePasswordInput.RevokeOtherSessions` | `bool` | Если `true`, отзываются все сессии; иначе только указанная текущая сессия. |
| `ChangePasswordResult.Success` | `bool` | Признак успешной смены пароля. |
| `ChangePasswordResult.InvalidatedSessionsCount` | `int32` | Число отозванных сессий. |
| `SendVerificationEmailInput.UserID` | `uuid.UUID` | Пользователь, которому отправляется письмо. |
| `SendVerificationEmailInput.Email` | `string` | Необязательное проверяемое поле; фактический адрес берется из записи пользователя. |
| `SendVerificationEmailResult.Success` | `bool` | Признак успешного создания токена и отправки письма. |
| `SendVerificationEmailResult.ExpiresAtUnix` | `int64` | Срок действия ссылки в секундах Unix. |
| `VerifyEmailInput.Token` | `string` | Исходный одноразовый токен из ссылки. |
| `VerifyEmailResult.Success` | `bool` | Признак успешного подтверждения. |
| `VerifyEmailResult.UserID` | `uuid.UUID` | Пользователь с подтвержденной почтой. |
| `VerifyEmailResult.Email` | `string` | Подтвержденный адрес. |
| `VerifyEmailResult.EmailVerified` | `bool` | Новое состояние признака подтверждения. |
| `VerifyEmailResult.Message` | `string` | Текст результата. |
| `RequestPasswordResetInput.Email` | `string` | Адрес учетной записи для восстановления. |
| `RequestPasswordResetResult.Success` | `bool` | Всегда скрывает факт существования адреса и при корректном запросе равен `true`. |
| `RequestPasswordResetResult.ExpiresAtUnix` | `int64` | Срок ссылки; равен нулю, если пользователь не найден. |
| `ResetPasswordInput.Token` | `string` | Одноразовый токен восстановления. |
| `ResetPasswordInput.NewPassword` | `string` | Новый пароль. |
| `ResetPasswordResult.Success` | `bool` | Признак успешного восстановления. |
| `ResetPasswordResult.InvalidatedSessionsCount` | `int32` | Число завершенных сессий пользователя. |

### Хранимые предметные модели

К хранимым и составным предметным моделям относятся `User`, `Session`, `RefreshToken` и `UserAuthInfo`. Первые три соответствуют данным учетной записи, сеанса и токена обновления; `UserAuthInfo` объединяет сведения, возвращаемые при проверке пользователя.

| Структура и поле | Тип Go | Назначение |
|---|---|---|
| `User.ID` | `uuid.UUID` | Идентификатор пользователя. |
| `User.Email` | `string` | Уникальная электронная почта. |
| `User.Username` | `string` | Уникальное имя пользователя. |
| `User.PasswordHash` | `string` | Хеш пароля `bcrypt`. |
| `User.IsActive` | `bool` | Разрешен ли вход в учетную запись. |
| `User.EmailVerified` | `bool` | Подтверждена ли электронная почта. |
| `User.CreatedAt` | `time.Time` | Время создания. |
| `User.UpdatedAt` | `time.Time` | Время последнего изменения. |
| `Session.ID` | `uuid.UUID` | Идентификатор входа пользователя. |
| `Session.UserID` | `uuid.UUID` | Владелец сессии. |
| `Session.ClientID` | `string` | Клиентское приложение или устройство. |
| `Session.IP` | `string` | IP-адрес при входе. |
| `Session.UserAgent` | `string` | Данные клиентского приложения при входе. |
| `Session.IsRevoked` | `bool` | Признак принудительного завершения. |
| `Session.RevokedAt` | `*time.Time` | Время завершения. |
| `Session.ExpiresAt` | `time.Time` | Предельный срок действия. |
| `Session.LastSeenAt` | `*time.Time` | Последняя зафиксированная активность. |
| `Session.CreatedAt` | `time.Time` | Время создания. |
| `RefreshToken.ID` | `uuid.UUID` | Идентификатор записи токена обновления. |
| `RefreshToken.UserID` | `uuid.UUID` | Владелец токена. |
| `RefreshToken.SessionID` | `uuid.UUID` | Сессия токена. |
| `RefreshToken.TokenHash` | `string` | Хеш секретного значения. |
| `RefreshToken.IsRevoked` | `bool` | Признак отзыва. |
| `RefreshToken.RevokedAt` | `*time.Time` | Время отзыва. |
| `RefreshToken.ExpiresAt` | `time.Time` | Срок действия. |
| `RefreshToken.UsedAt` | `*time.Time` | Время применения при обновлении пары токенов. |
| `RefreshToken.ReplacedByTokenID` | `*string` | Идентификатор следующего токена в цепочке замены. |
| `RefreshToken.CreatedAt` | `time.Time` | Время создания. |
| `UserAuthInfo.UserID` | `uuid.UUID` | Идентификатор пользователя. |
| `UserAuthInfo.Email` | `string` | Электронная почта. |
| `UserAuthInfo.Roles` | `[]string` | Роли, прочитанные из базы. |
| `UserAuthInfo.Permissions` | `[]string` | Поле для разрешений; текущий метод его не заполняет. |
| `UserAuthInfo.IsActive` | `bool` | Признак активной учетной записи. |
| `UserAuthInfo.EmailVerified` | `bool` | Признак подтвержденной почты. |

### Настройка почты

| Поле `SMTPMailConfig` | Тип Go | Назначение |
|---|---|---|
| `Host` | `string` | Имя узла почтового сервера. |
| `Port` | `int` | Порт почтового сервера. |
| `Username`, `Password` | `string` | Учетные данные для проверки подлинности; имя может быть пустым. |
| `FromEmail` | `string` | Адрес отправителя. |
| `FromName` | `string` | Отображаемое имя отправителя. |
| `FrontendBaseURL` | `string` | Основа ссылок подтверждения и восстановления. |
| `UseTLS` | `bool` | Сразу устанавливать защищенное соединение. |
| `UseStartTLS` | `bool` | Перевести обычное соединение в защищенное командой `STARTTLS`. |
| `InsecureSkipVerify` | `bool` | Отключить проверку сертификата; предназначено только для доверенной испытательной среды. |
| `Timeout` | `time.Duration` | Ограничение времени соединения; при нуле используется 10 секунд. |

### Проверка моделей

`normalizeEmail` удаляет пробелы по краям и приводит адрес к нижнему регистру.
`normalizeString` удаляет пробелы по краям. `isEmailValid` разбирает адрес
средствами `net/mail`, а `isIPValid` — средствами `net`.
`validatePassword` требует не менее восьми символов Unicode.
`validateUsername` требует от 3 до 100 символов Unicode.

Методы `Validate` изменяют нормализуемые поля непосредственно во входной
структуре и затем проверяют обязательность, формат и ограничения. Для смены
пароля дополнительно обязательны `UserID`, `SessionID`, старый пароль и
отличие нового пароля от старого.

## Функции

Имя функции открывает её реализацию в ветке `test`; структуры параметров и результатов описаны в конце README.

### func [NewAuthServiceStruct](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L42)

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

Типы: [AuthServiceStruct](#type-authservicestruct), [MailService](#type-mailservice), [ProfileProvisioner](#type-profileprovisioner).

Структуры: [MailService](#type-mailservice), [ProfileProvisioner](#type-profileprovisioner), [AuthServiceStruct](#type-authservicestruct).

Создает основную реализацию прикладного слоя. Принимает объединенный репозиторий,
закрытый ключ RSA, идентификатор ключа, отправщик писем, клиент создания профиля
и журнал `zap`. Функция только сохраняет зависимости; их доступность здесь не
проверяется.

### func (*AuthServiceStruct) [Register](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L60)

```go
func (a *AuthServiceStruct) Register(ctx context.Context, in models.RegisterInput) (*models.RegisterResult, error)
```

Типы: [AuthServiceStruct](#type-authservicestruct), [RegisterInput](#type-registerinput), [RegisterResult](#type-registerresult).

Структуры: [RegisterInput](#type-registerinput), [RegisterResult](#type-registerresult).

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

### func (*AuthServiceStruct) [Login](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L177)

```go
func (a *AuthServiceStruct) Login(ctx context.Context, in models.LoginInput) (*models.LoginResult, error)
```

Типы: [AuthServiceStruct](#type-authservicestruct), [LoginInput](#type-logininput), [LoginResult](#type-loginresult).

Структуры: [LoginInput](#type-logininput), [LoginResult](#type-loginresult).

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

### func (*AuthServiceStruct) [Refresh](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L307)

```go
func (a *AuthServiceStruct) Refresh(ctx context.Context, in models.RefreshInput) (*models.RefreshResult, error)
```

Типы: [AuthServiceStruct](#type-authservicestruct), [RefreshInput](#type-refreshinput), [RefreshResult](#type-refreshresult).

Структуры: [RefreshInput](#type-refreshinput), [RefreshResult](#type-refreshresult).

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

### func (*AuthServiceStruct) [Logout](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L459)

```go
func (a *AuthServiceStruct) Logout(ctx context.Context, in models.LogoutInput) error
```

Типы: [AuthServiceStruct](#type-authservicestruct), [LogoutInput](#type-logoutinput).

Структуры: [LogoutInput](#type-logoutinput).

Проверяет идентификаторы пользователя и сессии, загружает сессию и убеждается,
что она принадлежит этому пользователю. Затем транзакционно отзывает сессию и
все ее токены обновления и создает событие `auth.session.logged_out`.

### func (*AuthServiceStruct) [cleanupFailedLogin](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L515)

```go
func (a *AuthServiceStruct) cleanupFailedLogin(ctx context.Context, sessionID uuid.UUID, logger *zap.Logger)
```

Типы: [AuthServiceStruct](#type-authservicestruct).

Служебная компенсация незавершенного входа. Создает независимый от отмены
исходного запроса контекст на 2 секунды и вызывает ту же транзакцию выхода.
Ошибка компенсации только записывается в журнал, поскольку основной метод уже
возвращает исходную ошибку.

### func (*AuthServiceStruct) [LogoutAll](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L526)

```go
func (a *AuthServiceStruct) LogoutAll(ctx context.Context, in models.LogoutAllInput) (uint32, error)
```

Типы: [AuthServiceStruct](#type-authservicestruct), [LogoutAllInput](#type-logoutallinput).

Структуры: [LogoutAllInput](#type-logoutallinput).

Проверяет `UserID`, убеждается в существовании пользователя и транзакционно
отзывает все его сессии и токены обновления. Возвращает число измененных сессий
как `uint32` и создает событие `auth.user.logged_out_all`.

### func (*AuthServiceStruct) [GetUserAuthInfo](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L574)

```go
func (a *AuthServiceStruct) GetUserAuthInfo(ctx context.Context, userID uuid.UUID) (*models.UserAuthInfo, error)
```

Типы: [AuthServiceStruct](#type-authservicestruct), [UserAuthInfo](#type-userauthinfo).

Структуры: [UserAuthInfo](#type-userauthinfo).

Загружает пользователя и отдельно его роли. Возвращает идентификатор, почту,
роли, активность и состояние подтверждения почты. Поле `Permissions` в
текущем коде остается пустым.

### func (*AuthServiceStruct) [GetJWKS](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L621)

```go
func (a *AuthServiceStruct) GetJWKS(ctx context.Context) (string, error)
```

Типы: [AuthServiceStruct](#type-authservicestruct).

Преобразует открытую часть настроенного ключа RSA в JWK, задает ей `kid`,
алгоритм `RS256` и назначение `sig`, добавляет ключ в набор и возвращает
набор как JSON. Закрытая часть ключа в ответ не включается.

### func (*AuthServiceStruct) [ChangePassword](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L685)

```go
func (a *AuthServiceStruct) ChangePassword(ctx context.Context, in models.ChangePasswordInput) (*models.ChangePasswordResult, error)
```

Типы: [AuthServiceStruct](#type-authservicestruct), [ChangePasswordInput](#type-changepasswordinput), [ChangePasswordResult](#type-changepasswordresult).

Структуры: [ChangePasswordInput](#type-changepasswordinput), [ChangePasswordResult](#type-changepasswordresult).

1. Проверяет пользователя, сессию, оба пароля и их различие.
2. Запускает идемпотентную транзакционную операцию.
3. Загружает пользователя и проверяет старый пароль через `bcrypt`.
4. Хеширует новый пароль.
5. Репозиторий одной транзакцией обновляет хеш, отзывает либо все сессии, либо
   только указанную сессию и соответствующие токены обновления.
6. Создает событие `auth.user.password_changed` и возвращает число завершенных
   сессий.

### func (*AuthServiceStruct) [SendVerification](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L764)

```go
func (a *AuthServiceStruct) SendVerification(ctx context.Context, in models.SendVerificationEmailInput) (*models.SendVerificationEmailResult, error)
```

Типы: [AuthServiceStruct](#type-authservicestruct), [SendVerificationEmailInput](#type-sendverificationemailinput), [SendVerificationEmailResult](#type-sendverificationemailresult).

Структуры: [SendVerificationEmailInput](#type-sendverificationemailinput), [SendVerificationEmailResult](#type-sendverificationemailresult).

1. Проверяет пользователя и необязательный адрес.
2. Загружает фактический адрес из записи пользователя и запрещает повторное
   подтверждение.
3. Помечает использованными все прежние неиспользованные токены подтверждения.
4. Создает новый случайный одноразовый токен, сохраняет хеш со сроком 24 часа.
5. Передает исходное значение почтовому слою.
6. Возвращает срок ссылки. Из-за внешней отправки письма используется отдельный
   вариант идемпотентности, не удерживающий транзакцию базы во время SMTP.

### func (*AuthServiceStruct) [VerifyEmail](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L865)

```go
func (a *AuthServiceStruct) VerifyEmail(ctx context.Context, in models.VerifyEmailInput) (*models.VerifyEmailResult, error)
```

Типы: [AuthServiceStruct](#type-authservicestruct), [VerifyEmailInput](#type-verifyemailinput), [VerifyEmailResult](#type-verifyemailresult).

Структуры: [VerifyEmailInput](#type-verifyemailinput), [VerifyEmailResult](#type-verifyemailresult).

Вычисляет хеш токена, находит токен типа `email_verification`, проверяет
отсутствие `UsedAt` и срок действия. После проверки пользователя транзакционно
помечает токен использованным, выставляет `users.email_verified=true` и
создает событие `auth.user.email_verified`.

### func (*AuthServiceStruct) [RequestPasswordReset](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L935)

```go
func (a *AuthServiceStruct) RequestPasswordReset(ctx context.Context, in models.RequestPasswordResetInput) (*models.RequestPasswordResetResult, error)
```

Типы: [AuthServiceStruct](#type-authservicestruct), [RequestPasswordResetInput](#type-requestpasswordresetinput), [RequestPasswordResetResult](#type-requestpasswordresetresult).

Структуры: [RequestPasswordResetInput](#type-requestpasswordresetinput), [RequestPasswordResetResult](#type-requestpasswordresetresult).

Нормализует и проверяет почту. Если пользователь не найден, возвращает успешный
ответ с нулевым сроком, не раскрывая наличие учетной записи. Для существующего
пользователя отзывает прежние токены восстановления, создает новый токен на
30 минут, сохраняет его хеш и отправляет исходное значение по почте.

### func (*AuthServiceStruct) [ResetPassword](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L1022)

```go
func (a *AuthServiceStruct) ResetPassword(ctx context.Context, in models.ResetPasswordInput) (*models.ResetPasswordResult, error)
```

Типы: [AuthServiceStruct](#type-authservicestruct), [ResetPasswordInput](#type-resetpasswordinput), [ResetPasswordResult](#type-resetpasswordresult).

Структуры: [ResetPasswordInput](#type-resetpasswordinput), [ResetPasswordResult](#type-resetpasswordresult).

Проверяет токен и новый пароль, затем выполняет идемпотентную операцию. Находит
токен типа `password_reset` по хешу, проверяет использование и срок, загружает
пользователя и хеширует новый пароль. Репозиторий одной транзакцией помечает
токен использованным, меняет пароль, отзывает все сессии и токены обновления и
создает событие `auth.user.password_reset`.

### func (*AuthServiceStruct) [generateAccessToken](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L1102)

```go
func (a *AuthServiceStruct) generateAccessToken(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID, roles []string) (string, int64, error)
```

Типы: [AuthServiceStruct](#type-authservicestruct).

Создает `JWT` с полями `sub` (пользователь), `sid` (сессия), `roles`,
`exp`, `iat`, `iss=auth-jwt` и `aud=api-gateway`. Подписывает его
`RS256` закрытым ключом и возвращает строку токена и срок действия.

### func (*AuthServiceStruct) [generateRefreshToken](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L1133)

```go
func (a *AuthServiceStruct) generateRefreshToken(ctx context.Context) (raw string, hash string, exp int64, err error)
```

Типы: [AuthServiceStruct](#type-authservicestruct).

Обе функции получают 32 криптографически случайных байта, кодируют исходное
значение как `base64url` и строят такой же кодированный хеш `SHA-256`.
`generateRefreshToken` дополнительно возвращает срок через 30 суток.

### func (*AuthServiceStruct) [generateOpaqueToken](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/auth_service.go#L1157)

```go
func (a *AuthServiceStruct) generateOpaqueToken(ctx context.Context) (raw string, hash string, err error)
```

Типы: [AuthServiceStruct](#type-authservicestruct).

Обе функции получают 32 криптографически случайных байта, кодируют исходное
значение как `base64url` и строят такой же кодированный хеш `SHA-256`.
`generateRefreshToken` дополнительно возвращает срок через 30 суток.

### func (*AuthServiceStruct) [withIdempotency](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/idempotency.go#L19)

```go
func (a *AuthServiceStruct) withIdempotency(
    ctx context.Context,
    operation string,
    actorKey string,
    request any,
    fn func(context.Context) (any, uuid.UUID, error),
) (any, error)
```

Типы: [AuthServiceStruct](#type-authservicestruct).

Если в контексте нет ключа идемпотентности, сразу выполняет переданную функцию.
Иначе вычисляет устойчивый хеш JSON-запроса и передает выполнение
`RunIdempotentTx`. Уже существующая запись проверяется на совпадение запроса:
`COMPLETED` возвращает сохраненный JSON, `PROCESSING` и `FAILED` дают
соответствующие ошибки. Срок записи — 24 часа.

### func (*AuthServiceStruct) [withExternalSideEffectIdempotency](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/idempotency.go#L71)

```go
func (a *AuthServiceStruct) withExternalSideEffectIdempotency(
    ctx context.Context,
    operation string,
    actorKey string,
    request any,
    fn func(context.Context) (any, uuid.UUID, error),
) (any, error)
```

Типы: [AuthServiceStruct](#type-authservicestruct).

Вариант для отправки писем и других внешних действий. Сначала отдельно создает
запись `PROCESSING`, затем выполняет действие вне транзакции. При ошибке
помечает запись `FAILED`; при успехе сериализует ответ и помечает запись
`COMPLETED`. Это не гарантирует строго однократную отправку при аварии между
SMTP и записью результата; комментарий в коде предусматривает перенос писем в
надежную очередь исходящих событий.

### func [cachedResult](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/idempotency.go#L126)

```go
func cachedResult[T any](result any) (*T, error)
```

Приводит обычный или восстановленный из JSON результат к требуемому типу. Если
указатель уже имеет нужный тип, возвращает его без преобразования; иначе
выполняет промежуточную сериализацию и разбор JSON.

### func [hashRequest](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/idempotency.go#L144)

```go
func hashRequest(request any) (string, error)
```

Сериализует запрос в JSON, вычисляет `SHA-256` и возвращает шестнадцатеричную
строку. Хеш позволяет обнаружить повторное использование одного ключа
идемпотентности с другими данными.

### func [NewSMTPMailService](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/mail_service.go#L39)

```go
func NewSMTPMailService(cfg SMTPMailConfig, logger *zap.Logger) (*SMTPMailService, error)
```

Типы: [SMTPMailConfig](#type-smtpmailconfig), [SMTPMailService](#type-smtpmailservice).

Структуры: [SMTPMailConfig](#type-smtpmailconfig), [SMTPMailService](#type-smtpmailservice).

Проверяет обязательные `Host`, `Port`, `FromEmail` и
`FrontendBaseURL`. Для отсутствующего или неположительного `Timeout`
устанавливает 10 секунд и создает почтовую реализацию.

### func (*SMTPMailService) [SendVerificationEmail](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/mail_service.go#L62)

```go
func (s *SMTPMailService) SendVerificationEmail(ctx context.Context, toEmail string, token string) error
```

Типы: [SMTPMailService](#type-smtpmailservice).

Строят соответственно пути `/verify-email` и `/reset-password` с параметром
`token`, формируют русские текстовую и HTML-версии письма и передают их в
`send`.

### func (*SMTPMailService) [SendPasswordResetEmail](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/mail_service.go#L103)

```go
func (s *SMTPMailService) SendPasswordResetEmail(ctx context.Context, toEmail string, token string) error
```

Типы: [SMTPMailService](#type-smtpmailservice).

Строят соответственно пути `/verify-email` и `/reset-password` с параметром
`token`, формируют русские текстовую и HTML-версии письма и передают их в
`send`.

### func (*SMTPMailService) [buildURL](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/mail_service.go#L144)

```go
func (s *SMTPMailService) buildURL(ctx context.Context, path string, params map[string]string) (string, error)
```

Типы: [SMTPMailService](#type-smtpmailservice).

Разбирает `FrontendBaseURL`, удаляет завершающий косой знак, добавляет путь и
кодирует параметры стандартными средствами `net/url`. Возвращает полностью
собранную ссылку.

### func (*SMTPMailService) [send](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/mail_service.go#L168)

```go
func (s *SMTPMailService) send(ctx context.Context, to []string, subject string, textBody string, htmlBody string) error
```

Типы: [SMTPMailService](#type-smtpmailservice).

Сначала вызывает `buildMessage`, затем `sendSMTP`. Ошибки снабжаются
контекстом этапа; успешная отправка записывается в журнал.

### func (*SMTPMailService) [buildMessage](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/mail_service.go#L187)

```go
func (s *SMTPMailService) buildMessage(to []string, subject string, textBody string, htmlBody string) ([]byte, error)
```

Типы: [SMTPMailService](#type-smtpmailservice).

Формирует сообщение `multipart/alternative`: заголовки отправителя,
получателей и темы, текстовую часть и HTML-часть. Русские имя отправителя и тема
кодируются по MIME. Граница частей строится из текущего времени.

### func (*SMTPMailService) [sendSMTP](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/mail_service.go#L226)

```go
func (s *SMTPMailService) sendSMTP(ctx context.Context, to []string, msg []byte) error
```

Типы: [SMTPMailService](#type-smtpmailservice).

1. Открывает соединение с ограничением `Timeout`.
2. При `UseTLS` сразу использует TLS; иначе создает обычное соединение.
3. При `UseStartTLS` проверяет поддержку команды и повышает защиту соединения.
4. Если задано имя пользователя, выполняет `PlainAuth`.
5. Передает отправителя, каждого получателя и тело сообщения.
6. Закрывает поток данных, отправляет `QUIT` и закрывает клиент.

### func [NewService](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/service.go#L44)

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

Типы: [MailService](#type-mailservice), [ProfileProvisioner](#type-profileprovisioner), [Repository](#type-repository), [Service](#type-service).

Структуры: [MailService](#type-mailservice), [ProfileProvisioner](#type-profileprovisioner).

`NewService` заменяет отсутствующий журнал на `zap.NewNop()`, создает
`AuthServiceStruct` и объединяет прикладной и почтовый интерфейсы в
`Service`. `NewAuthService` является совместимым псевдонимом и просто
вызывает `NewService`.

### func [NewAuthService](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/src/core/service/service.go#L70)

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

Типы: [MailService](#type-mailservice), [ProfileProvisioner](#type-profileprovisioner), [Service](#type-service).

Структуры: [MailService](#type-mailservice), [ProfileProvisioner](#type-profileprovisioner).

`NewService` заменяет отсутствующий журнал на `zap.NewNop()`, создает
`AuthServiceStruct` и объединяет прикладной и почтовый интерфейсы в
`Service`. `NewAuthService` является совместимым псевдонимом и просто
вызывает `NewService`.

## Структура БД

Ниже приведено итоговое состояние схемы после применения всех миграций из
`scheme`. Каждой таблице соответствует отдельная таблица документации.

### `users` — пользователи

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `UUID` | Первичный ключ, по умолчанию `gen_random_uuid()`. |
| `email` | `VARCHAR(255)` | Электронная почта; обязательна и уникальна. |
| `username` | `VARCHAR(100)` | Имя пользователя; обязательно и уникально. |
| `password_hash` | `TEXT` | Хеш пароля; обязателен. |
| `email_verified` | `BOOLEAN` | Подтверждение почты; по умолчанию `FALSE`. |
| `is_active` | `BOOLEAN` | Возможность входа; по умолчанию `TRUE`. |
| `created_at` | `TIMESTAMPTZ` | Время создания, по умолчанию `NOW()`. |
| `updated_at` | `TIMESTAMPTZ` | Время изменения, по умолчанию `NOW()`; автоматического триггера в миграциях нет. |

### `sessions` — пользовательские сессии

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `UUID` | Первичный ключ. |
| `user_id` | `UUID` | Владелец, внешний ключ на `users.id` с каскадным удалением. |
| `client_id` | `VARCHAR(100)` | Идентификатор клиента; обязателен. |
| `ip` | `INET` | IP-адрес входа; может отсутствовать. |
| `user_agent` | `TEXT` | Данные клиентского приложения; могут отсутствовать. |
| `is_revoked` | `BOOLEAN` | Сессия отозвана; по умолчанию `FALSE`. |
| `revoked_at` | `TIMESTAMPTZ` | Время отзыва. |
| `expires_at` | `TIMESTAMPTZ` | Срок действия; обязателен. |
| `last_seen_at` | `TIMESTAMPTZ` | Время последней активности. |
| `created_at` | `TIMESTAMPTZ` | Время создания. |

Индексы: `user_id`, `client_id`, `is_revoked`, `expires_at`.

### `refresh_tokens` — токены обновления

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `UUID` | Первичный ключ. |
| `user_id` | `UUID` | Владелец, внешний ключ на `users` с каскадным удалением. |
| `session_id` | `UUID` | Сессия, внешний ключ на `sessions` с каскадным удалением. |
| `token_hash` | `TEXT` | Уникальный хеш токена; исходное значение не хранится. |
| `is_revoked` | `BOOLEAN` | Признак отзыва. |
| `revoked_at` | `TIMESTAMPTZ` | Время отзыва. |
| `expires_at` | `TIMESTAMPTZ` | Срок действия. |
| `used_at` | `TIMESTAMPTZ` | Время применения. |
| `replaced_by_token_id` | `UUID` | Следующий токен цепочки, внешний ключ на эту же таблицу с `ON DELETE SET NULL`. |
| `created_at` | `TIMESTAMPTZ` | Время создания. |

### `signing_keys` — ключи подписи

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `UUID` | Первичный ключ. |
| `kid` | `VARCHAR(100)` | Уникальный внешний идентификатор ключа. |
| `algorithm` | `VARCHAR(20)` | Алгоритм подписи. |
| `public_key_pem` | `TEXT` | Открытая часть в формате PEM. |
| `private_key_pem` | `TEXT` | Закрытая часть в формате PEM. |
| `is_active` | `BOOLEAN` | Активен ли ключ; по умолчанию `FALSE`. |
| `created_at` | `TIMESTAMPTZ` | Время создания. |
| `expires_at` | `TIMESTAMPTZ` | Необязательный срок действия. |

Индекс создан по `is_active`. Текущий прикладной слой получает ключ из
настройки процесса, а не читает эту таблицу.

### `roles` — роли

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `UUID` | Первичный ключ. |
| `name` | `VARCHAR(50)` | Уникальное машинное имя роли. |
| `description` | `TEXT` | Пояснение роли. |
| `created_at` | `TIMESTAMPTZ` | Время создания. |

Миграции создают роли `user`, `admin`, `dispatcher`, `hr`,
`qualification_verifier` и `worker`.

### `user_roles` — роли пользователей

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `user_id` | `UUID` | Пользователь, внешний ключ на `users`. |
| `role_id` | `UUID` | Роль, внешний ключ на `roles`. |
| `assigned_at` | `TIMESTAMPTZ` | Время назначения. |

Составной первичный ключ `(user_id, role_id)` запрещает повторное назначение
той же роли. Оба внешних ключа используют каскадное удаление.

### `one_time_tokens` — одноразовые токены

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `UUID` | Первичный ключ. |
| `user_id` | `UUID` | Владелец, внешний ключ на `users`. |
| `token_hash` | `TEXT` | Уникальный хеш секретного значения. |
| `type` | `VARCHAR(64)` | Назначение токена. |
| `expires_at` | `TIMESTAMPTZ` | Срок действия. |
| `used_at` | `TIMESTAMPTZ` | Время использования или отзыва. |
| `created_at` | `TIMESTAMPTZ` | Время создания. |

Индексы: `user_id`, `type`, `expires_at`.

### `outbox_events` — надежная публикация событий

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `UUID` | Первичный ключ события. |
| `aggregate_type` | `VARCHAR(100)` | Вид измененной сущности. |
| `aggregate_id` | `UUID` | Идентификатор сущности. |
| `event_type` | `VARCHAR(100)` | Вид события. |
| `payload` | `JSONB` | Полезные данные события. |
| `status` | `VARCHAR(50)` | `PENDING`, `PROCESSING`, `SENT` или `FAILED`. |
| `attempts` | `INT` | Число попыток публикации. |
| `last_error` | `TEXT` | Последняя ошибка. |
| `next_attempt_at` | `TIMESTAMP` | Когда разрешена следующая попытка. |
| `locked_at` | `TIMESTAMP` | Когда запись была захвачена обработчиком. |
| `created_at` | `TIMESTAMP` | Время создания. |
| `sent_at` | `TIMESTAMP` | Время успешной публикации. |

Индексы поддерживают выборку по состоянию и времени повтора, сущности и виду
события.

### `idempotency_keys` — результаты повторяемых операций

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `UUID` | Первичный ключ записи. |
| `actor_key` | `VARCHAR(128)` | Пользователь или иной владелец области ключа. |
| `operation` | `VARCHAR(100)` | Имя операции. |
| `idempotency_key` | `VARCHAR(128)` | Ключ из запроса. |
| `request_hash` | `VARCHAR(128)` | Хеш входных данных. |
| `status` | `VARCHAR(32)` | `PROCESSING`, `COMPLETED` или `FAILED`. |
| `response` | `JSONB` | Сохраненный успешный ответ. |
| `error` | `TEXT` | Текст завершившей операцию ошибки. |
| `resource_type` | `VARCHAR(100)` | Вид созданного или измененного ресурса. |
| `resource_id` | `UUID` | Идентификатор ресурса. |
| `created_at` | `TIMESTAMP` | Время создания. |
| `updated_at` | `TIMESTAMP` | Время последнего перехода состояния. |
| `expires_at` | `TIMESTAMP` | Время удаления или неприменимости записи. |

Сочетание `actor_key`, `operation` и `idempotency_key` уникально. Индексы
созданы по `expires_at` и `status`.

## Структуры параметров и результатов

### type AuthServiceStruct

```go
type AuthServiceStruct struct {
	repo        *repository.Repo
	privateKey  *rsa.PrivateKey
	keyID       string
	mailService MailService
	profiles    ProfileProvisioner
	logger      *zap.Logger
}
```

### type ChangePasswordInput

```go
type ChangePasswordInput struct {
	UserID              uuid.UUID
	OldPassword         string
	NewPassword         string
	SessionID           uuid.UUID
	RevokeOtherSessions bool
}
```

### type ChangePasswordResult

```go
type ChangePasswordResult struct {
	Success                  bool
	InvalidatedSessionsCount int32
}
```

### type LoginInput

```go
type LoginInput struct {
	Email     string
	Password  string
	ClientID  string
	IP        string
	UserAgent string
}
```

### type LoginResult

```go
type LoginResult struct {
	AccessToken          string
	RefreshToken         string
	AccessExpiresAtUnix  int64
	RefreshExpiresAtUnix int64
	SessionID            uuid.UUID
	TokenType            string
}
```

### type LogoutAllInput

```go
type LogoutAllInput struct {
	UserID uuid.UUID
}
```

### type LogoutInput

```go
type LogoutInput struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
}
```

### type MailService

```go
type MailService interface {
	SendVerificationEmail(ctx context.Context, toEmail string, token string) error
	SendPasswordResetEmail(ctx context.Context, toEmail string, token string) error
}
```

### type ProfileProvisioner

```go
type ProfileProvisioner interface {
	CreateUserProfile(ctx context.Context, userID uuid.UUID, fullName string) error
	UserProfileExists(ctx context.Context, userID uuid.UUID) (bool, error)
}
```

### type RefreshInput

```go
type RefreshInput struct {
	RefreshToken string
	ClientID     string
	IP           string
	UserAgent    string
}
```

### type RefreshResult

```go
type RefreshResult struct {
	AccessToken          string
	RefreshToken         string
	AccessExpiresAtUnix  int64
	RefreshExpiresAtUnix int64
	SessionID            uuid.UUID
	TokenType            string
}
```

### type RegisterInput

```go
type RegisterInput struct {
	Email    string
	Password string
	Username string
}
```

### type RegisterResult

```go
type RegisterResult struct {
	UserID        string
	Email         string
	EmailVerified bool
}
```

### type Repository

```go
type Repository struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
	UserRepository
	SessionRepository
	RefreshTokenRepository
	RoleRepository
	TXRepository
	OneTimeTokenRepo
}
```

### type RequestPasswordResetInput

```go
type RequestPasswordResetInput struct {
	Email string
}
```

### type RequestPasswordResetResult

```go
type RequestPasswordResetResult struct {
	Success       bool
	ExpiresAtUnix int64
}
```

### type ResetPasswordInput

```go
type ResetPasswordInput struct {
	Token       string
	NewPassword string
}
```

### type ResetPasswordResult

```go
type ResetPasswordResult struct {
	Success                  bool
	InvalidatedSessionsCount int32
}
```

### type SMTPMailConfig

```go
type SMTPMailConfig struct {
	Host               string
	Port               int
	Username           string
	Password           string
	FromEmail          string
	FromName           string
	FrontendBaseURL    string
	UseTLS             bool
	UseStartTLS        bool
	InsecureSkipVerify bool
	Timeout            time.Duration
}
```

### type SMTPMailService

```go
type SMTPMailService struct {
	cfg    SMTPMailConfig
	logger *zap.Logger
}
```

### type SendVerificationEmailInput

```go
type SendVerificationEmailInput struct {
	UserID uuid.UUID
	Email  string
}
```

### type SendVerificationEmailResult

```go
type SendVerificationEmailResult struct {
	Success       bool
	ExpiresAtUnix int64
}
```

### type Service

```go
type Service struct {
	AuthService
	MailService
}
```

### type UserAuthInfo

```go
type UserAuthInfo struct {
	UserID        uuid.UUID
	Email         string
	Roles         []string
	Permissions   []string
	IsActive      bool
	EmailVerified bool
}
```

### type VerifyEmailInput

```go
type VerifyEmailInput struct {
	Token string
}
```

### type VerifyEmailResult

```go
type VerifyEmailResult struct {
	Success       bool
	UserID        uuid.UUID
	Email         string
	EmailVerified bool
	Message       string
}
```
