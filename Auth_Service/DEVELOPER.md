# Auth Service — developer documentation

Auth Service владеет учетными записями, паролями, ролями, сессиями, refresh/access tokens, одноразовыми токенами подтверждения email и сброса пароля. Остальные сервисы не должны хранить пароль, email verification state или выдавать JWT самостоятельно.

## Слои сервиса

- `models` — доменные структуры и input/result DTO для service layer.
- `src/core/handler` — gRPC handler. Принимает protobuf request, мапит его в `models.*Input`, вызывает service, мапит result обратно в protobuf response.
- `src/core/service` — бизнес-логика Auth. Проверяет входные данные, пароли, токены, lifecycle сессий, вызывает репозитории и mail service.
- `src/core/repository` — работа с PostgreSQL. Содержит репозитории пользователей, сессий, refresh tokens, ролей, одноразовых токенов и транзакционные методы.
- `pkg` — общая инфраструктура: PostgreSQL config, request id, idempotency key, logger, graceful closer.

## Основные структуры `models`

- `User` — учетная запись: `id`, `email`, `username`, `password_hash`, `is_active`, `email_verified`, timestamps.
- `Session` — пользовательская сессия: `id`, `user_id`, `client_id`, `ip`, `user_agent`, revoke/expiry/last_seen timestamps.
- `RefreshToken` — сохраненный refresh token: hash, session/user binding, revoke state, replacement chain.
- `OneTimeToken` — одноразовый token для `email_verification` или `password_reset`; хранится только hash.
- `UserAuthInfo` — read-model для других сервисов/API Gateway: user id, email, roles, permissions, active/email flags.

## Service methods

### `Register(ctx, RegisterInput) -> RegisterResult`

Принимает `email`, `password`, `username`.

Логика:

1. Валидирует email/password/username.
2. Проверяет уникальность email на уровне repository/DB.
3. Хеширует пароль.
4. Создает пользователя.
5. Создает одноразовый verification token.
6. Отправляет письмо через `MailService`, если он подключен.
7. Возвращает `user_id`, `email`, `email_verified=false`.

Важно: пароль никогда не возвращается наружу; token хранится только как hash.

### `Login(ctx, LoginInput) -> LoginResult`

Принимает `email`, `password`, `client_id`, `ip`, `user_agent`.

Логика:

1. Ищет пользователя по email.
2. Проверяет `is_active`.
3. Сравнивает пароль с hash.
4. Получает роли пользователя.
5. Создает новую session.
6. Выпускает access JWT и refresh token.
7. Сохраняет hash refresh token.
8. Возвращает пару токенов, expiry timestamps, `session_id`, `token_type`.

### `Refresh(ctx, RefreshInput) -> RefreshResult`

Принимает refresh token и client metadata.

Логика:

1. Хеширует входной refresh token.
2. Находит token record.
3. Проверяет revoked/expired/used state.
4. Проверяет связанную session.
5. Выпускает новый access token и новый refresh token.
6. Старый refresh token помечает used и связывает с новым.
7. Обновляет `last_seen` session.

### `Logout(ctx, LogoutInput) -> error`

Принимает `user_id`, `session_id`.

Логика: отзывает указанную session и refresh tokens этой session. Используется для выхода с одного устройства.

### `LogoutAll(ctx, LogoutAllInput) -> uint32`

Принимает `user_id`.

Логика: отзывает все sessions и все refresh tokens пользователя. Возвращает количество инвалидированных сессий.

### `GetUserAuthInfo(ctx, userID) -> UserAuthInfo`

Read-only метод для API Gateway и внутренних сервисов.

Возвращает user id, email, роли, permissions, `is_active`, `email_verified`. Не возвращает password hash или refresh tokens.

### `GetJWKS(ctx) -> string`

Возвращает JWKS публичного ключа для проверки JWT.

### `ChangePassword(ctx, ChangePasswordInput) -> ChangePasswordResult`

Принимает `user_id`, `old_password`, `new_password`, `session_id`, `revoke_other_sessions`.

Логика:

1. Проверяет старый пароль.
2. Хеширует новый пароль.
3. В транзакции меняет пароль.
4. При необходимости отзывает другие sessions/refresh tokens.
5. Возвращает количество инвалидированных сессий.

### `SendVerification(ctx, SendVerificationEmailInput) -> SendVerificationEmailResult`

Создает новый verification token, отзывает старые unused verification tokens этого пользователя и отправляет письмо.

### `VerifyEmail(ctx, VerifyEmailInput) -> VerifyEmailResult`

Принимает plaintext token из email.

Логика:

1. Хеширует token.
2. Находит active `email_verification` token.
3. Проверяет expiry/used.
4. В транзакции помечает token used и `users.email_verified=true`.

### `RequestPasswordReset(ctx, RequestPasswordResetInput) -> RequestPasswordResetResult`

Принимает email. Если пользователь существует, создает password reset token и отправляет письмо. Для безопасности внешний ответ не должен раскрывать, существует email или нет.

### `ResetPassword(ctx, ResetPasswordInput) -> ResetPasswordResult`

Принимает reset token и новый пароль.

Логика:

1. Проверяет token.
2. Хеширует новый пароль.
3. В транзакции меняет пароль, помечает token used, отзывает sessions/refresh tokens.

## Repository interfaces

- `UserRepository`
  - `CreateUser` — insert user, возвращает id.
  - `GetUserByID`, `GetUserByEmail` — read user.
  - `UpdateUser` — обновляет поля user.
- `SessionRepository`
  - `CreateSession`, `GetSessionByID`, `GetSessionByUserID`.
  - `RevokeSessionByID`, `RevokeAllSessionByUserID`.
  - `UpdateLastSeenSession`.
- `RefreshTokenRepository`
  - `CreateToken`, `GetByTokenHash`.
  - `RevokeTokenByID`, `RevokeTokenBySessionID`, `RevokeAllTokenByUserID`.
  - `MarkUsedAndReplaceToken` — ротация refresh token.
- `RoleRepository`
  - `GetRolesByUserID`.
  - `AssignRoleToUser`.
- `OneTimeTokenRepo`
  - `CreateOneTimeToken`.
  - `GetOneTimeTokenByHashAndType`.
  - `MarkOneTimeTokenUsed`.
  - `RevokeUnusedTokensByUserIDAndType`.
- `TXRepository`
  - транзакционные сценарии, где нужно атомарно менять несколько таблиц: password change, logout, reset password, verify email.

## Handler layer

`AuthHandler` реализует gRPC contract:

- `Register`
- `Login`
- `Refresh`
- `Logout`
- `LogoutAll`
- `GetUserAuthInfo`
- `GetJWKS`
- `ChangePassword`
- `SendVerificationEmail`
- `VerifyEmail`
- `RequestPasswordReset`
- `ResetPassword`

Handler не должен содержать бизнес-логику. Его задача — mapping, извлечение metadata, вызов service, mapping ошибок в gRPC status.

## Ошибки и безопасность

- Пароли и plaintext tokens нельзя логировать.
- В БД хранить только hashes refresh/one-time tokens.
- Refresh token должен быть одноразовым: после `Refresh` старый token становится `used`.
- Password reset и email verification должны быть идемпотентны на уровне пользовательского опыта, но сами tokens одноразовые.
- `GetUserAuthInfo` — главный метод для авторизации на стороне Gateway/других сервисов.

## Как добавлять новый auth flow

1. Добавить input/result в `models`.
2. Добавить validation.
3. Добавить метод в `AuthService`.
4. Реализовать бизнес-логику в `auth_service.go`.
5. Если меняются несколько таблиц — делать через `TXRepository` или `WithTx`.
6. Добавить gRPC handler mapping.
7. Добавить unit/integration tests.
