# API Gateway — developer documentation

API Gateway — внешний HTTP-вход в систему. Он принимает REST/JSON-запросы, проверяет авторизацию, добавляет request/idempotency metadata, вызывает внутренние gRPC сервисы и возвращает клиенту нормализованный HTTP/JSON-ответ.

Gateway не владеет бизнес-данными и не должен содержать доменную бизнес-логику. Его задача — безопасность, маршрутизация, преобразование форматов и единая обработка ошибок.

## Слои и директории

- `models` — HTTP request/response DTO для gateway. Эти структуры не обязаны один-в-один совпадать с protobuf или доменными моделями сервисов.
- `src/cmd/server` — bootstrap приложения: env config, gRPC clients, router, middlewares, HTTP server.
- `src/core/handlers` — HTTP handlers и mapper functions для Auth, Department, Ticket, Brigade.
- `src/core/middleware` — auth, request id, rate limit, logging, idempotency.
- `src/core/retry` — gRPC retry interceptor для transient ошибок.
- `src/core/idempotency` и `src/core/requestid` — helpers для передачи metadata.
- `pkg/closer` — graceful shutdown.

## Общий поток запроса

```text
Client
  -> HTTP route
  -> middleware chain
  -> HTTP handler
  -> mapper HTTP DTO -> protobuf request
  -> gRPC client
  -> mapper protobuf response -> HTTP DTO
  -> JSON response
```

Gateway должен доверять actor context только после проверки JWT. Для защищенных маршрутов `user_id`, roles и связанные claims берутся из токена/контекста, а не из тела запроса клиента.

## Middleware

### `RequestID`

Создает или принимает входящий request id и кладет его в context/headers. Этот id должен пробрасываться дальше во внутренние gRPC сервисы, чтобы логи разных сервисов можно было связать.

### `AuthMiddleware`

Проверяет `Authorization: Bearer <access_token>`.

Логика:

1. Проверяет наличие header.
2. Проверяет формат Bearer token.
3. Валидирует подпись JWT публичным ключом.
4. Проверяет стандартные claims: expiry, issuer/audience, если они настроены.
5. Извлекает user id, roles/permissions.
6. Кладет actor context в request context.

Gateway не должен хранить private key и не должен выпускать access tokens. Это ответственность Auth Service.

### `Idempotency`

Читает idempotency key из заголовка и передает его во внутренний сервис через metadata. Сами гарантии идемпотентности реализуются в сервисах, потому что только они знают доменную операцию и транзакционные границы.

### `RateLimit`

Ограничивает частоту запросов. Нужен как базовая защита edge-слоя от случайных всплесков и грубого abuse.

### `RequestLogger`

Логирует method/path/status/duration/request id. Не должен писать в лог access token, password, refresh token и другие секреты.

## Handlers

### Auth handler

Отвечает за публичные и пользовательские auth routes.

Типовая логика методов:

1. Декодировать JSON body в gateway model.
2. Выполнить легкую HTTP-level validation: обязательные поля, формат.
3. Смапить request в protobuf.
4. Вызвать Auth Service.
5. Смапить результат в HTTP response.
6. При ошибке преобразовать gRPC status в HTTP code.

Примеры сценариев: register, login, refresh, logout, logout all, get auth info, change password, email verification, password reset.

### Department handler

Отвечает за CRUD департаментов.

Логика: actor context берется из middleware, затем handler вызывает Department Service. Проверки `admin`/department-level доступа должны оставаться в Department Service, а Gateway только передает контекст.

### Ticket handler

Отвечает за заявки и категории.

Логика:

- create ticket — принимает клиентский payload, actor user берется из JWT, вызывает Ticket Service;
- list/get/update — мапит query/path/body в protobuf;
- status transitions — вызывает специализированные методы Ticket Service;
- assignment/cancel/complete — не должен реализовывать доменную логику внутри Gateway.

### Brigade handler

Отвечает за бригады, участников, навыки, графики и зоны.

Логика: принимает REST-запросы, мапит UUID/path/query/body, передает actor roles/department context дальше. Проверки принадлежности департаменту и готовности бригады остаются в Brigade Service.

### Profile routes

На момент этой документации Profile Service уже имеет доменную модель и service/repository слой, но Gateway routes для Profile еще не подключены. Когда они появятся, их стоит добавить отдельным `profile.go` handler + mapper, не смешивая profile DTO с brigade/auth/ticket DTO.

## Mapper functions

Mapper слой нужен, чтобы не размазывать преобразования по handler methods.

Правила:

- HTTP DTO не должен утекать в gRPC service напрямую.
- protobuf response не должен отдаваться клиенту “как есть”, если внешний контракт отличается.
- UUID/time/status conversion лучше держать рядом с handler конкретного домена.
- Ошибка парсинга UUID/time должна становиться `400 Bad Request`.

## Retry logic

`src/core/retry` содержит gRPC retry interceptor.

Retry допустим только для transient ошибок: unavailable, deadline exceeded, временные сетевые сбои. Нельзя бездумно retry-ить небезопасные write operations без idempotency key, иначе можно получить дубли.

## Error mapping

Gateway должен возвращать клиенту понятный HTTP status:

- validation/invalid argument -> `400 Bad Request`;
- unauthenticated -> `401 Unauthorized`;
- permission denied -> `403 Forbidden`;
- not found -> `404 Not Found`;
- already exists/conflict -> `409 Conflict`;
- deadline exceeded -> `504 Gateway Timeout`;
- unavailable -> `503 Service Unavailable`;
- unknown/internal -> `500 Internal Server Error`.

В тело ответа не стоит прокидывать внутренние SQL/gRPC детали. Для клиента достаточно стабильного code/message/request_id.

## Конфигурация и зависимости

Gateway обычно получает через env:

- адреса Auth/Ticket/Department/Brigade gRPC сервисов;
- HTTP listen address/port;
- публичный ключ или JWKS settings для проверки JWT;
- timeout/retry settings;
- rate limit settings.

При добавлении нового сервиса нужно:

1. Добавить gRPC client в bootstrap.
2. Добавить handler и mapper.
3. Зарегистрировать routes.
4. Пробросить request id, idempotency key и actor context.
5. Обновить документацию и postman/openapi коллекции, если они ведутся.

## Правила код-дизайна

- Gateway не принимает бизнес-решения за сервисы.
- Gateway не доверяет user_id/roles/department_id из тела защищенного запроса.
- Handler должен быть тонким: parse -> map -> call -> map -> respond.
- Middleware отвечает за cross-cutting concerns.
- Ошибки должны быть единообразными для всех доменов.
- Логи должны быть полезны для расследования, но безопасны по данным.
