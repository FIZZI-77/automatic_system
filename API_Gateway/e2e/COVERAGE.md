# API Gateway cluster E2E coverage

Актуальный контракт содержит **202 HTTP-операции**: **191 защищённую JWT** и
**11 публичных**. Дополнительно проверяется WebSocket `/notifications/ws`, который
пока не включён в OpenAPI.

`Frontend/e2e/gateway-coverage.spec.ts` является обязательным gate: каждая
операция OpenAPI должна присутствовать в позитивном сценарии с указанным классом
evidence. Inventory проверяет 202 операции, включая `/tickets/integrations/list`,
`/tickets/integrations/set-active`, `/tickets/integrations/rotate-secret`.
Сценарий `gateway-tickets-stateful.spec.ts` сверяет список и состояние БД,
запрет управления для обычного пользователя, отключение интеграции, ротацию
секрета без изменения активности, отказ старому секрету и идемпотентный повтор
обращения с новым секретом. `gateway-route-sweep.spec.ts` динамически проверяет отсутствие JWT и
повреждённый JWT для каждой защищённой операции.

| Группа | Операций | Evidence |
|---|---:|---|
| Auth и JWKS | 12 | PostgreSQL, session/token lifecycle, JWT |
| Tickets и integrations | 22 | Citus/PostgreSQL, no-write negatives, управление активностью и секретом интеграции |
| Departments, categories, geo zones | 15 | PostgreSQL CRUD |
| Brigades, members, skills, schedules, zones | 33 | PostgreSQL lifecycle/history |
| Profiles, certifications, skill grants | 34 | PostgreSQL lifecycle/history |
| Locations, Routing, Dispatch | 20 | PostgreSQL, Redis, Citus, cross-service state |
| Files | 6 | PostgreSQL и реальный объект MinIO |
| SLA | 8 | PostgreSQL CRUD/read |
| Notifications | 10 + WebSocket | PostgreSQL и Redis Pub/Sub |
| Audit и Analytics | 18 | PostgreSQL/ClickHouse read surface |
| Reports | 7 | PostgreSQL, Citus, Analytics, File Service/MinIO |
| Assets | 14 | PostgreSQL lifecycle |
| Health/livez/readyz | 3 | HTTP protocol |

Проверка 27 октября 2026: два статических Playwright-теста inventory прошли,
как и ESLint измененных spec-файлов и TypeScript. Новый кластерный сценарий
обнаруживается runner, но не запускался: Kubernetes API текущего контекста
на `127.0.0.1:54025` недоступен. Статический inventory не доказывает успешный
сквозной прогон и не проверяет бизнес-поведение каждой операции.

Основной self-contained прогон не требует постоянных demo-аккаунтов:

```powershell
& .\scripts\run-api-gateway-e2e.ps1 -SkipSeed
```

Позитивные SMTP-сценарии включаются отдельно, поскольку требуют сетевого доступа
к настроенному провайдеру:

```powershell
& .\scripts\run-api-gateway-e2e.ps1 -SkipSeed -IncludeSMTP
```

Из Go-модуля Gateway основной кластерный набор запускается так:

```powershell
$env:API_GATEWAY_E2E = '1'
$env:GOCACHE = 'C:\AuthomaticCityServices\.gocache'
go test -v ./e2e -run TestAPICluster -count=1
```
