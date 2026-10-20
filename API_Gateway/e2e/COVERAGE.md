# API Gateway cluster E2E coverage

Актуальный контракт содержит **199 HTTP-операций**: **188 защищённых JWT** и
**11 публичных**. Дополнительно проверяется WebSocket `/notifications/ws`, который
пока не включён в OpenAPI.

`Frontend/e2e/gateway-coverage.spec.ts` является обязательным gate: каждая
операция OpenAPI должна присутствовать в позитивном сценарии с указанным классом
evidence. `gateway-route-sweep.spec.ts` динамически проверяет отсутствие JWT и
повреждённый JWT для каждой защищённой операции.

| Группа | Операций | Evidence |
|---|---:|---|
| Auth и JWKS | 12 | PostgreSQL, session/token lifecycle, JWT |
| Tickets и integrations | 19 | Citus/PostgreSQL, no-write negatives |
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
