# Real-IP k6 Load Tests

These tests simulate different client IPs by running many k6 containers on the same Docker network as `api-gateway`.

One `k6-user` container is one real Docker source IP. Keep `K6_VUS=1` if you want one user per IP.

## Start the system

```powershell
docker compose up -d --build
```

## Run 10 users with 10 different Docker IPs

```powershell
docker compose -f docker-compose.yml -f load-tests/docker-compose.k6.yml --profile load up --scale k6-user=10 k6-user
```

## Run 50 users

```powershell
docker compose -f docker-compose.yml -f load-tests/docker-compose.k6.yml --profile load up --scale k6-user=50 k6-user
```

## Tune duration

PowerShell:

```powershell
$env:K6_DURATION="5m"
docker compose -f docker-compose.yml -f load-tests/docker-compose.k6.yml --profile load up --scale k6-user=20 k6-user
```

The compose file defaults to:

- `BASE_URL=http://api-gateway:8081`
- `K6_VUS=1`
- `K6_DURATION=2m`
- `K6_ITERATIONS=` unset, so duration mode is used
- `K6_USER_OFFSET=0`
- `K6_SLEEP_SECONDS=1`
- `K6_INCLUDE_BUSINESS=false`

By default, each k6 container registers a unique user, logs in, then repeatedly calls `/health` and `/auth/me`.

## Include business endpoints

PowerShell:

```powershell
$env:K6_INCLUDE_BUSINESS="true"
docker compose -f docker-compose.yml -f load-tests/docker-compose.k6.yml --profile load up --scale k6-user=10 k6-user
```

This also calls:

- `POST /tickets/list`
- `POST /departments/list`
- `POST /brigades/list`
- `POST /ticket-categories/list`

## Full Business Flow

Prepare admin users first:

```powershell
.\load-tests\seed-business-users.ps1 -Count 20
```

Then run the full business workflow:

Smoke test one complete pass:

```powershell
$env:K6_SCRIPT="/scripts/business-flow.js"
$env:K6_ITERATIONS="1"
$env:K6_USER_OFFSET="0"
$env:K6_SLEEP_SECONDS="0"
docker compose -f docker-compose.yml -f load-tests/docker-compose.k6.yml --profile load up --scale k6-user=1 k6-user
```

If a previous run was interrupted after adding a brigade member, bump `K6_USER_OFFSET` to use the next seeded admin user.

Load test the same workflow:

```powershell
$env:K6_SCRIPT="/scripts/business-flow.js"
$env:K6_ITERATIONS=""
$env:K6_DURATION="2m"
docker compose -f docker-compose.yml -f load-tests/docker-compose.k6.yml --profile load up --scale k6-user=5 k6-user
```

The full flow covers auth plus department, ticket category, ticket, brigade, member, skill, brigade skill, schedule, zone, availability, status history, assignment, completion, cancellation, and cleanup endpoints.

`business-flow.js` logs in once per VU/container and reuses the access token, so the business load test does not accidentally become an `/auth/login` rate-limit test. Seed at least `K6_USER_OFFSET + scaled k6-user containers` users.

## Verify that IPs are really different

Watch gateway logs while the test is running:

```powershell
docker compose logs -f api-gateway
```

Each scaled `k6-user` container gets its own Docker network address, so `gin.Context.ClientIP()` should see different client IPs when the request goes directly to `http://api-gateway:8081` inside the compose network.
