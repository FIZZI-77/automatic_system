# k6 load tests

Основной нагрузочный тест запускается одним контейнером `k6`. Нагрузка создаётся VU и executors внутри k6, поэтому метрики и thresholds формируют единый итоговый отчёт.

## Быстрый запуск

Стек должен быть запущен:

```powershell
docker compose up -d
```

Smoke:

```powershell
$env:K6_PROFILE="smoke"
$env:K6_RUN_ID="smoke-$(Get-Date -Format yyyyMMddHHmmss)"
docker compose -f docker-compose.yml -f load-tests/docker-compose.k6.yml --profile load run --rm k6
```

Обычная ramping-нагрузка до 20 VU:

```powershell
$env:K6_PROFILE="load"
$env:K6_VUS="20"
$env:K6_DURATION="5m"
$env:K6_RUN_ID="load-$(Get-Date -Format yyyyMMddHHmmss)"
docker compose -f docker-compose.yml -f load-tests/docker-compose.k6.yml --profile load run --rm k6
```

Один VU получает отдельного пользователя и переиспользует его access token. `K6_RUN_ID` должен отличаться между запусками.

## Профили

Все профили определены через `options.scenarios` в `user-load.js`.

| Профиль | Executor | Назначение |
|---|---|---|
| `smoke` | `shared-iterations` | Быстрая проверка сценария |
| `load` | `ramping-vus` | Плановая нагрузка с плавным разгоном |
| `rate` | `constant-arrival-rate` | Точный поток итераций/RPS |
| `stress` | `ramping-vus` | Поиск деградации при росте нагрузки |
| `spike` | `ramping-vus` | Резкий скачок нагрузки |
| `soak` | `constant-vus` | Длительная проверка утечек и деградации |

### Constant arrival rate

20 итераций в секунду в течение 5 минут:

```powershell
$env:K6_PROFILE="rate"
$env:K6_RATE="20"
$env:K6_DURATION="5m"
$env:K6_PREALLOCATED_VUS="20"
$env:K6_MAX_VUS="100"
$env:K6_RUN_ID="rate-$(Get-Date -Format yyyyMMddHHmmss)"
docker compose -f docker-compose.yml -f load-tests/docker-compose.k6.yml --profile load run --rm k6
```

Одна итерация выполняет четыре HTTP-запроса batch, поэтому `K6_RATE=20` создаёт примерно 80 HTTP-запросов в секунду плюс первичный register/login каждого VU.

### Stress

```powershell
$env:K6_PROFILE="stress"
$env:K6_VUS="25"
$env:K6_STRESS_VUS="50"
$env:K6_MAX_VUS="100"
$env:K6_RUN_ID="stress-$(Get-Date -Format yyyyMMddHHmmss)"
docker compose -f docker-compose.yml -f load-tests/docker-compose.k6.yml --profile load run --rm k6
```

### Spike

```powershell
$env:K6_PROFILE="spike"
$env:K6_VUS="10"
$env:K6_MAX_VUS="100"
$env:K6_RUN_ID="spike-$(Get-Date -Format yyyyMMddHHmmss)"
docker compose -f docker-compose.yml -f load-tests/docker-compose.k6.yml --profile load run --rm k6
```

### Soak

```powershell
$env:K6_PROFILE="soak"
$env:K6_VUS="20"
$env:K6_DURATION="2h"
$env:K6_RUN_ID="soak-$(Get-Date -Format yyyyMMddHHmmss)"
docker compose -f docker-compose.yml -f load-tests/docker-compose.k6.yml --profile load run --rm k6
```

## Полный бизнес-сценарий

Подготовить отдельных admin-пользователей (не меньше максимального количества VU):

```powershell
.\load-tests\seed-business-users.ps1 -Count 20
```

Запустить один контейнер с 20 VU:

```powershell
$env:K6_SCRIPT="/scripts/business-flow.js"
$env:K6_VUS="20"
$env:K6_DURATION="5m"
docker compose -f docker-compose.yml -f load-tests/docker-compose.k6.yml --profile load run --rm k6
```

В одном k6-процессе `__VU` корректно распределяет записи из `users.json`. Не запускайте `business-flow.js` через Docker `--scale`: в разных процессах номера `__VU` повторяются.

## Проверка rate limit по разным IP

Множество контейнеров оставлено только для теста разных исходных IP:

```powershell
$env:K6_DURATION="2m"
docker compose -f docker-compose.yml -f load-tests/docker-compose.k6.yml --profile real-ip up --abort-on-container-exit --scale k6-real-ip=10 k6-real-ip
```

Каждый `k6-real-ip` содержит ровно один VU и получает отдельный Docker IP. Этот режим не следует использовать для обычных load/stress/spike/soak тестов: его метрики разделены по контейнерам.

## Thresholds

Основной сценарий завершается ошибкой, если:

- успешность checks ниже 99%;
- доля HTTP-ошибок выше 1%;
- p95 больше 1 секунды;
- p99 больше 2 секунд.
