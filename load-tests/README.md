# Automatic System load testing and capacity planning

Framework работает с текущим кодом рабочего дерева. Числа производительности в репозитории не зашиты: до реального запуска результат — `N/A / not measured`. Измеренные и экстраполированные значения сохраняются раздельно.

## Требования

- Go версии из `go.work`, k6, Node.js (только детерминированный генератор fixtures), PowerShell 7 или Bash.
- Развёрнутый test environment Automatic System и доступ к Gateway/Prometheus.
- Для прямых gRPC-прогонов — ghz и текущий checkout `automatic-system-contracts`.
- Для Kubernetes profile — `kubectl` с явно выбранным test namespace.

Установка: `winget install k6.k6`, `go install github.com/bojand/ghz/cmd/ghz@latest`.

## Быстрый запуск в PowerShell

```powershell
$env:LOAD_USER_EMAIL='load@example.invalid'
$env:LOAD_USER_PASSWORD='test-only-password'
$env:ACCESS_TOKEN='...'
$env:TICKET_ID='00000000-0000-0000-0000-000000000000'
$env:BRIGADE_ID='00000000-0000-0000-0000-000000000000'
$env:VEHICLE_ID='00000000-0000-0000-0000-000000000000'
./load-tests/scripts/run.ps1 -Scenario gateway -Rates '100,250,500'
```

Записывающие сценарии требуют `$env:LOAD_TEST_ALLOW_DESTRUCTIVE='true'`; цель с `prod/production` в имени блокируется. Флаг не даёт права очищать реальные данные. Fixtures создаются детерминированно: `./load-tests/scripts/prepare.ps1 -Seed 77 -Count 100`.

## Методика

Основная нагрузка задаётся `constant-arrival-rate`, не числом VU. Каждая ступень имеет отдельные теги `warmup`, `measurement`, `stabilization`; capacity рассчитывается только по measurement. Настройки: `K6_RATES`, `K6_WARMUP`, `K6_MEASUREMENT`, `K6_STABILIZATION`, `K6_SEGMENT_SECONDS`.

Ступень sustainable только при одновременном выполнении SLO latency/errors, CPU/RAM target, нерастущем Kafka lag/queue/PgBouncer wait/backlog и отсутствии OOM/restarts. Knee — объяснимое увеличение наклона `delta(p95)/delta(throughput)`; failure — первая нарушившая ограничения ступень. Это три разных результата.

## Сценарии

Исполняются сейчас: `gateway`, `gateway-authenticated-read`, `auth-login`, `auth-refresh`, `ticket-read` (60/30/10), `location`, `dispatch-preview`, `analytics`, `full`. Маршруты и DTO соответствуют текущему Gateway. GPS запускается отдельно от web mix.

```powershell
go run ./load-tests/cmd/capacity run gateway --rate 100
go run ./load-tests/cmd/capacity analyze --input ./analysis-input.json
go run ./load-tests/cmd/capacity report --input ./load-tests/reports/<run-id>/summary.json
go run ./load-tests/cmd/capacity compare --baseline ./A.json --current ./B.json
go run ./load-tests/cmd/capacity estimate --result ./A.json --measured-server ./measured.yaml --server ./target.yaml --points 3 --efficiency .87
```

Run wrapper сохраняет `k6.json` и `config.json` в `results/raw/<run-id>`. Анализатор создаёт `summary.json`, `summary.csv`, `report.md`; модель summary содержит measured/extrapolated раздельно, Little's Law, estimated active users, Brigade equivalents и N+1. Для одной реплики N+1 выводится как unavailable. Stateful dependencies линейно не масштабируются.

## Конфигурация и Prometheus

- `config/server.example.yaml` — железо, reserved resources, replicas/requests/limits.
- `config/workload.example.yaml` — ступени, mixed workload, user activity, amplification.
- `config/thresholds.example.yaml` — SLO и regression thresholds.
- `config/environments.example.yaml` — Gateway, Prometheus, namespace, production marker.
- `infra/prometheus/queries.yaml` — только метрики, подтверждённые текущими manifests/exporters.

Prometheus client получает `query_range` с context cancellation и сохраняет snapshot, связанный с run interval. Запрос без `confirmed_by` помечается unavailable. Run metadata должен включать git SHA, server/runtime profile, параметры и timestamps. Kubernetes runtime profile получают командой `kubectl get deployments,statefulsets -n <namespace> -o json`; результат сохраняют как `server.json` и сверяют с server profile.

## Интерпретация

Capacity — максимум устойчивой измеренной ступени, а не последний k6 target. Для Kafka допустим только поток с `d(lag)/dt <= 0` после stabilization. Business и mixed capacity рассчитываются через подтверждённые amplification factors. Active users — оценка активных, не зарегистрированных пользователей. Экстраполяция разрешена лишь при нескольких resource scaling points (250m/500m/1000m/2000m), стабильном bottleneck и измеренной efficiency; иначе CLI возвращает «insufficient measurements».

## Ограничения и TODO

- Полные Ticket write/cancel/complete, Dispatch reserve/confirm/auto compensation, Routing matrix, SLA scanner, Notification provider, Report/File/MinIO и Kafka producer workloads нельзя корректно завершить одним универсальным fixture без состояния конкретного test deployment. Для них не созданы фиктивные вызовы; ghz каталог объясняет привязку к текущим contracts.
- В текущем коде не подтверждены метрики location history buffer/dropped history, outbox backlog, notification/report queue. Они перечислены как unavailable; для автоматического bottleneck HIGH требуется добавить instrumentation.
- Analytics 1M–500M и SLA 10k–1M требуют отдельного controlled seed в явно выделенные ClickHouse/PostgreSQL test databases. Автоматическое удаление данных отсутствует намеренно.
- SMTP/FCM fake provider и fault injection для 0/10/30% Dispatch failures требуют конфигурируемых test doubles в сервисах; существующие producers/consumers не подменяются выдуманными.
- Фактическая capacity, N+1, soak 2/6/12h, spike recovery и server extrapolation появляются только после прогонов; репозиторий не содержит benchmark numbers.

## Проверка разработки

```powershell
$env:GOCACHE="$PWD/.gocache"
go test ./load-tests/...
go vet ./load-tests/...
k6 inspect ./load-tests/k6/gateway/baseline.js
```

Старые `user-load.js`, `business-flow.js`, `real-ip-user.js` и chaos-сценарий сохранены для совместимости, но не считаются автоматически доказательством capacity.
