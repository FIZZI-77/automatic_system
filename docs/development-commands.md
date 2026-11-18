# Команды проекта через Make

Корневой `Makefile` — общий вход в существующие PowerShell-скрипты, Go-модули,
Docker Compose, Helm, Kubernetes, Playwright и нагрузочный контур.
Реализация находится в [`scripts/project.ps1`](../scripts/project.ps1).
Список целей и краткие пояснения выводит `make help`.

## Требования и параметры

Основная платформа — Windows с PowerShell 7 (`pwsh.exe`) и GNU Make.
Проверка совместимости выполнялась с установленным GNU Make 3.81.
Bash и WSL для самого Makefile не нужны. Windows PowerShell 5.1 не поддерживается:
часть существующих скриптов содержит UTF-8 без BOM, который этот движок читает
неверно. Для выбора другого расположения PowerShell 7:

```powershell
make help POWERSHELL=pwsh.exe
make doctor
make deploy ENV=local-ha DRY_RUN=1
```

`doctor` проверяет инструменты, Docker daemon и Kubernetes. Он завершится
ошибкой, если обязательная зависимость недоступна; это не означает, что
статические команды, например `test-inventory`, тоже требуют кластер.
`bootstrap` загружает Go-зависимости и выполняет `npm ci` во Frontend;
Docker, Kubernetes, Go и Node он не устанавливает.

| Параметр | Значение и применение |
|---|---|
| `SERVICE=all` | Go-команды обходят 18 модулей из `go.work`. Можно выбрать `ticket`, `API_Gateway`, `api-gateway`, `root` и другие имена модулей. |
| `ENV=local` | `local`, `local-ha`, `dev`, `prod`. HA-цели по умолчанию выбирают `local-ha`. |
| `NAMESPACE` | По умолчанию `automatic-system-dev` для dev, иначе `automatic-system`. Скрипты с фиксированным namespace отклоняют несовместимое значение. |
| `CONTEXT` | Ожидаемый текущий Kubernetes context. При несовпадении выполнение прекращается; контекст автоматически не переключается. |
| `DRY_RUN=1` | Печатает команды и параметры, не запуская их. Проверяет входные значения и наличие вызываемых скриптов. |
| `SKIP_BUILD=1`, `SKIP_IMPORT=1` | Пропустить сборку и/или импорт образов в `deploy-ha`/`deploy-infra`. `SKIP_BUILD` также поддерживается `up` и `test-ui`. |
| `IMAGE_TAG`, `MIGRATOR_TAG` | Метки образов для `deploy-apps`. Обязательны для dev/prod, кроме метки мигратора при `SKIP_MIGRATIONS=1`. |
| `TEST_RUN` / `RACE=1` | Фильтр Go-тестов / включение race detector; последний требует подходящий C toolchain. |
| `TEST_FILE` | Один spec-файл для `test-api`, например `e2e/gateway-tickets-stateful.spec.ts`. |
| `GATEWAY_URL` | Для `test-api`: существующий Gateway вместо временного port-forward. |
| `SKIP_SEED=1` | По умолчанию не обновлять demo-данные при кластерных проверках и bulk seed аналитики. |
| `INCLUDE_SMTP=1`, `HEADED=1` | SMTP-сценарии для `test-api` / видимый браузер для UI E2E. |
| `FOLLOW=1`, `TAIL=100` | Следить за журналами / количество последних строк. |

Переменные передаются обработчику через окружение `ACS_*`, без сборки
PowerShell-команд из строк. Пароль для demo-операций передавайте через
`$env:DEMO_PASSWORD`; Makefile не принимает пароль отдельным параметром
и не печатает его. `observability-password` использует скрытый запрос
существующего скрипта.

## Разработка и проверки

```powershell
make bootstrap
make frontend-dev
make go-build SERVICE=ticket
make fmt-check SERVICE=ticket
make fmt SERVICE=ticket
make vet SERVICE=ticket
make test-unit SERVICE=ticket
make test SERVICE=ticket TEST_RUN=TestIntegrationService
make test-integration SERVICE=ticket
make test-compile
make test SERVICE=api-gateway RACE=1
make frontend-build
make frontend-test
make lint
make check
make test-tools
```

`test` выполняет обычный `go test -count=1 ./...` в выбранных модулях.
В некоторых из них есть тесты с Testcontainers. `test-unit` исключает отдельные
пакеты с сегментами пути `integration` и `e2e`, а `test-integration` включает
build tag `integration` и timeout 15 минут. Требования и правила пропуска тестов
остаются такими, как реализованы в конкретном модуле; пропуск не доказывает
работоспособность интеграции. `test-compile` использует `-run '^$'`.
Все Go-команды используют локальный `.gocache`. Пакеты внутри `node_modules`
исключаются: корневой `go list ./...` иначе включает Go-код npm-зависимостей.

`check` последовательно выполняет `fmt-check`, `vet`, frontend ESLint,
TypeScript, `openapi-check` и `test-inventory`. Он не запускает кластер и
не заменяет тесты бизнес-логики. Сборка frontend и тесты запускаются отдельными
целями. `test-tools` проверяет цели Make, параметры существующих скриптов,
выбор модулей и обработку неверных аргументов без развёртывания.

## Compose и сквозные сценарии

```powershell
make compose-config
make up
make compose-status
make compose-logs SERVICE=ticket-service FOLLOW=1
make simulation-up
make down

make test-inventory
make test-api
make test-api TEST_FILE=e2e/gateway-tickets-stateful.spec.ts
make test-api GATEWAY_URL=http://127.0.0.1:8081 INCLUDE_SMTP=1
make test-ui
make test-ui-ha
make test-report
```

`compose-logs` принимает точное имя сервиса из `docker-compose.yml`.
`down` сохраняет volumes. Отдельной команды неявного удаления данных нет.
`test-inventory` использует [`playwright.inventory.config.ts`](../Frontend/playwright.inventory.config.ts):
два теста инвентаризации контракта без global setup/teardown, seed и Gateway.
`test-api` использует существующий API-only runner со storage assertions.
`test-ui` поднимает Compose; `test-ui-ha` использует существующий HA runner.
Оба UI runner требуют `DEMO_PASSWORD`.

## Развёртывание и эксплуатация Kubernetes

Makefile развёртывает систему **в уже существующем Kubernetes**.
Создание Kubernetes-кластера и настройка Docker Desktop в репозитории этими
целями не автоматизируются.

```powershell
make cluster-check CONTEXT=docker-desktop
make build
make deploy-local
make deploy ENV=local-ha
make deploy-ha SKIP_BUILD=1 SKIP_IMPORT=1
make deploy-infra
make deploy-apps ENV=local-ha
make deploy-apps ENV=dev IMAGE_TAG=sha-1234567 MIGRATOR_TAG=sha-1234567
make cluster-status
make logs SERVICE=ticket FOLLOW=1
make rollout-status
make cluster-verify
```

`build` вызывает `build-images.ps1` для всего предусмотренного им набора;
выбор отдельного образа через `SERVICE` этот скрипт не поддерживает.
`deploy-local` вызывает `apply.ps1`, `deploy-ha` — `start-local-ha.ps1`,
`deploy-infra` — тот же HA-скрипт с `-SkipApplications`.
`deploy` выбирает только local/local-ha. Для dev/prod подготовка инфраструктуры,
секретов, StorageClass и меток HA-образов выполняется по
[инструкции развёртывания](../k8s/docs/deployment.md), затем можно вызвать
`deploy-apps`. Makefile не подменяет эти настройки и не включает смену владельца
ресурсов Helm автоматически. Миграции выполняются в рамках существующего
Helm-выпуска; отдельная универсальная команда отката схемы не вводится.

`cluster-verify` ожидает rollout, затем запускает API E2E.
Он не подтверждает завершение Flagger analysis или готовность дорожного графа
Valhalla только по состоянию pod. `logs SERVICE=frontend` обращается к исходному
Deployment; после продвижения Flagger журналы primary доступны обычной командой
`kubectl -n automatic-system logs deployment/frontend-primary`.

Дополнительные цели используют одноимённые существующие скрипты:

- `mesh-install ENV=local` или `ENV=prod`, `metrics-install`, `ingress-setup`;
- `flux-install`, `flux-sync`, `flux-status` — синхронизацию включает только `flux-sync`;
- `observability PUBLIC_URL=...`, `observability-password USERNAME=admin`;
- `pgadmin-setup`, `funnel-setup`, `transponders-apply`;
- `dashboards-generate`, `dashboards-import`, `kibana-setup`.

Для Kibana сохраняются значения URL и индексов из её скрипта. Нестандартные
параметры можно передать прямым вызовом соответствующего `.ps1`.
`cluster-delete` сохраняет интерактивное подтверждение `DELETE` из
`delete-local.ps1`. Поведение PVC после удаления namespace зависит от storage
policy. Параметры `ResetData` и `ResetSecrets` HA-скрипта намеренно не включены
в обычное развёртывание.

## Данные, нагрузка и документация

```powershell
make seed ENV=local
make seed ENV=local-ha BASE_URL=http://127.0.0.1:18081
make seed-analytics SCALE=1000
make load-prepare
make load SCENARIO=ticket-read BASE_URL=http://localhost:8081 RATES=10,25,50
make load SCENARIO=location ALLOW_WRITES=1
make load-suite SCENARIO_FILTER=gateway,analytics
make test-chaos EXECUTE=1
make test-k6-chaos
make test-k6-chaos EXECUTE=1
make openapi
make openapi-check
make manifests-render ENV=local-ha
make helm-check ENV=local-ha
make docs-context
```

Нагрузку дополнительно настраивают `WARMUP`, `MEASUREMENT`, `STABILIZATION`.
`load-suite` использует Kubernetes, требует demo-пароль и **временно заменяет
образ Gateway** согласно реализации `run-local-suite.ps1`, даже без
`ALLOW_WRITES=1`. Цели не отключают ограничения нагрузки на production.
`test-chaos EXECUTE=1` перезапускает компоненты и требует demo-пароль;
`test-k6-chaos` без `EXECUTE=1` запускает только нагрузку. Обе цели используют
проверку контекста `docker-desktop` внутри существующих скриптов.

Отчёты сохраняются там, где их создают конкретные runner: Playwright —
`Frontend/test-results` и `Frontend/playwright-report`, нагрузка —
`load-tests/results`, chaos — `test-results`.
`manifests-render` и `helm-check` не применяют ресурсы, но выводят манифесты,
в том числе описанные в них Secret. `docs-context` обновляет игнорируемый
`output/context/automatic-city-compact.md`; публикацию Wiki и YouTrack
эти команды не выполняют.
