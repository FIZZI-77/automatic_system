# Kubernetes

Проект имеет четыре основных deployment contexts.

## `local`

```powershell
.\k8s\scripts\apply.ps1
```

Поднимает простой developer stack: namespace, secrets, PostgreSQL, Redis, Kafka, MinIO, ClickHouse, Valhalla, MailHog, migrations и applications Helm release.

Этот режим **не** является проверкой HA, Citus distribution или canary promotion.

## `local-ha`

```powershell
.\k8s\scripts\start-local-ha.ps1
```

Включает более production-like topology:

- Patroni;
- Citus;
- PgBouncer;
- MinIO;
- наблюдаемость;
- Istio;
- поддержка Kafka/Redis/ClickHouse/Valhalla;
- приложения Helm;
- необязательный путь Flux/Flagger.

`-ResetData` разрушителен: удаляет namespace и локальные volumes.

## `dev`

Пространство имён: `automatic-system-dev`.

Applications выпускаются Helm, а не дублируются в Kustomize apps. Для dev требуются immutable image tags.

## `prod`

Production overlay содержит platform/network/observability/HA building blocks и migration templates. Applications также выпускаются Helm.

Перед реальным применением должны быть заменены placeholder image tags, StorageClass assumptions и local secret management.

## Helm

Единый release называется `applications`.

```powershell
.\k8s\scripts\deploy-applications-helm.ps1 `
  -Environment prod `
  -ImageTag sha-<commit> `
  -MigratorTag sha-<commit>
```

`--atomic --wait` способен откатить Helm resources при неготовности, но **не откатывает schema migration**. Поэтому DB changes должны быть backward-compatible в период rollout.

## Istio

В `local-ha`/`prod` application workloads получают sidecar. Infrastructure workloads исключаются. Используются mTLS, traffic policies и ingress gateways.

## Временный внешний доступ

Для разработки входной шлюз можно опубликовать через Tailscale Funnel без
покупки домена. Перед первым запуском требуется войти в Tailscale:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\k8s\scripts\setup-tailscale-funnel.ps1
```

Скрипт направляет публичный HTTPS-трафик в локальный Istio, проверяет состояние
Funnel и ответы маршрутов Istio, сохраняет стабильный адрес узла в
`.runtime/tailscale-funnel-url.txt` и синхронизирует `FRONTEND_BASE_URL` в Auth
Service. Этот режим предназначен для разработки и демонстрации, не для
production.

### Источники
- [Deployment guide](https://github.com/FIZZI-77/automatic_system/blob/test/k8s/docs/deployment.md)
- [Security and observability](https://github.com/FIZZI-77/automatic_system/blob/test/k8s/docs/security-observability.md)
