# Архитектура Automatic City Services

Редактируемый исходник — [`automatic-city-system-architecture.drawio`](automatic-city-system-architecture.drawio). В нём три страницы:

1. **Логическая архитектура** — презентационный слоистый вид с пиктограммами: клиенты, access layer, все доменные сервисы, Kafka, данные, интеграции, наблюдаемость, легенда и ключевые принципы.
2. **Детальная архитектура** — расширенный технический вид синхронных gRPC/HTTP2-вызовов, Kafka/outbox/inbox/retry/DLQ, service-owned storage и внешних движков.
3. **Kubernetes HA** — фактическая топология `prod` / `local-ha`: числа реплик, Istio, Patroni/Citus/PgBouncer, Kafka/Redis, backup flow и текущие точки отказа.

Готовые превью:

- [`logical-architecture.svg`](logical-architecture.svg) / [`logical-architecture.png`](logical-architecture.png)
- [`architecture-overview.svg`](architecture-overview.svg) / [`architecture-overview.png`](architecture-overview.png)
- [`kubernetes-ha.svg`](kubernetes-ha.svg) / [`kubernetes-ha.png`](kubernetes-ha.png)

После изменения архитектуры SVG и draw.io можно пересобрать без дополнительных npm-пакетов:

```powershell
node .\tools\generate-architecture-diagrams.mjs
```

## Что отражено на схемах

- Patroni использует Kubernetes API/Endpoints как DCS. Отдельного etcd-кластера для Patroni в текущих манифестах нет; показанный etcd относится к control plane Kubernetes.
- `postgres-platform` состоит из трёх Patroni members и содержит тринадцать изолированных баз прикладных сервисов.
- Ticket хранится в Citus: coordinator group из трёх members и две worker groups по два members; shard key — `department_id`.
- Перед обоими PostgreSQL-контурами стоят отдельные PgBouncer read/write pools по две реплики.
- Kafka работает как KRaft cluster из трёх combined broker/controller nodes с RF=3 и `min.insync.replicas=2`.
- Location Redis имеет master, две replicas и три Sentinel; Gateway Redis и Notification Redis пока одноузловые.
- В production API Gateway масштабируется до 2–6 replicas, остальные прикладные Deployments и Frontend пока имеют одну replica.
- MinIO, ClickHouse, Valhalla, Prometheus, OTel Collector, Jaeger, Grafana, Elasticsearch и Kibana сейчас одноузловые.
- HA PostgreSQL/Citus зависит от наличия минимум трёх независимых node failure domains. Число replicas Istio ingress/istiod в репозитории явно не закреплено.

## Основание

Схемы собраны по текущим Kustomize manifests, runtime config сервисов, Kafka topic configuration, PostgreSQL HA-документации и frontend server routes. Это описание текущего состояния, а не целевая схема «когда-нибудь».
