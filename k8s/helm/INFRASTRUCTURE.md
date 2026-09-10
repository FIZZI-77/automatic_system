# Infrastructure Helm direction

Infrastructure must use releases independent from `applications`, with pinned chart and application versions, explicit CRD upgrade procedures, backups and restore tests.

Preferred upstream ownership boundaries:

- Kafka: Strimzi operator and Kafka custom resources.
- ClickHouse: Altinity ClickHouse operator.
- Elasticsearch: Elastic Cloud on Kubernetes (ECK).
- Prometheus/Grafana/Alertmanager: Prometheus Community `kube-prometheus-stack`.
- Istio and Kiali: their official Helm charts.
- Redis and MinIO: evaluate maintained operator/chart versions against the existing Sentinel and bucket lifecycle requirements before adoption.

The PostgreSQL topology is an exception. The existing shared etcd, multiple Patroni clusters and Citus coordinator/worker groups must first move unchanged into an internal infrastructure chart. Replacing it with a generic PostgreSQL chart would break the agreed topology and is a separate architecture migration.

Do not add these dependencies to the `applications` release. Data-plane rollback, CRDs, backups and application rollout have different failure domains.

