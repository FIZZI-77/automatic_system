# Service level objectives and alerts

## Scope and measurement window

These objectives cover the critical path: ingress/API Gateway, authentication,
Ticket lifecycle, Dispatch, Routing, SLA and notifications, plus their Kafka,
PostgreSQL, PgBouncer and Redis dependencies.

The current Prometheus retention is seven days, so compliance is calculated over
a rolling 7-day window. A 30-day production SLO needs at least 35 days of retained
metrics and persistent Prometheus storage.

| SLO | Target | Error budget per 7 days | SLI |
|---|---:|---:|---|
| Gateway availability | 99.9% | 10m 4.8s | non-5xx requests / all non-probe requests |
| Gateway latency | 99% under 1s | 1% of requests | requests in the `le=1.0` histogram bucket / all requests |
| Backend gRPC availability | 99.9% | 10m 4.8s | calls without server-side gRPC failure / all non-health calls |
| Critical workload availability | 99.9% | 10m 4.8s | available replicas / desired replicas |
| Event freshness proxy | 99.9% below 100 messages | 10m 4.8s | Kafka consumer lag evaluation intervals within target |
| Database endpoint availability | 99.95% | 5m 2.4s | healthy PostgreSQL/PgBouncer endpoints and exactly one primary |
| Observability coverage | 99% | 1h 40m 48s | successful critical Prometheus scrapes / expected scrapes |

Client-caused HTTP 4xx, gRPC validation, authentication and permission errors do
not consume backend availability budgets. HTTP 5xx and gRPC `UNKNOWN`,
`DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED`, `INTERNAL`, `UNAVAILABLE` and
`DATA_LOSS` do consume them.

## Gateway availability

Fast burn pages on a 14.4x burn rate in both 5-minute and 1-hour windows. Slow
burn warns on a 6x rate in both 30-minute and 6-hour windows. Start with Gateway
logs grouped by route/status, then follow the trace ID into Jaeger and inspect the
downstream gRPC service.

## Gateway latency

The objective is 99% of non-probe requests below one second. This threshold
captures user-visible degradation while leaving normal variance for mixed read
and write operations.

## Backend gRPC availability

The SLI is evaluated per service. Business errors such as invalid input, missing
records, conflicts and permission denial are excluded; only server and dependency
failures consume the budget.

## Critical workloads

No available replica is critical after two minutes. Fewer available replicas than
desired is a warning after ten minutes. Inspect scheduling events, readiness probe
failures, resource pressure and the most recent container termination reason.

## Event freshness

Lag above 100 messages for ten minutes is a warning; above 1000 for five minutes
is critical. Inspect the named consumer group, topic, partition lag, consumer logs
and Kafka broker health. Message lag is a proxy: a true time-to-process SLO needs
an event-age histogram in each consumer.

## Data plane

The shared platform Patroni cluster and the Ticket coordinator must each have
exactly one primary. PostgreSQL, PgBouncer and Redis endpoint health is alertable
independently so routing, rate limiting and persistence failures remain visible.

## Observability coverage

A down scrape target warns because missing telemetry makes SLO calculations
optimistic or absent. Check the target in Prometheus, its Service/Pod endpoint,
NetworkPolicy and Istio mTLS before treating a missing series as a healthy zero.

## Grafana

Prometheus evaluates these rules and Grafana displays them under **Alerting →
Alert rules → Data source-managed** for the provisioned Prometheus datasource.
Notification delivery additionally requires an Alertmanager and contact-point
routing; neither is currently provisioned in this local stack.
