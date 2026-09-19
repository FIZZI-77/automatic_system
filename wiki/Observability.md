# Наблюдаемость

## Метрики

Prometheus собирает:

- `/metrics` Go services;
- kube-state-metrics;
- node-exporter;
- Redis/Kafka exporter metrics;
- ClickHouse metrics;
- control-plane etcd `/metrics`;
- Istio/Flagger metrics.

Grafana dashboards разделены по applications, databases/Citus, PgBouncer, Kafka/Redis, infrastructure и deployment/Flagger.

## Трассировка

```text
Application
    ↓ OTLP/gRPC
OpenTelemetry Collector
    ↓
Jaeger
```

Проектная конфигурация использует OTLP endpoint `http://otel-collector:4317`, protocol `grpc` и parent-based trace sampling.

Полный trace требует propagation context через HTTP/gRPC. Создание нового `context.Background()` в середине flow разрушает связь span-ов.

## Журналы

```text
container stdout/stderr
    ↓
Kubernetes node logs
    ↓ Filebeat
Elasticsearch
    ↓
Kibana
```

Полезная structured log запись должна содержать service, level/message, operation, wrapped error chain и `trace_id`/`span_id`, но не secrets/tokens.

## Kiali

Kiali объединяет Kubernetes, Istio, Prometheus и Jaeger context. Его warning следует подтверждать `istioctl analyze` и реальными selectors/traffic metrics.

## Порядок диагностики пустой панели

1. Есть ли workload traffic?
2. Работает ли `/metrics`?
3. Target `UP` в Prometheus?
4. Совпадает ли metric/labels с PromQL?
5. Подходящий ли time range/dashboard variables?
6. Для canary: существовал ли canary pod в этом time range?

### Источники
[Security & observability guide](https://github.com/FIZZI-77/automatic_system/blob/test/k8s/docs/security-observability.md)
