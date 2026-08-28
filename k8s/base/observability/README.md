# Observability

The stack receives OTLP telemetry from every backend service:

- OpenTelemetry Collector accepts OTLP gRPC on `otel-collector:4317`;
- Jaeger stores and displays distributed traces;
- Prometheus stores application, runtime, gRPC, HTTP, PostgreSQL and span-derived RED metrics;
- Grafana has provisioned Prometheus and Jaeger data sources, including metric-exemplar links to traces.

Application configuration is provided by the generated `telemetry-config` ConfigMap. The SDK uses parent-based sampling and exports asynchronously, so a temporary Collector outage does not stop an application.

For local access:

```powershell
./k8s/scripts/open-observability.ps1
```

Then open Grafana at <http://localhost:3001>, Jaeger at <http://localhost:16686>, and Prometheus at <http://localhost:9090>.

For production, replace Jaeger's in-memory storage and the Prometheus/Grafana `emptyDir` volumes with retained storage before relying on telemetry for incident history.

