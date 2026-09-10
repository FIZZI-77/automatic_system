# Audit Service

Append-only audit trail built from domain events. The service consumes Kafka independently, deduplicates by topic and event ID, and exposes read-only gRPC queries to administrators and dispatchers.

Configuration is loaded from `config.yaml`; `DATABASE_URL` remains an environment secret.
