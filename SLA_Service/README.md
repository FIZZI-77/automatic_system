# SLA Service

SLA Service tracks response and resolution deadlines for tickets. It consumes `tickets.events.v1`, selects the most specific active rule, stores the current SLA and history, and publishes lifecycle events to `sla.events.v1` through a transactional outbox.

Rule matching order is based on specificity: department, category and priority; unset fields act as wildcards. Default rules for every priority are installed by the migration.

## API

The gRPC API exposes rule CRUD, ticket SLA lookup/listing and history. Mutation of rules requires `admin`; SLA reads allow `admin`, `dispatcher` and `worker`. API Gateway exposes the same operations under `/sla`.

## Runtime

- PostgreSQL stores rules, current SLA, history, inbox and outbox.
- Kafka input: `tickets.events.v1`.
- Kafka output: `sla.events.v1`.
- The deadline scanner is safe for concurrent replicas through `FOR UPDATE SKIP LOCKED`.
- Health is exposed through standard gRPC health checking.

Run tests with `go test ./...`.
