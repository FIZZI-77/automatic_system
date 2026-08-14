# Analytics Service

Kafka-driven ClickHouse read model for ticket volume, lifecycle time, SLA breaches and breakdowns. The service is read-only from the business workflow perspective and supports replay through a new Kafka consumer group.

Local development uses one ClickHouse node. Production should use ClickHouse Keeper, replicated local tables and Distributed query tables across at least two shards with two replicas when availability and measured load require it.
