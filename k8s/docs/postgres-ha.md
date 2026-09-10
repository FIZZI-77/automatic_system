# PostgreSQL HA topology

Production uses two database contours instead of one Patroni cluster per service.

Applications do not connect to Patroni directly. Each write and read route has
two PgBouncer replicas in transaction-pooling mode:

- `pgbouncer-platform-primary:6432` and `pgbouncer-platform-replicas:6432`;
- `pgbouncer-ticket-primary:6432` and `pgbouncer-ticket-replicas:6432`.

Migration and administrative Jobs bypass PgBouncer and use the Patroni services
on port 5432. This keeps DDL, backup, failover, and Citus management outside the
transaction pool.

The production workflow replaces every `sha-*` image placeholder in the apps,
migrations, infrastructure, and connectivity-check overlays with the 12-character
SHA tag published by the same workflow. After migrations and Citus distribution,
`pgbouncer-connectivity-check` executes `SELECT 1` through all four pooler routes;
application rollout stops if any route is unavailable.

## Platform cluster

`postgres-platform` is a three-node Patroni cluster shared by Auth, Department,
Brigade, Profile, Location, Routing, Dispatch, File, SLA, Notification, Audit,
Report, and Asset. Services still have separate databases, owners, credentials,
and migration jobs.

- Writes and migrations use `postgres-platform-primary`.
- Eventually consistent reads use `postgres-platform-replicas`.
- Transactional flows, outbox relays, inbox consumers, and `SELECT ... FOR UPDATE`
  always use the primary.
- Location history is partitioned monthly by `recorded_at`; its maintenance worker
  creates future partitions in advance.

## Ticket Citus cluster

`postgres-ticket-citus` is one logical Citus deployment managed by Patroni. It
contains a three-node coordinator group and two two-node worker groups. These are
Citus availability groups, not independent service databases.

Ticket tables are distributed by `department_id`. Status history, work reports,
and report files carry the same key and are colocated with `tickets`. Categories
are a Citus reference table. The distribution Job waits for the normal Ticket
migrations before converting the prepared tables.

Writes use `postgres-ticket-primary`; eligible reads use
`postgres-ticket-replicas`. A request that must read its own just-committed write
must stay on the primary because streaming replicas can lag.

## Backup and recovery

Replicas provide availability; they are not backups. pgBackRest archives WAL and
stores differential backups in the versioned MinIO bucket `postgres-backups`.
Initialization Jobs create and verify every stanza before scheduled backups begin.

Before production rollout:

1. Replace every `change-me-*` value in `runtime.env` and create `runtime-secrets`.
2. Build and publish the two HA images and PgBouncer image, then replace the
   placeholder `sha-0000000` tags.
3. Apply data infrastructure, wait for Patroni leaders and pgBackRest init Jobs,
   then run service migrations.
4. Wait for the Citus distribution Job before starting Ticket traffic.
5. Execute and record a restore/PITR drill in an isolated namespace.

Database TLS is not enabled by these manifests. Enable server certificates and
change application DSNs from `sslmode=disable` before exposing the cluster outside
the namespace.
