# Manifest decisions

- Current runtime topology is preserved; no Patroni, Istio, Citus, PgBouncer or observability stack is introduced here.
- Application Deployments remain at one replica in local mode.
- PDB is deferred until stateless services run with at least two replicas.
- HPA is deferred until metrics and representative resource requests are validated.
- NetworkPolicy is deferred to avoid silently breaking the current service graph; it should be added from observed/declared dependencies.
- StorageClass is not pinned in base/local so the Docker Desktop default provisioner remains usable.
- PVC retention is explicit on StatefulSets.
- Secrets are generated from an ignored local env file; production should use an external secret manager/GitOps-compatible secret solution.
