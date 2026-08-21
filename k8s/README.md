# automatic_system Kubernetes

This directory is the Kubernetes deployment for the **current project topology**. It intentionally does not introduce the planned future Patroni/Istio/Citus architecture.

## Layout

- `base/apps/` — one folder per application: Deployment, Service and ConfigMap.
- `base/data/postgres/` — one folder per current PostgreSQL/PostGIS instance.
- `base/data/redis/` — gateway Redis, notification Redis, and Location Redis + Sentinel.
- `base/data/kafka/` — the current three KRaft brokers.
- `base/data/{minio,clickhouse,valhalla}/` — specialized stateful infrastructure.
- `base/migrations/` — one Job per migration/init task.
- `base/auxiliary/` — local supporting services such as MailHog.
- `overlays/local/` — phased local overlays: `secrets`, `infra`, `migrations`, `apps`, plus a full-state aggregate.
- `optional/transponders/` — simulators, not deployed by default.
- `scripts/` — build, validate and deployment helpers.

## Maturity changes from the initial bring-up bundle

The manifests now include component-level files, phased Kustomize composition, standard labels, explicit rolling strategies, startup/readiness/liveness probes, resource requests/limits, service-account token disabling, RuntimeDefault seccomp for workloads, application capability dropping, StatefulSet PVC retention, selective Job cleanup, Job deadlines/TTL/resources, and secret/config separation.

TCP probes remain on Go gRPC services because the current deployment is known to work with them. Replace them with Kubernetes `grpc:` probes once every service implements and exposes `grpc.health.v1.Health` consistently.

PDB/HPA/NetworkPolicy are intentionally not enabled in the local current topology. PDB is not useful with one application replica, HPA needs metrics and tested resource sizing, and NetworkPolicy should be introduced after connectivity dependencies are explicitly verified.

## Local secrets

`overlays/local/secrets/runtime.env` is ignored by Git. On first run `scripts/apply.ps1` copies the example file. These are development defaults only; review them before use.

JWT private/public keys are not embedded in manifests. `apply.ps1` creates Kubernetes Secrets from `keys/private.pem` and `keys/public.pem` in the repository root if those Secrets do not already exist.

## Build

From repository root:

```powershell
.\k8s\scripts\build-images.ps1
```

## Validate

```powershell
.\k8s\scripts\validate.ps1
```

## Deploy

```powershell
.\k8s\scripts\apply.ps1
```

The script applies the cluster in phases: `secrets -> infra -> migrations -> apps`, so migration Jobs are not started before databases/Kafka/Redis are ready.

Watch status:

```powershell
kubectl get pods -n automatic-system -w
```

The base API Gateway Service is `ClusterIP`; the local overlay patches it to `LoadBalancer`.

Gateway:

```powershell
kubectl get svc api-gateway -n automatic-system
```

Optional transponder simulators:

```powershell
.\k8s\scripts\apply-transponders.ps1
```

## Storage

Current local sizes intentionally remain small to match the existing project topology. StatefulSets use `persistentVolumeClaimRetentionPolicy: Retain` for scale/delete operations. The default StorageClass is intentionally not hard-coded so Docker Desktop can use its cluster default. Production storage sizing, CSI class, backup and restore policy should be environment-specific.

## Next production-oriented steps

After the current manifests have been exercised under load: immutable registry tags/digests, separate stage/prod overlays, gRPC health probes, multiple replicas for stateless apps, PDBs, HPA, NetworkPolicy, external secret management, backup/restore tests, and finally the separately planned HA/service-mesh architecture.
