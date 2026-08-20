# automatic_system — Kubernetes manifests for CURRENT `test` Compose topology

This is intentionally **not** the future Patroni/Istio/production architecture. It mirrors the current development stack: per-service PostgreSQL, 3-node Kafka KRaft, Redis, Redis Sentinel for Location, MinIO, ClickHouse, Valhalla, MailHog, current Go services, API Gateway, and optional transponder simulators.

## Important choices

- Namespace: `automatic-system`.
- API Gateway is the only externally exposed application service (`LoadBalancer`, port 8081).
- Frontend is not deployed because the current root `docker-compose.yml` does not define a frontend service.
- PostgreSQL remains one physical instance per current service, matching Compose (no Patroni yet).
- Kafka stays 3-node KRaft, matching the current design.
- Location Redis keeps 1 master + 2 replicas + 3 Sentinels.
- Images for project services are local tags `automatic-system/<service>:dev`.
- Migration SQL is baked into local migration images so Kubernetes does not depend on host bind mounts.
- Credentials are development defaults copied from the current Compose/env examples. Change them before using this outside a local cluster.

## Put this directory in the repository

Place this extracted folder directly under the repository root. The PowerShell scripts resolve their own directory, so the folder may keep the name `automatic-system-k8s-current` or be renamed to `k8s-current`.

## 1. Build local images

From repository root in PowerShell:

```powershell
.\automatic-system-k8s-current\build-images.ps1
```

Docker Desktop Kubernetes normally sees images from Docker Desktop. If your cluster uses another runtime/VM, push these images to a registry and replace the `automatic-system/*:dev` image names.

## 2. JWT keys

The manifests deliberately do not contain the private key. Create secrets from the existing project keys:

```powershell
kubectl apply -f .\automatic-system-k8s-current\manifests\00-namespace-secrets.yaml
kubectl -n automatic-system create secret generic jwt-private-key --from-file=private.pem=.\keys\private.pem
kubectl -n automatic-system create secret generic jwt-public-key  --from-file=public.pem=.\keys\public.pem
```

If the secrets already exist, delete/recreate them or use `kubectl create ... --dry-run=client -o yaml | kubectl apply -f -`.

## 3. Start the stack

```powershell
.\automatic-system-k8s-current\apply.ps1
```

The script applies infrastructure first, waits for pods, runs migrations, waits for every migration Job, then starts applications and API Gateway.

## 4. Check

```powershell
kubectl -n automatic-system get pods
kubectl -n automatic-system get svc
kubectl -n automatic-system get jobs
kubectl -n automatic-system logs deploy/api-gateway
```

On Docker Desktop, `api-gateway` should normally be reachable through the LoadBalancer on port `8081`. If Docker Desktop does not assign localhost automatically:

```powershell
kubectl -n automatic-system port-forward svc/api-gateway 8081:8081
```

Location HTTP can be inspected with:

```powershell
kubectl -n automatic-system port-forward svc/location-service 8082:8080
```

MinIO console:

```powershell
kubectl -n automatic-system port-forward svc/minio 9001:9001
```

## Optional transponder simulators

They are excluded from `apply.ps1` by default because they continuously generate traffic. Enable them after the main stack is healthy:

```powershell
kubectl apply -f .\automatic-system-k8s-current\manifests\32-transponders.yaml
```

## Valhalla

The current configuration downloads the Central Federal District Russia OSM extract. First initialization can take a long time and consume substantial disk/CPU. The manifest gives Valhalla an 8 Gi PVC; increase it if tile building runs out of space.

## Known differences from Docker Compose

Kubernetes has no `depends_on`. Ordering is achieved with the `apply.ps1` phases and readiness/wait logic. Redis Sentinel configuration is represented as a ConfigMap and Sentinel state itself is disposable. Project services use TCP liveness/readiness probes because not every current service exposes a uniform HTTP health endpoint. This can later be tightened to native gRPC/HTTP health probes service-by-service.

This package is a **bring-up configuration**, not the final production architecture. Once it works, it is a good baseline for the later split deployment/Helm/Istio/HA work.
