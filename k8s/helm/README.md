# Helm releases

Application workloads are moving from Kustomize to independently deployable Helm releases. Stateful infrastructure, observability, Istio policy and bootstrap resources remain in Kustomize until their separate lifecycle and rollback procedures are migrated.

## Applications

`k8s/helm/applications` is the single stateless application release. Dispatch is included as a local subchart because it has additional scaling and migration settings; it is not deployed as a separate release.

It contains Analytics, API Gateway, Asset, Audit, Auth, Brigade, Department, Dispatch, File, Frontend, Location, Notification, Profile, Report, Routing, SLA and Ticket.

The release owns all application Deployments, Services and ConfigMaps, API Gateway and Dispatch HPA/PDB resources, PostgreSQL Goose hooks, and the Analytics ClickHouse schema hook.

Environment files are `values-local.yaml`, `values-local-ha.yaml`, `values-dev.yaml` and `values-prod.yaml`. Dev and production require immutable application and migrator tags. HA values preserve the platform/ticket PgBouncer primary and replica endpoints.

The Dispatch subchart owns:

- `Deployment/dispatch-service`
- `Service/dispatch-service`
- `ConfigMap/dispatch-service-config`
- `HorizontalPodAutoscaler/dispatch-service` when enabled
- `PodDisruptionBudget/dispatch-service` when enabled
- a pre-install/pre-upgrade Goose migration hook when enabled

The migration hook runs before the Deployment changes. `--atomic --wait` rolls an unsuccessful application release back; database migrations must therefore remain backward compatible.

Local deployment:

```powershell
.\k8s\scripts\deploy-applications-helm.ps1 -Environment local
```

Local HA deployment:

```powershell
.\k8s\scripts\deploy-applications-helm.ps1 -Environment local-ha
```

Production requires explicit immutable application and migrator tags:

```powershell
.\k8s\scripts\deploy-applications-helm.ps1 `
  -Environment prod `
  -ImageTag sha-<commit> `
  -MigratorTag sha-<commit>
```

For the one-time adoption of resources created by Kustomize, add `-TakeOwnership`. Do not use that flag for normal upgrades.

Inspect or roll back a release:

```powershell
& .\.tools\mesh\helm.exe history applications -n automatic-system
& .\.tools\mesh\helm.exe rollback applications <revision> -n automatic-system --wait
```
