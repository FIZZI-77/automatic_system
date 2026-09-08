# Flux CD for local-ha

Flux owns the stateless application release, Flagger, and the Istio ingress and
policy manifests in the current `local-ha` cluster. Stateful infrastructure,
secrets, migrations, and backup jobs remain outside Flux in this first phase.

## Prerequisites

- the cluster and Istio/Flagger CRDs are installed by `k8s/scripts/install-mesh.ps1`;
- the `automatic-system` runtime and JWT secrets already exist;
- the self-hosted GitHub runner uses the `github-runner` ServiceAccount from
  namespace `arc-runners`;
- the `test` and deployable `feature/**` branches contain this directory before
  reconciliation is enabled.

## Install controllers

Run from the repository root:

```powershell
.\k8s\scripts\install-flux.ps1
```

This installs pinned Flux controllers and runner RBAC, but does not start Git
reconciliation. That makes the bootstrap safe before the GitOps files have been
pushed.

After the files are available in the remote branch, the CI deployment job runs
on the local GitHub runner, points Flux at the successfully tested `test` or
`feature/**` branch, waits until Flux has fetched the exact release commit, and
removes the initial suspension.

For a manual first activation after the files are pushed:

```powershell
.\k8s\scripts\install-flux.ps1 -ConfigureLocalHASync
kubectl patch kustomization automatic-system-local-ha `
  -n flux-system `
  --type merge `
  -p '{"spec":{"suspend":false}}'
```

## Ownership boundary

Flux reconciles:

- `HelmRelease/applications` in `automatic-system`;
- `HelmRelease/flagger` in `flagger-system`;
- `k8s/mesh/policies` and `k8s/mesh/ingress`.

The release values are generated from
`clusters/local-ha/applications-values.yaml`. CI changes only the three immutable
SHA tags, commits the GitOps update to the tested branch with `[skip ci]`, and
waits for all 17 Flagger primary deployments to promote that tag. Deployments
from `test` and `feature/**` share one concurrency group because they target the
same local cluster.

Do not add stateful infrastructure to this Kustomization until storage adoption,
pruning, and rollback have been tested separately.
