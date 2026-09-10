# Flux CD for local-ha

Flux owns the stateless application release, Flagger, and the Istio ingress and
policy manifests in the current `local-ha` cluster. Stateful infrastructure,
secrets, migrations, and backup jobs remain outside Flux in this first phase.

## Prerequisites

- the cluster and Istio/Flagger CRDs are installed by `k8s/scripts/install-mesh.ps1`;
- the `automatic-system` runtime and JWT secrets already exist;
- the self-hosted GitHub runner uses the `github-runner` ServiceAccount from
  namespace `arc-runners`;
- the `test`, `feature`, and deployable `feature/**` branches contain this directory;
- the first successful local deployment creates the `deploy/local` branch
  before reconciliation is enabled.

## Install controllers

Run from the repository root:

```powershell
.\k8s\scripts\install-flux.ps1
```

This installs pinned Flux controllers and runner RBAC, but does not start Git
reconciliation. That makes the bootstrap safe before the GitOps files have been
pushed.

After the files are available in a source branch, the CI deployment job runs on
the local GitHub runner and publishes the successfully tested source snapshot to
`deploy/local`. Flux watches only that deployment branch. The job waits until
Flux has fetched the exact release commit and then removes the initial
suspension.

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
SHA tag groups, commits the GitOps snapshot to `deploy/local` with `[skip ci]`,
and waits for the changed Flagger primary deployments to promote that tag. The
source branches are never modified by the deployment job. Deployments from
`test`, `feature`, and `feature/**` share one deployment branch and one
concurrency group because they target the same local cluster.

Do not add stateful infrastructure to this Kustomization until storage adoption,
pruning, and rollback have been tested separately.
