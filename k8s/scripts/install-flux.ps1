param(
  [string]$FluxVersion = "2.9.5",
  [switch]$ConfigureLocalHASync
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$installManifest = "https://github.com/fluxcd/flux2/releases/download/v$FluxVersion/install.yaml"

kubectl apply --server-side -f $installManifest
if ($LASTEXITCODE -ne 0) {
  throw "Flux installation failed"
}

kubectl wait deployment --all -n flux-system --for=condition=Available --timeout=5m
if ($LASTEXITCODE -ne 0) {
  throw "Flux controllers are not ready"
}

kubectl apply -f (Join-Path $repoRoot "k8s\github-runner\flux-rbac.yaml")
if ($LASTEXITCODE -ne 0) {
  throw "Flux runner RBAC installation failed"
}

if ($ConfigureLocalHASync) {
  kubectl apply -f (Join-Path $repoRoot "k8s\flux\bootstrap\local-ha-sync.yaml")
  if ($LASTEXITCODE -ne 0) {
    throw "Flux local HA sync configuration failed"
  }
}

Write-Host "Flux $FluxVersion controllers are ready."
if (-not $ConfigureLocalHASync) {
  Write-Host "Git reconciliation was not enabled. Use -ConfigureLocalHASync after the GitOps files are pushed."
}
