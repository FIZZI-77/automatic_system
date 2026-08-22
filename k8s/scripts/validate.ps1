$ErrorActionPreference = "Stop"
$k8sDir = Split-Path -Parent $PSScriptRoot
$secretDir = Join-Path $k8sDir "overlays/local/secrets"
$secretFile = Join-Path $secretDir "runtime.env"
$secretExample = Join-Path $secretDir "runtime.env.example"
$created = $false
if (-not (Test-Path $secretFile)) { Copy-Item $secretExample $secretFile; $created = $true }
try {
  $targets = @(
    "$k8sDir/base/namespace",
    "$k8sDir/overlays/local/secrets",
    "$k8sDir/overlays/local/infra",
    "$k8sDir/overlays/local/migrations",
    "$k8sDir/overlays/local/apps",
    "$k8sDir/overlays/local"
  )
  foreach ($target in $targets) {
    Write-Host "Validating $target"
    kubectl kustomize $target | kubectl apply --dry-run=client -f - > $null
    if ($LASTEXITCODE -ne 0) { throw "Validation failed: $target" }
  }
  Write-Host "All Kustomize targets rendered and passed kubectl client validation."
} finally {
  if ($created) { Remove-Item $secretFile -Force }
}
