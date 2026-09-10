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
    "$k8sDir/overlays/local"
  )
  foreach ($target in $targets) {
    Write-Host "Validating $target"
    kubectl kustomize $target | kubectl apply --dry-run=client -f - > $null
    if ($LASTEXITCODE -ne 0) { throw "Validation failed: $target" }
  }
  $repoRoot = Split-Path -Parent $k8sDir
  $helm = Join-Path $repoRoot ".tools\mesh\helm.exe"
  foreach ($chart in @("applications", "dispatch")) {
    $chartPath = Join-Path $k8sDir "helm\$chart"
    & $helm lint $chartPath
    if ($LASTEXITCODE -ne 0) { throw "Helm lint failed: $chart" }
  }
  & $helm template applications (Join-Path $k8sDir "helm\applications") `
    --namespace automatic-system `
    -f (Join-Path $k8sDir "helm\applications\values-local.yaml") |
    kubectl apply --dry-run=client -f - > $null
  if ($LASTEXITCODE -ne 0) { throw "Helm client validation failed: applications" }
  Write-Host "Kustomize infrastructure and Helm applications passed client validation."
} finally {
  if ($created) { Remove-Item $secretFile -Force }
}
