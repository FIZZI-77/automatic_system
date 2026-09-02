$ErrorActionPreference = "Stop"
$k8sDir = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $k8sDir
$ns = "automatic-system"
$local = Join-Path $k8sDir "overlays/local"
$secretDir = Join-Path $local "secrets"
$secretFile = Join-Path $secretDir "runtime.env"
$secretExample = Join-Path $secretDir "runtime.env.example"

if (-not (Test-Path $secretFile)) {
  Copy-Item $secretExample $secretFile
  Write-Warning "Created $secretFile from local-development example values. Review it before any non-local use."
}

kubectl apply -k "$k8sDir/base/namespace"

# Runtime Secret is declarative but sourced from a gitignored local env file.
kubectl apply -k $secretDir

# JWT key Secrets are intentionally not stored in Git.
if (-not (kubectl -n $ns get secret jwt-private-key --ignore-not-found)) {
  $private = Join-Path $repoRoot "keys/private.pem"
  if (-not (Test-Path $private)) { throw "Missing $private" }
  kubectl -n $ns create secret generic jwt-private-key --from-file=private.pem=$private
}
if (-not (kubectl -n $ns get secret jwt-public-key --ignore-not-found)) {
  $public = Join-Path $repoRoot "keys/public.pem"
  if (-not (Test-Path $public)) { throw "Missing $public" }
  kubectl -n $ns create secret generic jwt-public-key --from-file=public.pem=$public
}

Write-Host "Applying infrastructure..."
kubectl apply -k "$local/infra"

Write-Host "Waiting for stateful infrastructure..."
$statefulSets = @(
  "postgres-auth","postgres-ticket","postgres-department","postgres-brigade","postgres-profile","postgres-location",
  "postgres-routing","postgres-dispatch","postgres-file","postgres-sla","postgres-notification","postgres-audit",
  "postgres-report","postgres-asset","redis-gateway","redis-notification","redis-location-master",
  "redis-location-replica-1","redis-location-replica-2","kafka-1","kafka-2","kafka-3","minio","clickhouse","valhalla"
)
foreach($s in $statefulSets) { kubectl -n $ns rollout status "statefulset/$s" --timeout=900s }

$infraDeployments = @("redis-location-sentinel-1","redis-location-sentinel-2","redis-location-sentinel-3","mailhog")
foreach($d in $infraDeployments) { kubectl -n $ns rollout status "deployment/$d" --timeout=300s }

# Jobs are immutable: replace only this deployment's init/migration jobs.
kubectl -n $ns delete job -l automatic-system.io/job-type=migration --ignore-not-found
kubectl -n $ns delete job -l automatic-system.io/job-type=init --ignore-not-found

Write-Host "Running migrations and initialization jobs..."
kubectl apply -k "$local/migrations"
$jobs = @(
  "kafka-init"
)
foreach($j in $jobs) { kubectl -n $ns wait --for=condition=complete "job/$j" --timeout=600s }

Write-Host "Applying applications..."
$applicationsHelm = Join-Path $PSScriptRoot "deploy-applications-helm.ps1"
& $applicationsHelm -Environment local
if ($LASTEXITCODE -ne 0) { throw "Applications Helm release failed" }

Write-Host "Deployment complete."
kubectl -n $ns get pods
kubectl -n $ns get svc
