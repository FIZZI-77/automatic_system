param(
  [string]$IstioVersion = "1.30.3",
  [string]$HelmVersion = "3.18.6",
  [string]$KialiVersion = "2.27.0",
  [ValidateSet("local", "prod")]
  [string]$Environment = "local",
  [string]$KialiOIDCIssuerURI = $env:KIALI_OIDC_ISSUER_URI,
  [string]$KialiOIDCClientID = $env:KIALI_OIDC_CLIENT_ID,
  [string]$KialiPublicHost = $env:KIALI_PUBLIC_HOST
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$toolRoot = Join-Path $repoRoot ".tools\mesh"
$istioctl = Join-Path $toolRoot "istioctl.exe"
$helm = Join-Path $toolRoot "helm.exe"

New-Item -ItemType Directory -Force -Path $toolRoot | Out-Null

if (-not (Test-Path -LiteralPath $istioctl)) {
  $archive = Join-Path $toolRoot "istioctl.zip"
  Invoke-WebRequest `
    -Uri "https://github.com/istio/istio/releases/download/$IstioVersion/istioctl-$IstioVersion-win.zip" `
    -OutFile $archive
  Expand-Archive -Path $archive -DestinationPath $toolRoot -Force
  Remove-Item -LiteralPath $archive -Force
}

if (-not (Test-Path -LiteralPath $helm)) {
  $archive = Join-Path $toolRoot "helm.zip"
  $expanded = Join-Path $toolRoot "helm-expanded"
  Invoke-WebRequest `
    -Uri "https://get.helm.sh/helm-v$HelmVersion-windows-amd64.zip" `
    -OutFile $archive
  Expand-Archive -Path $archive -DestinationPath $expanded -Force
  Copy-Item -LiteralPath (Join-Path $expanded "windows-amd64\helm.exe") -Destination $helm
  Remove-Item -LiteralPath $archive -Force
  Remove-Item -LiteralPath $expanded -Recurse -Force
}

& $istioctl install `
  --filename (Join-Path $repoRoot "k8s\mesh\istio-operator.yaml") `
  --skip-confirmation `
  --verify
if ($LASTEXITCODE -ne 0) {
  throw "Istio installation failed"
}

& $helm repo add kiali https://kiali.org/helm-charts --force-update
& $helm repo update kiali
$kialiValues = Join-Path $repoRoot "k8s\mesh\kiali-values.yaml"
$kialiArguments = @(
  "upgrade", "--install", "kiali-server", "kiali/kiali-server",
  "--namespace", "istio-system",
  "--version", $KialiVersion,
  "--values", $kialiValues,
  "--wait",
  "--timeout", "5m"
)

if ($Environment -eq "prod") {
  if (-not $KialiOIDCIssuerURI -or -not $KialiOIDCClientID -or -not $KialiPublicHost) {
    throw "Production Kiali requires KIALI_OIDC_ISSUER_URI, KIALI_OIDC_CLIENT_ID and KIALI_PUBLIC_HOST"
  }
  $kialiValues = Join-Path $repoRoot "k8s\mesh\kiali-values-prod.yaml"
  $kialiArguments[9] = $kialiValues
  $kialiArguments += @(
    "--set-string", "auth.openid.issuer_uri=$KialiOIDCIssuerURI",
    "--set-string", "auth.openid.client_id=$KialiOIDCClientID",
    "--set-string", "server.web_fqdn=$KialiPublicHost"
  )
}

& $helm @kialiArguments
if ($LASTEXITCODE -ne 0) {
  throw "Kiali installation failed"
}

kubectl label namespace automatic-system istio-injection=enabled --overwrite
kubectl apply -k (Join-Path $repoRoot "k8s\mesh\policies")
if ($LASTEXITCODE -ne 0) {
  throw "Istio baseline policy installation failed"
}

& (Join-Path $repoRoot "k8s\scripts\setup-ingress.ps1")
if ($LASTEXITCODE -ne 0) {
  throw "Istio ingress configuration failed"
}

$applicationOverlay = Join-Path $repoRoot "k8s\overlays\local-ha\apps"
if ($Environment -eq "prod") {
  $applicationOverlay = Join-Path $repoRoot "k8s\overlays\prod\apps"
}
kubectl apply -k $applicationOverlay
if ($LASTEXITCODE -ne 0) {
  throw "Application sidecar configuration failed"
}

$observabilityDeployments = @("grafana", "jaeger", "otel-collector", "prometheus")
foreach ($deployment in $observabilityDeployments) {
  kubectl annotate deployment/$deployment -n automatic-system `
    sidecar.istio.io/inject=false --overwrite
}

kubectl rollout restart deployment -n automatic-system `
  -l "app.kubernetes.io/component in (gateway,backend,frontend)"
kubectl rollout status deployment/kiali -n istio-system --timeout=180s

Write-Host "Istio and Kiali are ready."
Write-Host "Run: kubectl port-forward -n istio-system svc/kiali 20001:20001"
