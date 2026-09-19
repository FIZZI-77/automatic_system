[CmdletBinding()]
param(
    [string]$Namespace = "automatic-system"
)

$ErrorActionPreference = "Stop"
$k8sRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$repositoryRoot = Resolve-Path (Join-Path $PSScriptRoot "../..")
$runtimeDirectory = Join-Path $repositoryRoot ".runtime"
$urlFile = Join-Path $runtimeDirectory "tailscale-funnel-url.txt"
$tailscaleCandidates = @(
    (Join-Path $env:ProgramFiles "Tailscale\tailscale.exe"),
    "tailscale.exe"
)
$tailscale = $tailscaleCandidates |
    Where-Object { $_ -eq "tailscale.exe" -or (Test-Path -LiteralPath $_) } |
    Select-Object -First 1

if (-not $tailscale) {
    throw "Tailscale CLI is not installed. Install Tailscale and sign in before running this script."
}

function Invoke-Kubectl {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    & kubectl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "kubectl failed: kubectl $($Arguments -join ' ')"
    }
}

function Get-TailscaleStatus {
    $status = & $tailscale status --json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read Tailscale status. Run this script from an elevated PowerShell session."
    }

    return $status
}

function Set-FrontendBaseUrl {
    param([Parameter(Mandatory = $true)][string]$PublicUrl)

    $deploymentName = (& kubectl -n $Namespace get service auth-service -o jsonpath='{.spec.selector.app}').Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to resolve the active Auth Service deployment."
    }
    if (-not $deploymentName) {
        $deploymentName = "auth-service"
    }

    $deployment = & kubectl -n $Namespace get deployment $deploymentName -o json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read deployment $deploymentName."
    }

    $configName = $deployment.spec.template.spec.containers[0].envFrom |
        ForEach-Object { $_.configMapRef.name } |
        Where-Object { $_ -like "auth-service-config*" } |
        Select-Object -First 1
    if (-not $configName) {
        throw "Auth Service ConfigMap is not referenced by deployment $deploymentName."
    }

    $config = & kubectl -n $Namespace get configmap $configName -o json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read $configName."
    }
    if ($config.data.FRONTEND_BASE_URL -eq $PublicUrl) {
        return
    }

    $patch = @{ data = @{ FRONTEND_BASE_URL = $PublicUrl } } | ConvertTo-Json -Compress
    $patchFile = Join-Path ([IO.Path]::GetTempPath()) ("tailscale-config-{0}.json" -f [guid]::NewGuid())
    try {
        [IO.File]::WriteAllText($patchFile, $patch, [Text.UTF8Encoding]::new($false))
        Invoke-Kubectl -n $Namespace patch configmap $configName --type merge --patch-file $patchFile | Out-Null
    }
    finally {
        Remove-Item -LiteralPath $patchFile -Force -ErrorAction SilentlyContinue
    }

    Invoke-Kubectl -n $Namespace rollout restart "deployment/$deploymentName" | Out-Null
    Invoke-Kubectl -n $Namespace rollout status "deployment/$deploymentName" --timeout=180s | Out-Null
}

$status = Get-TailscaleStatus
if ($status.BackendState -ne "Running" -or -not $status.Self.DNSName) {
    throw "Tailscale is not signed in. Open Tailscale, sign in, and run the script again."
}

$publicUrl = "https://$($status.Self.DNSName.TrimEnd('.'))"
$configuredHost = (Select-String -Path (Join-Path $k8sRoot "mesh/ingress/gateway-public.yaml") -Pattern '^\s*-\s+([a-z0-9.-]+\.ts\.net)\s*$').Matches.Groups[1].Value
if ($configuredHost -ne $status.Self.DNSName.TrimEnd('.')) {
    throw "The public Istio Gateway is configured for '$configuredHost', but this node is '$($status.Self.DNSName.TrimEnd('.'))'. Update the exact host before enabling Funnel."
}

Invoke-Kubectl apply -f (Join-Path $k8sRoot "mesh/ingress/gateway-public.yaml") | Out-Null
Invoke-Kubectl apply -f (Join-Path $k8sRoot "mesh/ingress/routes-public.yaml") | Out-Null

& $tailscale funnel --bg --yes http://127.0.0.1:80
if ($LASTEXITCODE -ne 0) {
    throw "Unable to enable Tailscale Funnel. Check the approval URL printed above."
}

$funnelStatus = & $tailscale funnel status --json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $funnelStatus.AllowFunnel."$configuredHost`:443") {
    throw "Tailscale Funnel is not enabled for $publicUrl."
}

Set-FrontendBaseUrl -PublicUrl $publicUrl
New-Item -ItemType Directory -Force -Path $runtimeDirectory | Out-Null
[IO.File]::WriteAllText($urlFile, $publicUrl, [Text.UTF8Encoding]::new($false))

& docker rm -f automatic-system-cloudflare-quick-tunnel 2>$null | Out-Null
Invoke-Kubectl -n $Namespace delete deployment cloudflare-quick-tunnel --ignore-not-found | Out-Null
Invoke-Kubectl -n $Namespace delete networkpolicy allow-cloudflare-quick-tunnel-egress --ignore-not-found | Out-Null
Invoke-Kubectl -n $Namespace delete deployment ngrok-tunnel --ignore-not-found | Out-Null
Invoke-Kubectl -n $Namespace delete networkpolicy allow-ngrok-tunnel-egress --ignore-not-found | Out-Null
Invoke-Kubectl -n $Namespace delete secret ngrok-authtoken --ignore-not-found | Out-Null

$checks = @(
    @{ Name = "frontend"; Path = "/" },
    @{ Name = "health"; Path = "/health" },
    @{ Name = "email verification route"; Path = "/verify-email?token=manual-token-123" }
)

foreach ($check in $checks) {
    $result = & curl.exe -sS -o NUL -w "%{http_code}" --max-time 15 -H "Host: $configuredHost" "http://127.0.0.1$($check.Path)"
    if ($LASTEXITCODE -ne 0 -or $result -ne "200") {
        throw "Local Istio $($check.Name) check failed: $result"
    }
}

Write-Host "Tailscale Funnel URL: $publicUrl"
Write-Host "Funnel configuration and local Istio route checks passed. The URL is stored in $urlFile"
