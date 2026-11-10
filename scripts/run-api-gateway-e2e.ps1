param(
    [string]$GatewayUrl,
    [int]$LocalPort = 18081,
    [string]$Namespace = "automatic-system",
    [string]$Password = $env:DEMO_PASSWORD,
    [string[]]$TestFile,
    [switch]$SecuritySweepOnly,
    [switch]$IncludeSMTP,
    [switch]$SkipSeed
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$portForward = $null
$stdoutLog = Join-Path $repoRoot ".tmp-api-gateway-portforward.log"
$stderrLog = Join-Path $repoRoot ".tmp-api-gateway-portforward.err.log"

try {
    if ([string]::IsNullOrWhiteSpace($GatewayUrl)) {
        $GatewayUrl = "http://127.0.0.1:$LocalPort"
        $portForward = Start-Process -FilePath "kubectl.exe" `
            -ArgumentList @("-n", $Namespace, "port-forward", "svc/api-gateway", "${LocalPort}:8081") `
            -WindowStyle Hidden -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru
        Start-Sleep -Seconds 2
        if ($portForward.HasExited) {
            throw "kubectl port-forward завершился: $(Get-Content -Raw $stderrLog)"
        }
    }

    $env:E2E_API_ONLY = "1"
    $env:E2E_API_URL = $GatewayUrl
    $env:E2E_GATEWAY_HEALTH_URL = $GatewayUrl
    $env:E2E_NAMESPACE = $Namespace
    $env:E2E_STORAGE_ASSERTIONS = "1"
    $env:NO_PROXY = "127.0.0.1,localhost,$($env:NO_PROXY)"
    $env:no_proxy = $env:NO_PROXY

    if (-not [string]::IsNullOrWhiteSpace($Password)) {
        $env:DEMO_PASSWORD = $Password
        $env:E2E_DEMO_PASSWORD = $Password
    }
    if ($SkipSeed -or [string]::IsNullOrWhiteSpace($Password)) {
        $env:E2E_SKIP_SEED = "1"
        $env:E2E_RESTORE_SEED = "0"
    }

    Push-Location (Join-Path $repoRoot "Frontend")
    try {
        if ($TestFile.Count -gt 0) {
            & npx.cmd playwright test @TestFile --project=desktop-chromium
        } elseif ($SecuritySweepOnly -or [string]::IsNullOrWhiteSpace($Password)) {
            & npx.cmd playwright test e2e/gateway-coverage.spec.ts e2e/gateway-route-sweep.spec.ts e2e/gateway-auth-storage.spec.ts e2e/gateway-auth-lifecycle.spec.ts e2e/gateway-auth-tokens.spec.ts e2e/gateway-read-surface.spec.ts e2e/gateway-assets-stateful.spec.ts e2e/gateway-master-data-stateful.spec.ts e2e/gateway-tickets-stateful.spec.ts e2e/gateway-sla-stateful.spec.ts e2e/gateway-brigades-stateful.spec.ts e2e/gateway-profiles-stateful.spec.ts e2e/gateway-location-routing-stateful.spec.ts e2e/gateway-dispatch-stateful.spec.ts e2e/gateway-files-stateful.spec.ts e2e/gateway-reports-stateful.spec.ts e2e/gateway-notifications-stateful.spec.ts --project=desktop-chromium
        } else {
            & npx.cmd playwright test e2e/api-contracts.spec.ts e2e/negative-api.spec.ts e2e/gateway-coverage.spec.ts e2e/gateway-route-sweep.spec.ts e2e/gateway-auth-storage.spec.ts e2e/gateway-auth-lifecycle.spec.ts e2e/gateway-auth-tokens.spec.ts e2e/gateway-read-surface.spec.ts e2e/gateway-assets-stateful.spec.ts e2e/gateway-master-data-stateful.spec.ts e2e/gateway-tickets-stateful.spec.ts e2e/gateway-sla-stateful.spec.ts e2e/gateway-brigades-stateful.spec.ts e2e/gateway-profiles-stateful.spec.ts e2e/gateway-location-routing-stateful.spec.ts e2e/gateway-dispatch-stateful.spec.ts e2e/gateway-files-stateful.spec.ts e2e/gateway-reports-stateful.spec.ts e2e/gateway-notifications-stateful.spec.ts --project=desktop-chromium
        }
        if ($LASTEXITCODE -ne 0) { throw "API Gateway E2E завершился с ошибкой" }
        if ($IncludeSMTP) {
            & npx.cmd playwright test e2e/gateway-auth-smtp.spec.ts --project=desktop-chromium
            if ($LASTEXITCODE -ne 0) { throw "SMTP API Gateway E2E завершился с ошибкой" }
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    if ($portForward -and -not $portForward.HasExited) {
        Stop-Process -Id $portForward.Id -Force
    }
}
