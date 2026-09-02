param(
    [string]$Scenario = 'gateway',
    [string]$Rates = '10',
    [string]$BaseUrl = 'http://localhost:8081',
    [string]$Warmup = '30s',
    [string]$Measurement = '3m',
    [string]$Stabilization = '15s',
    [string]$RunPrefix = '',
    [switch]$AllowWrites
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$runIdPrefix = if ($RunPrefix) { "$RunPrefix-" } else { '' }
$runId = "$runIdPrefix$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))-$($Scenario.Replace('/','-'))"
$rawDir = Join-Path $repoRoot "load-tests\results\raw\$runId"
New-Item -ItemType Directory -Force -Path $rawDir | Out-Null

$scripts = @{
    gateway = 'gateway/baseline.js'
    'gateway-authenticated-read' = 'gateway/authenticated-read.js'
    'auth-login' = 'auth/login.js'
    'auth-refresh' = 'auth/refresh.js'
    'ticket-read' = 'ticket/read.js'
    'ticket-baseline' = 'ticket/baseline.js'
    'ticket-write' = 'ticket/write.js'
    'ticket-mixed' = 'ticket/mixed.js'
    'ticket-saturation' = 'ticket/saturation.js'
    location = 'location/steady.js'
    'dispatch-preview' = 'dispatch/preview.js'
    analytics = 'analytics/queries.js'
    'services-parallel' = 'services/parallel-read.js'
    full = 'full-system/mixed.js'
}
if (-not $scripts.ContainsKey($Scenario)) { throw "Unknown scenario: $Scenario" }

$isWriteScenario = @('location', 'full', 'ticket-write', 'ticket-mixed', 'ticket-saturation') -contains $Scenario
if ($isWriteScenario -and -not $AllowWrites -and $env:LOAD_TEST_ALLOW_DESTRUCTIVE -ne 'true') {
    throw 'Write scenario requires -AllowWrites or LOAD_TEST_ALLOW_DESTRUCTIVE=true'
}
if ($isWriteScenario -and $BaseUrl -match '(?i)prod|production') { throw 'Production target is forbidden' }

$summary = Join-Path $rawDir 'k6.json'
$scriptPath = "load-tests/k6/$($scripts[$Scenario])"
$commonArgs = @(
    'run', '--quiet', '--summary-export', $summary,
    '--env', "BASE_URL=$BaseUrl", '--env', "K6_RATES=$Rates", '--env', "K6_RUN_ID=$runId",
    '--env', "K6_WARMUP=$Warmup", '--env', "K6_MEASUREMENT=$Measurement", '--env', "K6_STABILIZATION=$Stabilization",
    $scriptPath
)

$k6 = Get-Command k6 -ErrorAction SilentlyContinue
if ($k6) {
    Push-Location $repoRoot
    try { & $k6.Source @commonArgs; $exitCode = $LASTEXITCODE } finally { Pop-Location }
}
else {
    $dockerArgs = @('run', '--rm', '-v', "${repoRoot}:/work", '-w', '/work')
    foreach ($name in @('ACCESS_TOKEN','ACCESS_TOKENS','REFRESH_TOKEN','LOAD_USER_EMAIL','LOAD_USER_PASSWORD','CLIENT_ID','TICKET_ID','TICKET_IDS','DEPARTMENT_ID','CATEGORY_ID','CLIENT_IP_POOL_SIZE','HOST_HEADER','BRIGADE_ID','VEHICLE_ID','CANDIDATE_COUNT','P95_MS','P99_MS','ERROR_RATE_MAX')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($value) { $dockerArgs += @('-e', "$name=$value") }
    }
    $containerSummary = "/work/load-tests/results/raw/$runId/k6.json"
    $dockerArgs += @(
        'grafana/k6:0.49.0', 'run', '--quiet', '--summary-export', $containerSummary,
        '--env', "BASE_URL=$BaseUrl", '--env', "K6_RATES=$Rates", '--env', "K6_RUN_ID=$runId",
        '--env', "K6_WARMUP=$Warmup", '--env', "K6_MEASUREMENT=$Measurement", '--env', "K6_STABILIZATION=$Stabilization",
        $scriptPath
    )
    & docker @dockerArgs
    $exitCode = $LASTEXITCODE
}

@{
    run_id=$runId; scenario=$Scenario; git_sha=(git -C $repoRoot rev-parse HEAD); base_url=$BaseUrl
    rates=$Rates; warmup=$Warmup; measurement=$Measurement; stabilization=$Stabilization
    k6_exit_code=$exitCode; write_scenario=$isWriteScenario
} | ConvertTo-Json | Set-Content (Join-Path $rawDir 'config.json')
Write-Host "Raw result: $rawDir"
if ($exitCode -ne 0) { throw "k6 failed with exit code $exitCode" }
