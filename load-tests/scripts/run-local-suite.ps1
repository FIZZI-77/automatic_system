param(
    [string]$Namespace = 'automatic-system',
    [string]$Warmup = '5s',
    [string]$Measurement = '20s',
    [string]$Stabilization = '5s',
    [string]$Email = 'demo.admin@city.local',
    [string]$Password = 'CityDemo123!',
    [string]$ScenarioFilter = '',
    [string]$ParallelRates = '3,5,10',
    [switch]$AllowWrites
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$runtimeDir = Join-Path $repoRoot 'load-tests\.runtime'
$suiteStamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$suiteDir = Join-Path $repoRoot "load-tests\results\suite\$suiteStamp"
$temporaryImage = "automatic-system/api-gateway:loadtest-bypass-$suiteStamp"
$gatewayPort = Get-Random -Minimum 18081 -Maximum 19000
$originalImage = kubectl get deployment api-gateway -n $Namespace -o jsonpath='{.spec.template.spec.containers[0].image}'
if ($LASTEXITCODE -ne 0 -or -not $originalImage) { throw 'Unable to read current Gateway image' }

New-Item -ItemType Directory -Force -Path $runtimeDir, $suiteDir | Out-Null
$portForward = $null
$suiteResults = @()

try {
    Push-Location (Join-Path $repoRoot 'API_Gateway')
    try {
        $savedGOOS = $env:GOOS; $savedGOARCH = $env:GOARCH; $savedCGO = $env:CGO_ENABLED; $savedGOCACHE = $env:GOCACHE
        $env:GOOS = 'linux'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'; $env:GOCACHE = Join-Path $repoRoot '.gocache'
        go build -o (Join-Path $runtimeDir 'api-gateway') ./src/cmd/server
        if ($LASTEXITCODE -ne 0) { throw 'Gateway cross-build failed' }
    }
    finally {
        $env:GOOS = $savedGOOS; $env:GOARCH = $savedGOARCH; $env:CGO_ENABLED = $savedCGO; $env:GOCACHE = $savedGOCACHE
        Pop-Location
    }

    Push-Location $repoRoot
    try {
        docker build -t $temporaryImage -f load-tests/docker/Dockerfile.gateway-bypass .
        if ($LASTEXITCODE -ne 0) { throw 'Temporary Gateway image build failed' }
    }
    finally { Pop-Location }

    kubectl set image deployment/api-gateway -n $Namespace "api-gateway=$temporaryImage"
    if ($LASTEXITCODE -ne 0) { throw 'Unable to set temporary Gateway image' }
    kubectl set env deployment/api-gateway -n $Namespace RATE_LIMIT_BYPASS_LOAD_TESTS=true
    if ($LASTEXITCODE -ne 0) { throw 'Unable to enable load-test bypass' }
    kubectl rollout status deployment/api-gateway -n $Namespace --timeout=180s
    if ($LASTEXITCODE -ne 0) { throw 'Temporary Gateway rollout failed' }

    $portForward = Start-Process kubectl -ArgumentList @('port-forward','--address','0.0.0.0','-n',$Namespace,'service/api-gateway',"${gatewayPort}:8081") -WindowStyle Hidden -PassThru
    $ready = $false
    foreach ($attempt in 1..30) {
        try {
            if ($portForward.HasExited) { throw 'Gateway port-forward process exited' }
            $response = Invoke-WebRequest -Uri "http://localhost:$gatewayPort/readyz" -TimeoutSec 2 -UseBasicParsing
            if ($response.StatusCode -eq 200) { $ready = $true; break }
        }
        catch {}
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'Gateway port-forward did not become ready' }

    Push-Location $repoRoot
    try {
        docker run --rm -v "${repoRoot}:/work" -w /work grafana/k6:0.49.0 run --quiet --env "BASE_URL=http://host.docker.internal:$gatewayPort" load-tests/k6/smoke/ready.js
        if ($LASTEXITCODE -ne 0) { throw 'Gateway is not reachable from the k6 Docker container' }
    }
    finally { Pop-Location }

    $loginBody = @{email=$Email;password=$Password;client_id='k6-suite'} | ConvertTo-Json
    $login = Invoke-RestMethod -Uri "http://localhost:$gatewayPort/auth/login" -Method Post -ContentType 'application/json' -Headers @{'X-Load-Test-Run-ID'=$suiteStamp} -Body $loginBody
    $env:ACCESS_TOKEN = $login.access_token; $env:REFRESH_TOKEN = $login.refresh_token
    $env:LOAD_USER_EMAIL = $Email; $env:LOAD_USER_PASSWORD = $Password
    $env:TICKET_ID = '60000000-0000-4000-8000-000000000001'
    $env:BRIGADE_ID = '30000000-0000-4000-8000-000000000001'
    $env:VEHICLE_ID = 'e2000000-0000-4000-8000-000000000001'

    $scenarioDefinitions = @(
        @{Name='gateway';Rates='25,50,100';Writes=$false},
        @{Name='gateway-authenticated-read';Rates='10,25,50';Writes=$false},
        @{Name='auth-login';Rates='2,5,10';Writes=$false},
        @{Name='auth-refresh';Rates='1';Writes=$false},
        @{Name='ticket-read';Rates='10,25,50';Writes=$false},
        @{Name='location';Rates='10,25,50';Writes=$true},
        @{Name='dispatch-preview';Rates='2,5,10';Writes=$false},
        @{Name='analytics';Rates='5,10,20';Writes=$false},
        @{Name='services-parallel';Rates=$ParallelRates;Writes=$false},
        @{Name='full';Rates='5,10,20';Writes=$true}
    )
    $selectedScenarios = @($ScenarioFilter.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() })
    if ($selectedScenarios.Count -eq 0) {
        $scenarios = @($scenarioDefinitions)
    } else {
        $scenarios = @($scenarioDefinitions | Where-Object { $selectedScenarios -contains $_.Name })
    }
    if ($scenarios.Count -ne $(if ($selectedScenarios.Count -eq 0) { $scenarioDefinitions.Count } else { $selectedScenarios.Count })) {
        throw "Unknown or duplicate scenario in -ScenarioFilter: $ScenarioFilter"
    }

    foreach ($scenario in $scenarios) {
        if ($scenario.Writes -and -not $AllowWrites) { continue }
        $startedAt = (Get-Date).ToUniversalTime(); $scenarioExit = 0
        try {
            & (Join-Path $PSScriptRoot 'run.ps1') -Scenario $scenario.Name -Rates $scenario.Rates -BaseUrl "http://host.docker.internal:$gatewayPort" -Warmup $Warmup -Measurement $Measurement -Stabilization $Stabilization -RunPrefix $suiteStamp -AllowWrites:$AllowWrites
        }
        catch { $scenarioExit = 1; Write-Warning $_ }
        $suiteResults += [pscustomobject]@{scenario=$scenario.Name;rates=$scenario.Rates;writes=$scenario.Writes;exit_code=$scenarioExit;started_at=$startedAt;ended_at=(Get-Date).ToUniversalTime()}
    }

    $suiteResults | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $suiteDir 'suite.json')
    kubectl top pods -n $Namespace --containers | Set-Content (Join-Path $suiteDir 'kubectl-top.txt')
    kubectl get deployments,statefulsets -n $Namespace -o json | Set-Content (Join-Path $suiteDir 'runtime.json')
    Write-Host "Suite result: $suiteDir"
}
finally {
    if ($portForward -and -not $portForward.HasExited) { Stop-Process -Id $portForward.Id -Force }
    kubectl set image deployment/api-gateway -n $Namespace "api-gateway=$originalImage" | Out-Host
    kubectl set env deployment/api-gateway -n $Namespace RATE_LIMIT_BYPASS_LOAD_TESTS- | Out-Host
    kubectl rollout status deployment/api-gateway -n $Namespace --timeout=180s | Out-Host
    Remove-Item Env:ACCESS_TOKEN,Env:REFRESH_TOKEN -ErrorAction SilentlyContinue
}
