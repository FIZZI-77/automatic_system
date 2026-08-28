param(
    [switch]$SkipSeed,
    [switch]$Headed,
    [switch]$LocalFrontend,
    [switch]$ExistingFrontend
)

$ErrorActionPreference = "Stop"
$namespace = "automatic-system"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$portForwardProcesses = @()
$frontendProcess = $null

function Start-PortForward {
    param([string]$Service, [string]$Ports)

    $startParameters = @{
        FilePath = "kubectl"
        ArgumentList = @("port-forward", "--namespace=$namespace", "service/$Service", $Ports)
        WindowStyle = "Hidden"
        PassThru = $true
    }
    $process = Start-Process @startParameters
    $script:portForwardProcesses += $process
}

function Wait-Http {
    param([string]$Url, [int]$TimeoutSeconds = 120)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                return
            }
        }
        catch {
            Start-Sleep -Seconds 1
        }
    } while ((Get-Date) -lt $deadline)
    throw "Endpoint did not become available: $Url"
}

Push-Location $repoRoot
try {
    Start-PortForward "api-gateway" "8081:8081"
    if ($ExistingFrontend) {
        # The caller owns the already-running frontend process.
    }
    elseif ($LocalFrontend) {
        $frontendDirectory = Join-Path $repoRoot "Frontend"
        $vinextCli = Join-Path $frontendDirectory "node_modules/vinext/dist/cli.js"

        Push-Location $frontendDirectory
        try {
            & npm.cmd run build
            if ($LASTEXITCODE -ne 0) {
                throw "Frontend production build failed"
            }
        }
        finally {
            Pop-Location
        }

        $frontendProcess = Start-Process `
            -FilePath "node.exe" `
            -ArgumentList @($vinextCli, "start", "--hostname", "0.0.0.0") `
            -WorkingDirectory $frontendDirectory `
            -WindowStyle Hidden `
            -PassThru

        Start-Sleep -Seconds 1
        $frontendProcess.Refresh()
        if ($frontendProcess.HasExited) {
            throw "Frontend process exited during startup. Check whether port 3000 is already in use."
        }
    }
    else {
        Start-PortForward "frontend" "3000:3000"
    }
    Wait-Http "http://127.0.0.1:8081/health"
    Wait-Http "http://127.0.0.1:3000"

    if (-not $SkipSeed) {
        $seedScript = Join-Path $repoRoot "scripts/seed-demo-data.ps1"
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $seedScript `
            -BaseUrl "http://127.0.0.1:8081" `
            -Target Kubernetes
        if ($LASTEXITCODE -ne 0) {
            throw "Kubernetes E2E seed failed"
        }
    }

    Push-Location (Join-Path $repoRoot "Frontend")
    try {
        $env:E2E_BASE_URL = "http://127.0.0.1:3000"
        $env:E2E_API_URL = "http://127.0.0.1:8081"
        $env:E2E_SKIP_SEED = "1"
        if ($Headed) {
            & npm.cmd run e2e:headed
        }
        else {
            & npm.cmd run e2e
        }
        if ($LASTEXITCODE -ne 0) {
            throw "Playwright E2E failed"
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    if ($frontendProcess -and -not $frontendProcess.HasExited) {
        Stop-Process -Id $frontendProcess.Id -Force
    }
    foreach ($process in $portForwardProcesses) {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
        }
    }
    Pop-Location
}
