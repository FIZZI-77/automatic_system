[CmdletBinding()]
param(
    [string]$Namespace = "automatic-system",
    [int]$PollSeconds = 5,
    [switch]$RunOnce
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Resolve-Path (Join-Path $PSScriptRoot "../..")
$runtimeDirectory = Join-Path $repositoryRoot ".runtime"
$urlFile = Join-Path $runtimeDirectory "ngrok-url.txt"
$urlPattern = 'https://[a-z0-9.-]+\.ngrok(?:-free)?\.(?:app|dev)'
$watcherMutex = [Threading.Mutex]::new($false, "Local\AutomaticSystemNgrokWatcher")

if (-not $watcherMutex.WaitOne(0)) {
    Write-Host "The ngrok watcher is already running."
    exit 0
}

function Invoke-Kubectl {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    & kubectl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "kubectl failed: kubectl $($Arguments -join ' ')"
    }
}

function Get-PublicUrl {
    $logs = & kubectl -n $Namespace logs deployment/ngrok-tunnel --tail=200 2>&1
    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    $matches = [regex]::Matches(($logs -join "`n"), $urlPattern)
    if ($matches.Count -eq 0) {
        return $null
    }

    return $matches[$matches.Count - 1].Value
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
    $patchFile = Join-Path ([IO.Path]::GetTempPath()) ("ngrok-config-{0}.json" -f [guid]::NewGuid())

    try {
        [IO.File]::WriteAllText($patchFile, $patch, [Text.UTF8Encoding]::new($false))
        Invoke-Kubectl -n $Namespace patch configmap $configName --type merge --patch-file $patchFile | Out-Null
    }
    finally {
        Remove-Item -LiteralPath $patchFile -Force -ErrorAction SilentlyContinue
    }

    Invoke-Kubectl -n $Namespace rollout restart "deployment/$deploymentName" | Out-Null
    Invoke-Kubectl -n $Namespace rollout status "deployment/$deploymentName" --timeout=180s | Out-Null
    Write-Host "Auth Service now uses $PublicUrl"
}

try {
    New-Item -ItemType Directory -Force -Path $runtimeDirectory | Out-Null
    $lastUrl = $null

    while ($true) {
        $publicUrl = Get-PublicUrl
        if (-not $publicUrl -and $RunOnce) {
            throw "ngrok public URL was not found in deployment logs."
        }

        if ($publicUrl -and $publicUrl -ne $lastUrl) {
            Set-FrontendBaseUrl -PublicUrl $publicUrl
            [IO.File]::WriteAllText($urlFile, $publicUrl, [Text.UTF8Encoding]::new($false))
            $lastUrl = $publicUrl
            Write-Host "ngrok URL: $publicUrl"
        }

        if ($RunOnce) {
            break
        }

        Start-Sleep -Seconds $PollSeconds
    }
}
finally {
    $watcherMutex.ReleaseMutex()
    $watcherMutex.Dispose()
}

