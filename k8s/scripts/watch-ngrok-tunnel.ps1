[CmdletBinding()]
param(
    [string]$Namespace = "automatic-system",
    [int]$PollSeconds = 5
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

    $config = & kubectl -n $Namespace get configmap auth-service-config -o json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read auth-service-config."
    }

    if ($config.data.FRONTEND_BASE_URL -eq $PublicUrl) {
        return
    }

    $patch = @{ data = @{ FRONTEND_BASE_URL = $PublicUrl } } | ConvertTo-Json -Compress
    $patchFile = Join-Path ([IO.Path]::GetTempPath()) ("ngrok-config-{0}.json" -f [guid]::NewGuid())

    try {
        [IO.File]::WriteAllText($patchFile, $patch, [Text.UTF8Encoding]::new($false))
        Invoke-Kubectl -n $Namespace patch configmap auth-service-config --type merge --patch-file $patchFile | Out-Null
    }
    finally {
        Remove-Item -LiteralPath $patchFile -Force -ErrorAction SilentlyContinue
    }

    Invoke-Kubectl -n $Namespace rollout restart deployment/auth-service | Out-Null
    Invoke-Kubectl -n $Namespace rollout status deployment/auth-service --timeout=180s | Out-Null
    Write-Host "Auth Service now uses $PublicUrl"
}

try {
    New-Item -ItemType Directory -Force -Path $runtimeDirectory | Out-Null
    $lastUrl = $null

    while ($true) {
        $publicUrl = Get-PublicUrl
        if ($publicUrl -and $publicUrl -ne $lastUrl) {
            Set-FrontendBaseUrl -PublicUrl $publicUrl
            [IO.File]::WriteAllText($urlFile, $publicUrl, [Text.UTF8Encoding]::new($false))
            $lastUrl = $publicUrl
            Write-Host "ngrok URL: $publicUrl"
        }

        Start-Sleep -Seconds $PollSeconds
    }
}
finally {
    $watcherMutex.ReleaseMutex()
    $watcherMutex.Dispose()
}

