[CmdletBinding()]
param(
    [string]$Namespace = "automatic-system",
    [Security.SecureString]$Authtoken
)

$ErrorActionPreference = "Stop"
$k8sRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$repositoryRoot = Resolve-Path (Join-Path $PSScriptRoot "../..")
$runtimeDirectory = Join-Path $repositoryRoot ".runtime"
$urlFile = Join-Path $runtimeDirectory "ngrok-url.txt"
$urlPattern = 'https://[a-z0-9.-]+\.ngrok(?:-free)?\.(?:app|dev)'

function Invoke-Kubectl {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    & kubectl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "kubectl failed: kubectl $($Arguments -join ' ')"
    }
}

function Set-AuthtokenSecret {
    param([Parameter(Mandatory = $true)][Security.SecureString]$Token)

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
    try {
        $plainToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        $secret = & kubectl -n $Namespace create secret generic ngrok-authtoken `
            --from-literal="authtoken=$plainToken" `
            --dry-run=client `
            -o json
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to render ngrok-authtoken Secret."
        }

        $secret | & kubectl apply -f - | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to apply ngrok-authtoken Secret."
        }
    }
    finally {
        if ($pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        }
        Remove-Variable plainToken -ErrorAction SilentlyContinue
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

function Start-Watcher {
    $watcherPath = Join-Path $PSScriptRoot "watch-ngrok-tunnel.ps1"
    Start-Process powershell.exe `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $watcherPath, "-Namespace", $Namespace) `
        -WindowStyle Hidden | Out-Null
}

$secretExists = & kubectl -n $Namespace get secret ngrok-authtoken --ignore-not-found -o name
if ($LASTEXITCODE -ne 0) {
    throw "Unable to inspect ngrok-authtoken Secret."
}

if ($Authtoken) {
    Set-AuthtokenSecret -Token $Authtoken
}
elseif (-not $secretExists) {
    $Authtoken = Read-Host "Paste the ngrok authtoken" -AsSecureString
    Set-AuthtokenSecret -Token $Authtoken
}

Invoke-Kubectl apply -f (Join-Path $k8sRoot "mesh/ingress/gateway-public.yaml") | Out-Null
Invoke-Kubectl apply -f (Join-Path $k8sRoot "mesh/ingress/routes-public.yaml") | Out-Null
Invoke-Kubectl apply -k (Join-Path $k8sRoot "ngrok")
Invoke-Kubectl -n $Namespace rollout status deployment/ngrok-tunnel --timeout=300s

$publicUrl = $null
for ($attempt = 0; $attempt -lt 30 -and -not $publicUrl; $attempt++) {
    Start-Sleep -Seconds 2
    $publicUrl = Get-PublicUrl
}

if (-not $publicUrl) {
    Invoke-Kubectl -n $Namespace logs deployment/ngrok-tunnel --tail=100
    throw "ngrok became ready, but its public URL was not found in the logs."
}

New-Item -ItemType Directory -Force -Path $runtimeDirectory | Out-Null
[IO.File]::WriteAllText($urlFile, $publicUrl, [Text.UTF8Encoding]::new($false))
Start-Watcher

Write-Host "ngrok URL: $publicUrl"
Write-Host "The URL is stored in $urlFile"
