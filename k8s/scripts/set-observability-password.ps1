[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-zA-Z0-9_.-]+$')]
    [string]$Username,
    [string]$Namespace = "automatic-system"
)

$ErrorActionPreference = "Stop"
$secretFile = Join-Path ([IO.Path]::GetTempPath()) ("observability-auth-" + [guid]::NewGuid())
$securePassword = Read-Host "Password for $Username" -AsSecureString
$passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)

try {
    $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
    if ([string]::IsNullOrEmpty($password)) {
        throw "Password cannot be empty."
    }
    $output = $password | & docker run --rm -i httpd:2.4-alpine htpasswd -niB -C 12 $Username
    $entry = $output | Where-Object { $_ -match '^([^:]+):\$2[aby]\$' } | Select-Object -First 1
    if ($LASTEXITCODE -ne 0 -or -not $entry) {
        throw "Unable to generate the bcrypt password entry. Check Docker Desktop."
    }

    [IO.File]::WriteAllText($secretFile, ($entry.Trim() + "`n"), [Text.UTF8Encoding]::new($false))
    $manifest = & kubectl -n $Namespace create secret generic observability-basic-auth `
        "--from-file=htpasswd=$secretFile" --dry-run=client -o yaml
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to prepare the Kubernetes Secret."
    }

    $manifest | & kubectl apply -f - | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to save the Kubernetes Secret."
    }

    $gateway = & kubectl -n $Namespace get deployment observability-gateway --ignore-not-found -o name
    if ($LASTEXITCODE -ne 0) {
        throw "Secret was saved, but the gateway deployment could not be checked."
    }
    if ($gateway) {
        & kubectl -n $Namespace rollout restart deployment/observability-gateway | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Secret was saved, but the gateway rollout could not be started."
        }
    }
    Write-Host "Observability password updated for $Username."
}
finally {
    $password = $null
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    Remove-Item -LiteralPath $secretFile -Force -ErrorAction SilentlyContinue
}
