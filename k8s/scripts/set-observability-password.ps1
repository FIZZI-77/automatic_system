[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-zA-Z0-9_.-]+$')]
    [string]$Username,
    [string]$Namespace = "istio-system"
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

    $passwordBytes = [Text.Encoding]::UTF8.GetBytes($password)
    $passwordHash = [Security.Cryptography.SHA1]::HashData($passwordBytes)
    $entry = "$Username`:{SHA}$([Convert]::ToBase64String($passwordHash))"
    [IO.File]::WriteAllText($secretFile, ($entry + "`n"), [Text.UTF8Encoding]::new($false))

    $manifest = & kubectl -n $Namespace create secret generic observability-basic-auth `
        "--from-file=users=$secretFile" --dry-run=client -o yaml
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to prepare the Kubernetes Secret."
    }

    $manifest | & kubectl apply -f - | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to save the Kubernetes Secret."
    }

    $gateway = & kubectl -n $Namespace get deployment istio-ingressgateway --ignore-not-found -o name
    if ($LASTEXITCODE -ne 0) {
        throw "Secret was saved, but the ingress gateway deployment could not be checked."
    }
    if ($gateway) {
        & kubectl -n $Namespace rollout restart deployment/istio-ingressgateway | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Secret was saved, but the ingress gateway rollout could not be started."
        }
    }
    Write-Host "Observability password updated for $Username."
}
finally {
    $password = $null
    if ($passwordBytes) { [Array]::Clear($passwordBytes, 0, $passwordBytes.Length) }
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    Remove-Item -LiteralPath $secretFile -Force -ErrorAction SilentlyContinue
}
