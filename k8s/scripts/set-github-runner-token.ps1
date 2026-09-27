param(
  [string]$Namespace = "arc-runners",
  [string]$SecretName = "github-runner-secret"
)

$ErrorActionPreference = "Stop"

$secureToken = Read-Host "GitHub fine-grained PAT for FIZZI-77/automatic_system" -AsSecureString
$tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)

try {
  $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer)
  if (-not $token.StartsWith("github_pat_")) {
    throw "Expected a GitHub fine-grained PAT (github_pat_ prefix)"
  }

  $secret = @{
    apiVersion = "v1"
    kind = "Secret"
    metadata = @{
      name = $SecretName
      namespace = $Namespace
    }
    type = "Opaque"
    data = @{
      github_token = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($token))
    }
  }

  $existingSecret = kubectl get secret $SecretName -n $Namespace -o name --ignore-not-found
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to check GitHub runner secret"
  }

  if ($existingSecret) {
    $secret | ConvertTo-Json -Depth 5 -Compress | kubectl replace -f -
  } else {
    $secret | ConvertTo-Json -Depth 5 -Compress | kubectl create -f -
  }

  if ($LASTEXITCODE -ne 0) {
    throw "Failed to save GitHub runner secret"
  }
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer)
  $token = $null
  $secureToken.Dispose()
}
