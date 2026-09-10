param(
  [string]$Namespace = "automatic-system",
  [string]$GatewayNamespace = "istio-system",
  [string]$CertificateSecret = "automatic-system-local-tls",
  [switch]$RotateCertificate,
  [bool]$TrustCertificate = $true
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("automatic-system-ingress-" + [guid]::NewGuid())

try {
  $secretExists = $null -ne (kubectl get secret $CertificateSecret `
    --namespace $GatewayNamespace `
    --ignore-not-found `
    --output name)

  if ($RotateCertificate -or -not $secretExists) {
    New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null

    $certificatePath = Join-Path $temporaryDirectory "tls.crt"
    $privateKeyPath = Join-Path $temporaryDirectory "tls.key"
    $certificateMount = $temporaryDirectory.Replace('\', '/')
    docker run --rm `
      --volume "${certificateMount}:/certs" `
      alpine/openssl:latest `
      req -x509 -nodes -newkey rsa:2048 -sha256 -days 730 `
      -keyout /certs/tls.key `
      -out /certs/tls.crt `
      -subj /CN=city.localhost `
      -addext subjectAltName=DNS:city.localhost,DNS:api.city.localhost `
      -addext basicConstraints=critical,CA:FALSE `
      -addext keyUsage=critical,digitalSignature `
      -addext extendedKeyUsage=serverAuth
    if ($LASTEXITCODE -ne 0) {
      throw "Failed to generate the local ingress certificate"
    }

    kubectl create secret tls $CertificateSecret `
      --namespace $GatewayNamespace `
      --cert $certificatePath `
      --key $privateKeyPath `
      --dry-run=client `
      --output yaml | kubectl apply --filename -
    if ($LASTEXITCODE -ne 0) {
      throw "Failed to create the Istio ingress TLS secret"
    }
  }

  if ($TrustCertificate) {
    if (-not (Test-Path -LiteralPath $temporaryDirectory)) {
      New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
    }

    $trustedCertificatePath = Join-Path $temporaryDirectory "trusted-ingress.crt"
    $encodedCertificate = kubectl get secret $CertificateSecret `
      --namespace $GatewayNamespace `
      --output jsonpath="{.data.tls\.crt}"
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($encodedCertificate)) {
      throw "Failed to read the Istio ingress public certificate"
    }

    $certificateBytes = [Convert]::FromBase64String($encodedCertificate)
    [System.IO.File]::WriteAllBytes($trustedCertificatePath, $certificateBytes)
    $trustedCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
      $trustedCertificatePath
    )
    $rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
      [System.Security.Cryptography.X509Certificates.StoreName]::Root,
      [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )

    try {
      $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
      $existingCertificate = $rootStore.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
        $trustedCertificate.Thumbprint,
        $false
      )
      if ($existingCertificate.Count -eq 0) {
        $rootStore.Add($trustedCertificate)
        Write-Host "Trusted the ingress certificate in CurrentUser\\Root: $($trustedCertificate.Thumbprint)"
      } else {
        Write-Host "The ingress certificate is already trusted: $($trustedCertificate.Thumbprint)"
      }
    } finally {
      $rootStore.Close()
      $trustedCertificate.Dispose()
    }
  }

  kubectl apply --kustomize (Join-Path $repoRoot "k8s\mesh\ingress")
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to apply Istio ingress routes"
  }

  kubectl rollout status deployment/istio-ingressgateway `
    --namespace $GatewayNamespace `
    --timeout 180s
  if ($LASTEXITCODE -ne 0) {
    throw "Istio ingress gateway did not become ready"
  }

  Write-Host "Istio ingress is ready: https://city.localhost"
  Write-Host "API Gateway is ready: https://api.city.localhost"
  if ($TrustCertificate) {
    Write-Host "The ingress certificate is trusted for the current Windows user."
  } else {
    Write-Warning "The generated certificate is self-signed and is not trusted locally."
  }
} finally {
  if (Test-Path -LiteralPath $temporaryDirectory) {
    Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
  }
}
