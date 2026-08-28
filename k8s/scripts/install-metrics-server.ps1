[CmdletBinding()]
param(
    [string]$Version = "v0.9.0"
)

$ErrorActionPreference = "Stop"

function Invoke-Kubectl {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    & kubectl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "kubectl failed: $($Arguments -join ' ')"
    }
}

$manifest = "https://github.com/kubernetes-sigs/metrics-server/releases/download/$Version/components.yaml"
Invoke-Kubectl apply `
    --server-side `
    --force-conflicts `
    --field-manager=automatic-system `
    -f $manifest

# Local Docker/kind nodes expose kubelet with a certificate that does not
# contain the container InternalIP. Prefer the InternalIP and skip only the
# kubelet serving-certificate verification; API aggregation remains TLS.
$patch = @{
    spec = @{
        template = @{
            spec = @{
                containers = @(
                    @{
                        name = "metrics-server"
                        args = @(
                            "--cert-dir=/tmp"
                            "--secure-port=10250"
                            "--kubelet-preferred-address-types=InternalIP,Hostname"
                            "--kubelet-use-node-status-port"
                            "--metric-resolution=15s"
                            "--kubelet-insecure-tls"
                        )
                    }
                )
            }
        }
    }
} | ConvertTo-Json -Depth 10 -Compress

$patchFile = New-TemporaryFile
try {
    [System.IO.File]::WriteAllText($patchFile.FullName, $patch)
    Invoke-Kubectl patch deployment metrics-server `
        --namespace=kube-system `
        --type=strategic `
        "--patch-file=$($patchFile.FullName)"
} finally {
    Remove-Item -LiteralPath $patchFile.FullName -Force -ErrorAction SilentlyContinue
}
Invoke-Kubectl rollout status deployment/metrics-server `
    --namespace=kube-system `
    --timeout=300s
Invoke-Kubectl wait --for=condition=Available apiservice/v1beta1.metrics.k8s.io `
    --timeout=180s

Write-Host "Metrics Server $Version is ready."
