param(
    [ValidateSet('read','write','mixed')][string]$Scenario = 'mixed',
    [int[]]$Replicas = @(1,2,4,8),
    [string]$Rates = '500,1000,1500,2000,3000,4000,5000,7500,10000',
    [string]$BaseUrl = 'http://172.21.0.4',
    [string]$Namespace = 'automatic-system',
    [string]$Deployment = 'ticket-service',
    [string]$Warmup = '30s',
    [string]$Duration = '3m',
    [string]$Stabilization = '15s'
)

$ErrorActionPreference = 'Stop'
if ($BaseUrl -match '(?i)prod|production') { throw 'Production targets are forbidden.' }
$original = [int](kubectl get deployment $Deployment -n $Namespace -o jsonpath='{.spec.replicas}')
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$resultDir = Join-Path $root "load-tests\results\scaling\$stamp"
New-Item -ItemType Directory -Force -Path $resultDir | Out-Null

try {
    foreach ($count in $Replicas) {
        kubectl scale deployment $Deployment -n $Namespace --replicas=$count
        if ($LASTEXITCODE -ne 0) { throw "Failed to scale $Deployment to $count" }
        kubectl rollout status deployment/$Deployment -n $Namespace --timeout=10m
        if ($LASTEXITCODE -ne 0) { throw "$Deployment did not become Ready with $count replicas" }
        kubectl get deployment,pods -n $Namespace -l app=ticket-service -o wide | Set-Content (Join-Path $resultDir "replicas-$count-before.txt")
        kubectl top pods -n $Namespace | Set-Content (Join-Path $resultDir "replicas-$count-top-before.txt")
        & (Join-Path $PSScriptRoot 'load-test.ps1') -Scenario $Scenario -Rates $Rates -BaseUrl $BaseUrl -Warmup $Warmup -Duration $Duration -Stabilization $Stabilization
        kubectl top pods -n $Namespace | Set-Content (Join-Path $resultDir "replicas-$count-top-after.txt")
        kubectl top nodes | Set-Content (Join-Path $resultDir "replicas-$count-nodes-after.txt")
    }
}
finally {
    kubectl scale deployment $Deployment -n $Namespace --replicas=$original
    kubectl rollout status deployment/$Deployment -n $Namespace --timeout=10m
}
