param(
    [string]$Rates = '500,1500,3000,5000',
    [string]$BaseUrl = 'http://172.21.0.4',
    [string]$Namespace = 'automatic-system',
    [string]$HPA = 'ticket-service',
    [string]$Duration = '3m'
)

$ErrorActionPreference = 'Stop'
kubectl get hpa $HPA -n $Namespace | Out-Null
if ($LASTEXITCODE -ne 0) { throw "HPA $HPA is not deployed; enable applicationAutoscaling first." }
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$resultDir = Join-Path $root "load-tests\results\hpa\$stamp"
New-Item -ItemType Directory -Force -Path $resultDir | Out-Null
$history = Join-Path $resultDir 'hpa-history.csv'
'timestamp,currentReplicas,desiredReplicas,currentCPU,currentMemory' | Set-Content $history
$job = Start-Job -ScriptBlock {
    param($ns,$name,$path)
    while ($true) {
        $item = kubectl get hpa $name -n $ns -o json | ConvertFrom-Json
        $cpu = ($item.status.currentMetrics | Where-Object { $_.resource.name -eq 'cpu' }).resource.current.averageUtilization
        $memory = ($item.status.currentMetrics | Where-Object { $_.resource.name -eq 'memory' }).resource.current.averageUtilization
        "$(Get-Date -Format o),$($item.status.currentReplicas),$($item.status.desiredReplicas),$cpu,$memory" | Add-Content $path
        Start-Sleep -Seconds 5
    }
} -ArgumentList $Namespace,$HPA,$history
try {
    & (Join-Path $PSScriptRoot 'load-test.ps1') -Scenario mixed -Rates $Rates -BaseUrl $BaseUrl -Duration $Duration
}
finally {
    Stop-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    kubectl get hpa $HPA -n $Namespace -o yaml | Set-Content (Join-Path $resultDir 'hpa-final.yaml')
}
