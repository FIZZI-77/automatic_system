[CmdletBinding()]
param(
    [string]$Namespace = "automatic-system",
    [int]$GrafanaPort = 3001,
    [int]$JaegerPort = 16686,
    [int]$PrometheusPort = 9090,
    [int]$KibanaPort = 5601,
    [int]$KialiPort = 20001
)

$ErrorActionPreference = "Stop"

function Start-PortForward {
    param(
        [string]$Service,
        [int]$LocalPort,
        [int]$RemotePort
    )

    $arguments = @(
        "--namespace", $Namespace,
        "port-forward",
        "service/$Service",
        "${LocalPort}:$RemotePort"
    )
    Start-Process `
        -FilePath "kubectl" `
        -ArgumentList $arguments `
        -WindowStyle Hidden | Out-Null
}

Start-PortForward -Service "grafana" -LocalPort $GrafanaPort -RemotePort 3000
Start-PortForward -Service "jaeger" -LocalPort $JaegerPort -RemotePort 16686
Start-PortForward -Service "prometheus" -LocalPort $PrometheusPort -RemotePort 9090
Start-PortForward -Service "kibana" -LocalPort $KibanaPort -RemotePort 5601

$kialiArguments = @(
    "--namespace", "istio-system",
    "port-forward",
    "service/kiali",
    "${KialiPort}:20001"
)
Start-Process `
    -FilePath "kubectl" `
    -ArgumentList $kialiArguments `
    -WindowStyle Hidden | Out-Null

Write-Host "Grafana:    http://localhost:$GrafanaPort"
Write-Host "Jaeger:     http://localhost:$JaegerPort"
Write-Host "Prometheus: http://localhost:$PrometheusPort"
Write-Host "Kibana:     http://localhost:$KibanaPort"
Write-Host "Kiali:      http://localhost:$KialiPort"
