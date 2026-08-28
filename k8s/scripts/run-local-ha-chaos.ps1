param(
    [switch]$Execute,
    [int]$RecoveryTimeoutSeconds = 240,
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"
if (-not $Execute) {
    throw "Chaos testing is destructive. Re-run with -Execute after verifying the target context."
}

$namespace = "automatic-system"
$expectedContext = "docker-desktop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $ReportPath) {
    $ReportPath = Join-Path $repoRoot "test-results/local-ha-chaos.json"
}
$results = [System.Collections.Generic.List[object]]::new()
$portForward = $null

function Invoke-Kubectl {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    & kubectl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "kubectl failed: $($Arguments -join ' ')"
    }
}

function Wait-PodReady {
    param([string]$Pod)

    Invoke-Kubectl wait --namespace=$namespace --for=condition=Ready "pod/$Pod" "--timeout=${RecoveryTimeoutSeconds}s"
}

function Wait-StatefulSetReady {
    param([string]$StatefulSet)

    Invoke-Kubectl rollout status --namespace=$namespace "statefulset/$StatefulSet" "--timeout=${RecoveryTimeoutSeconds}s"
}

function Wait-DeploymentReady {
    param([string]$Deployment)

    Invoke-Kubectl rollout status --namespace=$namespace "deployment/$Deployment" "--timeout=${RecoveryTimeoutSeconds}s"
}

function Wait-Gateway {
    $deadline = (Get-Date).AddSeconds($RecoveryTimeoutSeconds)
    do {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8081/health" -TimeoutSec 3
            if ($response.StatusCode -eq 200) {
                return
            }
        }
        catch {
            Start-Sleep -Seconds 1
        }
    } while ((Get-Date) -lt $deadline)
    throw "API Gateway did not recover"
}

function Get-PrimaryPod {
    param([string]$Selector)

    $pod = kubectl get pods --namespace=$namespace --selector=$Selector --output=jsonpath='{.items[0].metadata.name}'
    if ($LASTEXITCODE -ne 0 -or -not $pod) {
        throw "Primary pod not found for selector: $Selector"
    }
    return $pod
}

function Start-Workload {
    $loginBody = @{
        email = "demo.admin@city.local"
        password = "CityDemo123!"
        client_id = "chaos-workload"
    } | ConvertTo-Json

    $deadline = (Get-Date).AddSeconds($RecoveryTimeoutSeconds)
    do {
        try {
            $login = Invoke-RestMethod `
                -Method Post `
                -Uri "http://127.0.0.1:8081/auth/login" `
                -ContentType "application/json" `
                -Body $loginBody `
                -TimeoutSec 5
            $token = $login.access_token
            if ($token) {
                break
            }
        }
        catch {
            Start-Sleep -Seconds 1
        }
    } while ((Get-Date) -lt $deadline)

    if (-not $token) {
        throw "Unable to obtain workload token before recovery timeout"
    }

    return Start-Job -ArgumentList $token -ScriptBlock {
        param($AccessToken)

        $success = 0
        $failures = 0
        $headers = @{ Authorization = "Bearer $AccessToken" }
        $body = @{ limit = 20; offset = 0 } | ConvertTo-Json
        $deadline = (Get-Date).AddSeconds(45)
        while ((Get-Date) -lt $deadline) {
            try {
                $response = Invoke-WebRequest `
                    -UseBasicParsing `
                    -Method Post `
                    -Uri "http://127.0.0.1:8081/tickets/list" `
                    -Headers $headers `
                    -ContentType "application/json" `
                    -Body $body `
                    -TimeoutSec 5
                if ($response.StatusCode -eq 200) {
                    $success++
                }
                else {
                    $failures++
                }
            }
            catch {
                $failures++
            }
            Start-Sleep -Milliseconds 500
        }
        [pscustomobject]@{ Success = $success; Failures = $failures }
    }
}

function Invoke-ChaosScenario {
    param(
        [string]$Name,
        [scriptblock]$Fault,
        [scriptblock]$Recovery
    )

    Write-Host "CHAOS: $Name"
    $startedAt = Get-Date
    $workload = Start-Workload
    try {
        & $Fault
        & $Recovery
        Wait-Gateway
        Wait-Job $workload -Timeout 60 | Out-Null
        $workloadResult = Receive-Job $workload
        if (-not $workloadResult -or $workloadResult.Success -eq 0) {
            throw "Workload had no successful requests"
        }
        $results.Add([pscustomobject]@{
            Name = $Name
            Status = "passed"
            DurationSeconds = [math]::Round(((Get-Date) - $startedAt).TotalSeconds, 2)
            SuccessfulRequests = $workloadResult.Success
            FailedRequests = $workloadResult.Failures
        })
    }
    catch {
        $results.Add([pscustomobject]@{
            Name = $Name
            Status = "failed"
            DurationSeconds = [math]::Round(((Get-Date) - $startedAt).TotalSeconds, 2)
            Error = $_.Exception.Message
        })
        throw
    }
    finally {
        Stop-Job $workload -ErrorAction SilentlyContinue
        Remove-Job $workload -Force -ErrorAction SilentlyContinue
    }
}

$context = kubectl config current-context
if ($context -ne $expectedContext) {
    throw "Refusing chaos test on context '$context'; expected '$expectedContext'."
}

$reportDirectory = Split-Path -Parent $ReportPath
New-Item -ItemType Directory -Force -Path $reportDirectory | Out-Null

try {
    $portForward = Start-Process kubectl `
        -ArgumentList @("port-forward", "--namespace=$namespace", "service/api-gateway", "8081:8081") `
        -WindowStyle Hidden `
        -PassThru
    Wait-Gateway

    Invoke-ChaosScenario "platform-read-replica" {
        $replica = Get-PrimaryPod "cluster-name=postgres-platform,role=replica"
        Invoke-Kubectl delete pod --namespace=$namespace $replica
    } {
        Wait-StatefulSetReady "postgres-platform"
        Wait-DeploymentReady "pgbouncer-platform-primary"
        Wait-DeploymentReady "pgbouncer-platform-replicas"
    }

    Invoke-ChaosScenario "platform-primary-failover" {
        $script:oldPlatformPrimary = Get-PrimaryPod "cluster-name=postgres-platform,role=primary"
        Invoke-Kubectl delete pod --namespace=$namespace $script:oldPlatformPrimary
    } {
        $deadline = (Get-Date).AddSeconds($RecoveryTimeoutSeconds)
        do {
            $newPrimary = Get-PrimaryPod "cluster-name=postgres-platform,role=primary"
            if ($newPrimary -ne $script:oldPlatformPrimary) {
                break
            }
            Start-Sleep -Seconds 2
        } while ((Get-Date) -lt $deadline)
        if ($newPrimary -eq $script:oldPlatformPrimary) {
            throw "Platform primary did not fail over"
        }
        Wait-StatefulSetReady "postgres-platform"
        Wait-DeploymentReady "pgbouncer-platform-primary"
        Wait-DeploymentReady "pgbouncer-platform-replicas"
    }

    Invoke-ChaosScenario "ticket-citus-coordinator-primary" {
        $script:oldTicketPrimary = Get-PrimaryPod "cluster-name=postgres-ticket-citus,citus-group=0,role=primary"
        Invoke-Kubectl delete pod --namespace=$namespace $script:oldTicketPrimary
    } {
        Wait-StatefulSetReady "coordinator-ticket-citus"
        Wait-DeploymentReady "pgbouncer-ticket-replicas"
    }

    Invoke-ChaosScenario "pgbouncer-ticket-primary" {
        $pod = kubectl get pods --namespace=$namespace --selector=app.kubernetes.io/name=pgbouncer,app.kubernetes.io/instance=ticket-primary --output=jsonpath='{.items[0].metadata.name}'
        Invoke-Kubectl delete pod --namespace=$namespace $pod
    } {
        Wait-DeploymentReady "pgbouncer-ticket-primary"
    }

    Invoke-ChaosScenario "kafka-single-broker" {
        Invoke-Kubectl delete pod --namespace=$namespace kafka-1-0
    } {
        Wait-StatefulSetReady "kafka-1"
    }

    Invoke-ChaosScenario "minio-restart" {
        Invoke-Kubectl delete pod --namespace=$namespace minio-0
    } {
        Wait-StatefulSetReady "minio"
    }

    Invoke-ChaosScenario "redis-gateway-restart" {
        Invoke-Kubectl delete pod --namespace=$namespace redis-gateway-0
    } {
        Wait-StatefulSetReady "redis-gateway"
    }

    Invoke-ChaosScenario "ticket-service-restart" {
        $pod = kubectl get pods --namespace=$namespace --selector=app=ticket-service --output=jsonpath='{.items[0].metadata.name}'
        Invoke-Kubectl delete pod --namespace=$namespace $pod
    } {
        Wait-DeploymentReady "ticket-service"
    }
}
finally {
    if ($portForward -and -not $portForward.HasExited) {
        Stop-Process -Id $portForward.Id -Force
    }
    $results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding utf8
}

if ($results.Where({ $_.Status -eq "failed" }).Count -gt 0) {
    throw "One or more chaos scenarios failed. See $ReportPath"
}
Write-Host "Chaos test passed. Report: $ReportPath"
