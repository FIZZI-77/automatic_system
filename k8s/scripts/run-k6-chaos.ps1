param(
    [switch]$ExecuteChaos,
    [switch]$Quick,
    [switch]$IncludeDatabaseFailover,
    [int]$Rate = 20,
    [int]$PreAllocatedVUs = 30,
    [int]$MaxVUs = 150,
    [int]$RecoveryTimeoutSeconds = 240,
    [string]$ReportDirectory = ""
)

$ErrorActionPreference = "Stop"
$namespace = "automatic-system"
$jobName = "k6-kubernetes-chaos"
$expectedContext = "docker-desktop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scriptPath = Join-Path $repoRoot "load-tests/kubernetes-chaos.js"
$jobManifest = Join-Path $repoRoot "k8s/load-testing/k6-job.yaml"

if (-not $ReportDirectory) {
    $ReportDirectory = Join-Path $repoRoot "test-results/k6-kubernetes-chaos"
}

function Invoke-Kubectl {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    & kubectl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "kubectl failed: $($Arguments -join ' ')"
    }
}

function Wait-Workload {
    param([ValidateSet("deployment", "statefulset")][string]$Kind, [string]$Name)

    Invoke-Kubectl rollout status "--namespace=$namespace" "$Kind/$Name" "--timeout=${RecoveryTimeoutSeconds}s"
}

function Get-PodName {
    param([string]$Selector)

    $pod = kubectl get pod "--namespace=$namespace" "--selector=$Selector" --output=jsonpath='{.items[0].metadata.name}'
    if ($LASTEXITCODE -ne 0 -or -not $pod) {
        throw "Pod not found for selector: $Selector"
    }
    return $pod
}

function Invoke-ChaosEvent {
    param([string]$Name, [scriptblock]$Fault, [scriptblock]$Recovery)

    $startedAt = Get-Date
    Write-Host "CHAOS START: $Name"
    try {
        & $Fault
        & $Recovery
        $script:chaosEvents.Add([pscustomobject]@{
            Name = $Name
            Status = "recovered"
            StartedAt = $startedAt.ToString("o")
            RecoverySeconds = [math]::Round(((Get-Date) - $startedAt).TotalSeconds, 2)
        })
        Write-Host "CHAOS RECOVERED: $Name"
    }
    catch {
        $script:chaosEvents.Add([pscustomobject]@{
            Name = $Name
            Status = "failed"
            StartedAt = $startedAt.ToString("o")
            RecoverySeconds = [math]::Round(((Get-Date) - $startedAt).TotalSeconds, 2)
            Error = $_.Exception.Message
        })
        throw
    }
}

function Wait-K6Job {
    param([int]$TimeoutSeconds)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $job = kubectl get job $jobName "--namespace=$namespace" --output=json | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to read k6 Job status."
        }
        if ($job.status.succeeded -ge 1) {
            return 0
        }
        if ($job.status.failed -ge 1) {
            return 1
        }
        Start-Sleep -Seconds 10
    } while ((Get-Date) -lt $deadline)
    throw "k6 Job did not finish within $TimeoutSeconds seconds."
}

function Wait-K6PodRunning {
    $deadline = (Get-Date).AddSeconds($RecoveryTimeoutSeconds)
    do {
        $pod = kubectl get pod "--namespace=$namespace" "--selector=job-name=$jobName" `
            --output=jsonpath='{.items[0].status.phase}' 2>$null
        if ($LASTEXITCODE -eq 0 -and $pod -eq "Running") {
            return
        }
        if ($pod -eq "Failed" -or $pod -eq "Succeeded") {
            throw "k6 Pod finished before reaching the Running phase."
        }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    throw "k6 Pod did not enter the Running phase."
}

$context = kubectl config current-context
if ($context -ne $expectedContext) {
    throw "Refusing load/chaos test on context '$context'; expected '$expectedContext'."
}
if ($Rate -lt 1 -or $PreAllocatedVUs -lt 1 -or $MaxVUs -lt $PreAllocatedVUs) {
    throw "Invalid k6 capacity parameters."
}

$timing = if ($Quick) {
    @{
        WarmupDuration = "15s"
        BaselineStart = "15s"
        BaselineDuration = "30s"
        ChaosStart = "45s"
        ChaosDuration = "2m"
        RecoveryStart = "2m45s"
        RecoveryDuration = "30s"
        ChaosDelaySeconds = 55
    }
} else {
    @{
        WarmupDuration = "1m"
        BaselineStart = "1m"
        BaselineDuration = "2m"
        ChaosStart = "3m"
        ChaosDuration = "4m"
        RecoveryStart = "7m"
        RecoveryDuration = "2m"
        ChaosDelaySeconds = 190
    }
}

New-Item -ItemType Directory -Force -Path $ReportDirectory | Out-Null
$chaosEvents = [System.Collections.Generic.List[object]]::new()

Invoke-Kubectl create configmap k6-kubernetes-chaos-script "--namespace=$namespace" `
    "--from-file=kubernetes-chaos.js=$scriptPath" --dry-run=client --output=yaml |
    kubectl apply --filename -
if ($LASTEXITCODE -ne 0) {
    throw "Failed to apply k6 script ConfigMap."
}

$configArguments = @(
    "create", "configmap", "k6-kubernetes-chaos-config", "--namespace=$namespace",
    "--from-literal=BASE_URL=http://api-gateway:8081",
    "--from-literal=K6_RATE=$Rate",
    "--from-literal=K6_PREALLOCATED_VUS=$PreAllocatedVUs",
    "--from-literal=K6_MAX_VUS=$MaxVUs",
    "--from-literal=K6_WARMUP_DURATION=$($timing.WarmupDuration)",
    "--from-literal=K6_BASELINE_START=$($timing.BaselineStart)",
    "--from-literal=K6_BASELINE_DURATION=$($timing.BaselineDuration)",
    "--from-literal=K6_CHAOS_START=$($timing.ChaosStart)",
    "--from-literal=K6_CHAOS_DURATION=$($timing.ChaosDuration)",
    "--from-literal=K6_RECOVERY_START=$($timing.RecoveryStart)",
    "--from-literal=K6_RECOVERY_DURATION=$($timing.RecoveryDuration)",
    "--dry-run=client", "--output=yaml"
)
& kubectl @configArguments | kubectl apply --filename -
if ($LASTEXITCODE -ne 0) {
    throw "Failed to apply k6 configuration ConfigMap."
}

kubectl delete job $jobName "--namespace=$namespace" --ignore-not-found --wait=true | Out-Null
kubectl delete pod "--namespace=$namespace" "--selector=job-name=$jobName" `
    --ignore-not-found --wait=true | Out-Null
Invoke-Kubectl apply --filename $jobManifest

try {
    Wait-K6PodRunning

    if ($ExecuteChaos) {
        $remainingDelay = $timing.ChaosDelaySeconds
        while ($remainingDelay -gt 0) {
            $sleepSeconds = [math]::Min(30, $remainingDelay)
            Start-Sleep -Seconds $sleepSeconds
            $remainingDelay -= $sleepSeconds
        }

        Invoke-ChaosEvent "kafka-single-broker" {
            Invoke-Kubectl delete pod kafka-1-0 "--namespace=$namespace"
        } {
            Wait-Workload statefulset kafka-1
        }

        Invoke-ChaosEvent "ticket-service-pod" {
            $pod = Get-PodName "app=ticket-service"
            Invoke-Kubectl delete pod $pod "--namespace=$namespace"
        } {
            Wait-Workload deployment ticket-service
        }

        Invoke-ChaosEvent "redis-gateway" {
            Invoke-Kubectl delete pod redis-gateway-0 "--namespace=$namespace"
        } {
            Wait-Workload statefulset redis-gateway
        }

        Invoke-ChaosEvent "pgbouncer-ticket-primary" {
            $pod = Get-PodName "app.kubernetes.io/name=pgbouncer,app.kubernetes.io/instance=ticket-primary"
            Invoke-Kubectl delete pod $pod "--namespace=$namespace"
        } {
            Wait-Workload deployment pgbouncer-ticket-primary
        }

        Invoke-ChaosEvent "platform-read-replica" {
            $pod = Get-PodName "cluster-name=postgres-platform,role=replica"
            Invoke-Kubectl delete pod $pod "--namespace=$namespace"
        } {
            Wait-Workload statefulset postgres-platform
        }

        if ($IncludeDatabaseFailover) {
            Invoke-ChaosEvent "platform-primary-failover" {
                $script:oldPrimary = Get-PodName "cluster-name=postgres-platform,role=primary"
                Invoke-Kubectl delete pod $script:oldPrimary "--namespace=$namespace"
            } {
                $deadline = (Get-Date).AddSeconds($RecoveryTimeoutSeconds)
                do {
                    $newPrimary = Get-PodName "cluster-name=postgres-platform,role=primary"
                    if ($newPrimary -ne $script:oldPrimary) {
                        break
                    }
                    Start-Sleep -Seconds 2
                } while ((Get-Date) -lt $deadline)
                if ($newPrimary -eq $script:oldPrimary) {
                    throw "Patroni primary did not fail over."
                }
                Wait-Workload statefulset postgres-platform
                Wait-Workload deployment pgbouncer-platform-primary
            }
        }
    }

    $waitSeconds = if ($Quick) { 300 } else { 720 }
    $jobExitCode = Wait-K6Job -TimeoutSeconds $waitSeconds

    $pod = Get-PodName "job-name=$jobName"
    kubectl logs "--namespace=$namespace" $pod | Tee-Object -FilePath (Join-Path $ReportDirectory "k6.log")
    $summaryPath = Join-Path $ReportDirectory "summary.json"
    $relativeSummaryPath = [System.IO.Path]::GetRelativePath($repoRoot, $summaryPath)
    Push-Location $repoRoot
    try {
        kubectl cp "${namespace}/${pod}:/results/summary.json" $relativeSummaryPath
    }
    finally {
        Pop-Location
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Unable to copy k6 summary.json; the full console summary is preserved in k6.log."
    }

    $chaosEvents | ConvertTo-Json -Depth 5 | Set-Content `
        -LiteralPath (Join-Path $ReportDirectory "chaos-events.json") `
        -Encoding utf8

    if ($jobExitCode -ne 0) {
        throw "k6 thresholds failed. See $ReportDirectory."
    }
    if ($chaosEvents.Where({ $_.Status -eq "failed" }).Count -gt 0) {
        throw "One or more chaos events failed to recover. See $ReportDirectory."
    }
}
finally {
    Write-Host "k6/chaos artifacts: $ReportDirectory"
}
