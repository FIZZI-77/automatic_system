[CmdletBinding()]
param(
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"

if (-not $OutputDirectory) {
    $OutputDirectory = [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot "..\base\observability\dashboards")
    )
}

function New-PrometheusTarget {
    param([string]$Expression, [string]$Legend = "")

    return @{
        datasource   = @{ type = "prometheus"; uid = "prometheus" }
        editorMode   = "code"
        expr         = $Expression
        legendFormat = $Legend
        range        = $true
        refId        = [string][char](65 + $script:TargetIndex++)
    }
}

function New-Panel {
    param(
        [int]$ID,
        [string]$Title,
        [string]$Type,
        [int]$X,
        [int]$Y,
        [int]$Width,
        [int]$Height,
        [array]$Targets,
        [string]$Unit = "short"
    )

    return @{
        id         = $ID
        title      = $Title
        type       = $Type
        datasource = @{ type = "prometheus"; uid = "prometheus" }
        gridPos    = @{ x = $X; y = $Y; w = $Width; h = $Height }
        fieldConfig = @{
            defaults = @{
                unit       = $Unit
                noValue    = "0"
                color      = @{ mode = "palette-classic" }
                thresholds = @{ mode = "absolute"; steps = @(@{ color = "green"; value = $null }, @{ color = "red"; value = 1 }) }
            }
            overrides = @()
        }
        options = if ($Type -eq "stat") {
            @{ colorMode = "value"; graphMode = "area"; justifyMode = "auto"; reduceOptions = @{ calcs = @("lastNotNull"); fields = ""; values = $false } }
        } else {
            @{ legend = @{ displayMode = "table"; placement = "bottom"; calcs = @("lastNotNull", "max") }; tooltip = @{ mode = "multi"; sort = "desc" } }
        }
        targets = $Targets
    }
}

function New-LogsPanel {
    param([int]$ID, [int]$Y, [string]$Query)

    return @{
        id         = $ID
        title      = "Recent logs"
        type       = "logs"
        datasource = @{ type = "elasticsearch"; uid = "elasticsearch" }
        gridPos    = @{ x = 0; y = $Y; w = 24; h = 10 }
        options    = @{ dedupStrategy = "none"; enableLogDetails = $true; prettifyLogMessage = $false; showCommonLabels = $false; showLabels = $false; showTime = $true; sortOrder = "Descending"; wrapLogMessage = $true }
        targets    = @(@{
            refId      = "Logs"
            query      = $Query
            queryType  = "logs"
            datasource = @{ type = "elasticsearch"; uid = "elasticsearch" }
            metrics    = @(@{ id = "1"; type = "logs" })
            bucketAggs = @()
            timeField  = "@timestamp"
        })
    }
}

function New-KubernetesDashboard {
    $script:TargetIndex = 0
    $panels = @(
        New-Panel 1 "Ready nodes" "stat" 0 0 4 5 @(
            New-PrometheusTarget 'sum(kube_node_status_condition{condition="Ready",status="true"}) or vector(0)' 'ready'
        )
        New-Panel 2 "Running pods" "stat" 4 0 4 5 @(
            New-PrometheusTarget 'sum(kube_pod_status_phase{namespace="automatic-system",phase="Running"}) or vector(0)' 'running'
        )
        New-Panel 3 "Unhealthy pods" "stat" 8 0 4 5 @(
            New-PrometheusTarget 'sum(kube_pod_status_phase{namespace="automatic-system",phase=~"Pending|Failed|Unknown"}) or vector(0)' 'unhealthy'
        )
        New-Panel 4 "Container restarts (1h)" "stat" 12 0 4 5 @(
            New-PrometheusTarget 'sum(increase(kube_pod_container_status_restarts_total{namespace="automatic-system"}[1h])) or vector(0)' 'restarts'
        )
        New-Panel 5 "Deployments ready" "stat" 16 0 4 5 @(
            New-PrometheusTarget 'sum(kube_deployment_status_replicas_available{namespace="automatic-system"}) or vector(0)' 'replicas'
        )
        New-Panel 6 "StatefulSets ready" "stat" 20 0 4 5 @(
            New-PrometheusTarget 'sum(kube_statefulset_status_replicas_ready{namespace="automatic-system"}) or vector(0)' 'replicas'
        )
        New-Panel 7 "Node CPU usage" "timeseries" 0 5 12 8 @(
            New-PrometheusTarget '100 * (1 - avg by (node) (rate(node_cpu_seconds_total{job="node-exporter",mode="idle"}[5m])))' '{{node}}'
        ) "percent"
        New-Panel 8 "Node memory usage" "timeseries" 12 5 12 8 @(
            New-PrometheusTarget '100 * (1 - node_memory_MemAvailable_bytes{job="node-exporter"} / node_memory_MemTotal_bytes{job="node-exporter"})' '{{node}}'
        ) "percent"
        New-Panel 9 "Pod CPU usage" "timeseries" 0 13 12 8 @(
            New-PrometheusTarget 'topk(15, sum by (pod) (rate(container_cpu_usage_seconds_total{namespace="automatic-system",container!="",image!=""}[5m])))' '{{pod}}'
        ) "cores"
        New-Panel 10 "Pod working-set memory" "timeseries" 12 13 12 8 @(
            New-PrometheusTarget 'topk(15, sum by (pod) (container_memory_working_set_bytes{namespace="automatic-system",container!="",image!=""}))' '{{pod}}'
        ) "bytes"
        New-Panel 11 "Pods by phase" "timeseries" 0 21 12 8 @(
            New-PrometheusTarget 'sum by (phase) (kube_pod_status_phase{namespace="automatic-system"})' '{{phase}}'
        ) "short"
        New-Panel 12 "Desired versus available deployments" "timeseries" 12 21 12 8 @(
            New-PrometheusTarget 'sum by (deployment) (kube_deployment_spec_replicas{namespace="automatic-system"})' '{{deployment}} desired'
            New-PrometheusTarget 'sum by (deployment) (kube_deployment_status_replicas_available{namespace="automatic-system"})' '{{deployment}} available'
        ) "short"
        New-Panel 13 "Container CPU throttling" "timeseries" 0 29 12 8 @(
            New-PrometheusTarget 'topk(15, sum by (pod, container) (rate(container_cpu_cfs_throttled_seconds_total{namespace="automatic-system",container!=""}[5m])))' '{{pod}} / {{container}}'
        ) "s"
        New-Panel 14 "Pod network throughput" "timeseries" 12 29 12 8 @(
            New-PrometheusTarget 'sum by (pod) (rate(container_network_receive_bytes_total{namespace="automatic-system"}[5m]))' '{{pod}} receive'
            New-PrometheusTarget 'sum by (pod) (rate(container_network_transmit_bytes_total{namespace="automatic-system"}[5m]))' '{{pod}} transmit'
        ) "Bps"
        New-Panel 15 "Node filesystem usage" "timeseries" 0 37 12 8 @(
            New-PrometheusTarget '100 * (1 - node_filesystem_avail_bytes{job="node-exporter",fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{job="node-exporter",fstype!~"tmpfs|overlay"})' '{{node}} / {{mountpoint}}'
        ) "percent"
        New-Panel 16 "Persistent volume claims" "timeseries" 12 37 12 8 @(
            New-PrometheusTarget 'sum by (phase) (kube_persistentvolumeclaim_status_phase{namespace="automatic-system"})' '{{phase}}'
        ) "short"
        New-Panel 17 "Observability scrape health" "timeseries" 0 45 12 8 @(
            New-PrometheusTarget 'up{job=~"prometheus|otel-collector|kube-state-metrics|node-exporter|kubernetes-kubelet|kubernetes-cadvisor"}' '{{job}} / {{instance}}'
        ) "short"
        New-Panel 18 "Kubernetes API and kubelet request rate" "timeseries" 12 45 12 8 @(
            New-PrometheusTarget 'sum by (verb, code) (rate(rest_client_requests_total[5m]))' '{{verb}} / {{code}}'
        ) "reqps"
        New-LogsPanel 19 53 'kubernetes.namespace: automatic-system'
    )

    return New-Dashboard "automatic-system-kubernetes-cluster" "Kubernetes / Cluster Overview" @("automatic-system", "kubernetes", "cluster") $panels
}

function New-Dashboard {
    param(
        [string]$UID,
        [string]$Title,
        [string[]]$Tags,
        [array]$Panels
    )

    $fileUID = $UID
    if ($UID.Length -gt 40) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($UID)
        $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
        $suffix = [Convert]::ToHexString($hash).Substring(0, 8).ToLowerInvariant()
        $UID = "$($UID.Substring(0, 31))-$suffix"
    }

    return @{
        dashboardFileUID = $fileUID
        annotations   = @{ list = @() }
        editable      = $false
        fiscalYearStartMonth = 0
        graphTooltip  = 1
        id            = $null
        links         = @()
        liveNow       = $false
        panels        = $Panels
        refresh       = "30s"
        schemaVersion = 41
        tags          = $Tags
        templating    = @{ list = @() }
        time          = @{ from = "now-6h"; to = "now" }
        timepicker    = @{}
        timezone      = "browser"
        title         = $Title
        uid           = $UID
        version       = 1
        weekStart     = ""
    }
}

function Write-Dashboard {
    param([hashtable]$Dashboard)

    $fileUID = $Dashboard.dashboardFileUID
    $Dashboard.Remove("dashboardFileUID")
    $path = Join-Path $OutputDirectory "$fileUID.json"
    $Dashboard | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $path -Encoding utf8NoBOM
}

function New-ServiceDashboard {
    param([string]$Service, [string]$Title)

    $script:TargetIndex = 0
    if ($Service -eq "api-gateway") {
        $requestRateExpression = "sum by (http_route, http_response_status_class) (rate(http_server_request_count_total{job=`"application-services`",service=`"$Service`",http_route!~`"/livez|/readyz`"}[5m])) or vector(0)"
        $requestLegend = "{{http_route}} / {{http_response_status_class}}"
        $latencyFilter = "job=`"application-services`",service=`"$Service`",http_route!~`"/livez|/readyz`""
    } else {
        $requestRateExpression = "sum by (rpc_method, rpc_response_status_code) (rate(rpc_server_call_duration_seconds_count{job=`"application-services`",service=`"$Service`",rpc_method!~`"grpc.health.*`"}[5m])) or vector(0)"
        $requestLegend = "{{rpc_method}} / {{rpc_response_status_code}}"
        $latencyFilter = "job=`"application-services`",service=`"$Service`",rpc_method!~`"grpc.health.*`""
    }

    $latencyMetric = if ($Service -eq "api-gateway") {
        "http_server_request_duration_seconds_bucket"
    } else {
        "rpc_server_call_duration_seconds_bucket"
    }

    $panels = @(
        New-Panel 1 "Scrape availability" "stat" 0 0 4 5 @(
            New-PrometheusTarget "max(up{job=`"application-services`",service=`"$Service`"}) or vector(0)" "up"
        )
        New-Panel 2 "Span rate" "stat" 4 0 5 5 @(
            New-PrometheusTarget "sum(rate(traces_span_metrics_calls_total{exported_job=`"$Service`"}[5m])) or vector(0)" "spans/s"
        ) "reqps"
        New-Panel 3 "Span error rate" "stat" 9 0 5 5 @(
            New-PrometheusTarget "100 * sum(rate(traces_span_metrics_calls_total{exported_job=`"$Service`",status_code=`"STATUS_CODE_ERROR`"}[5m])) / clamp_min(sum(rate(traces_span_metrics_calls_total{exported_job=`"$Service`"}[5m])), 0.001) or vector(0)" "errors"
        ) "percent"
        New-Panel 4 "Span p95 latency" "stat" 14 0 5 5 @(
            New-PrometheusTarget "histogram_quantile(0.95, sum by (le) (rate(traces_span_metrics_duration_milliseconds_bucket{exported_job=`"$Service`"}[5m]))) or vector(0)" "p95"
        ) "ms"
        New-Panel 5 "Go managed memory" "stat" 19 0 5 5 @(
            New-PrometheusTarget "sum(go_memory_used_bytes{job=`"application-services`",service=`"$Service`"}) or vector(0)" "memory"
        ) "bytes"
        New-Panel 6 "Operations by span name" "timeseries" 0 5 12 8 @(
            New-PrometheusTarget "sum by (span_name, span_kind) (rate(traces_span_metrics_calls_total{exported_job=`"$Service`"}[5m])) or vector(0)" "{{span_kind}} / {{span_name}}"
        ) "ops"
        New-Panel 7 "Operation p95 latency" "timeseries" 12 5 12 8 @(
            New-PrometheusTarget "histogram_quantile(0.95, sum by (le, span_name) (rate(traces_span_metrics_duration_milliseconds_bucket{exported_job=`"$Service`"}[5m]))) or vector(0)" "{{span_name}}"
        ) "ms"
        New-Panel 8 "Failed operations" "timeseries" 0 13 12 8 @(
            New-PrometheusTarget "sum by (span_name, span_kind) (rate(traces_span_metrics_calls_total{exported_job=`"$Service`",status_code=`"STATUS_CODE_ERROR`"}[5m])) or vector(0)" "{{span_kind}} / {{span_name}}"
        ) "ops"
        New-Panel 9 "Incoming service graph" "timeseries" 12 13 12 8 @(
            New-PrometheusTarget "sum by (client, failed) (rate(traces_service_graph_request_total{server=`"$Service`"}[5m])) or vector(0)" "{{client}} / failed={{failed}}"
        ) "reqps"
        New-Panel 10 "Outgoing service graph" "timeseries" 0 21 12 8 @(
            New-PrometheusTarget "sum by (server, failed) (rate(traces_service_graph_request_total{client=`"$Service`"}[5m])) or vector(0)" "{{server}} / failed={{failed}}"
        ) "reqps"
        New-Panel 11 "Outgoing dependency p95" "timeseries" 12 21 12 8 @(
            New-PrometheusTarget "histogram_quantile(0.95, sum by (le, server) (rate(traces_service_graph_request_server_seconds_bucket{client=`"$Service`"}[5m]))) or vector(0)" "{{server}}"
        ) "s"
        New-Panel 12 "Requests by operation and status" "timeseries" 0 29 12 8 @(
            New-PrometheusTarget $requestRateExpression $requestLegend
        ) "ops"
        New-Panel 13 "Request latency percentiles" "timeseries" 12 29 12 8 @(
            New-PrometheusTarget "histogram_quantile(0.50, sum by (le) (rate(${latencyMetric}{${latencyFilter}}[5m]))) or vector(0)" "p50"
            New-PrometheusTarget "histogram_quantile(0.95, sum by (le) (rate(${latencyMetric}{${latencyFilter}}[5m]))) or vector(0)" "p95"
            New-PrometheusTarget "histogram_quantile(0.99, sum by (le) (rate(${latencyMetric}{${latencyFilter}}[5m]))) or vector(0)" "p99"
        ) "s"
        New-Panel 14 "Database operations" "timeseries" 0 37 12 8 @(
            New-PrometheusTarget "sum by (pgx_operation_type) (rate(db_client_operation_duration_seconds_count{job=`"application-services`",service=`"$Service`"}[5m])) or vector(0)" "{{pgx_operation_type}}"
            New-PrometheusTarget "sum by (pgx_operation_type) (rate(db_client_operation_errors_total{job=`"application-services`",service=`"$Service`"}[5m])) or vector(0)" "{{pgx_operation_type}} errors"
        ) "ops"
        New-Panel 15 "Database p95 latency" "timeseries" 12 37 12 8 @(
            New-PrometheusTarget "histogram_quantile(0.95, sum by (le, pgx_operation_type) (rate(db_client_operation_duration_seconds_bucket{job=`"application-services`",service=`"$Service`"}[5m]))) or vector(0)" "{{pgx_operation_type}}"
        ) "s"
        New-Panel 16 "Connection pool" "timeseries" 0 45 12 8 @(
            New-PrometheusTarget "sum(pgxpool_acquired_connections{job=`"application-services`",service=`"$Service`"}) or vector(0)" "acquired"
            New-PrometheusTarget "sum(pgxpool_idle_connections{job=`"application-services`",service=`"$Service`"}) or vector(0)" "idle"
            New-PrometheusTarget "sum(pgxpool_max_connections{job=`"application-services`",service=`"$Service`"}) or vector(0)" "max"
        ) "short"
        New-Panel 17 "Go runtime" "timeseries" 12 45 12 8 @(
            New-PrometheusTarget "sum(go_goroutine_count{job=`"application-services`",service=`"$Service`"}) or vector(0)" "goroutines"
            New-PrometheusTarget "sum(rate(process_cpu_seconds_total{job=`"application-services`",service=`"$Service`"}[5m])) or vector(0)" "CPU cores"
        ) "short"
        New-Panel 18 "Istio traffic by destination" "timeseries" 0 53 24 8 @(
            New-PrometheusTarget "sum by (destination_service_name, response_code) (rate(istio_requests_total{source_app=`"$Service`",reporter=`"source`"}[5m])) or vector(0)" "{{destination_service_name}} / {{response_code}}"
        ) "ops"
        New-LogsPanel 19 61 "kubernetes.pod.name: $Service-*"
    )

    return New-Dashboard "automatic-system-service-$Service" "Service / $Title" @("automatic-system", "service", $Service) $panels
}

function New-InfrastructureDashboard {
    param(
        [string]$UID,
        [string]$Title,
        [string]$Filter,
        [string]$LogQuery,
        [array]$Metrics
    )

    $script:TargetIndex = 0
    $panels = @()
    $id = 1
    $y = 0
    for ($index = 0; $index -lt $Metrics.Count; $index += 2) {
        for ($column = 0; $column -lt 2 -and ($index + $column) -lt $Metrics.Count; $column++) {
            $metric = $Metrics[$index + $column]
            $expression = $metric.Expression.Replace("__FILTER__", $Filter)
            $expression = "($expression) or vector(0)"
            $panels += New-Panel $id $metric.Title "timeseries" ($column * 12) $y 12 8 @(
                New-PrometheusTarget $expression $metric.Legend
            ) $metric.Unit
            $id++
        }
        $y += 8
    }
    $panels += New-LogsPanel $id $y $LogQuery

    return New-Dashboard "automatic-system-infra-$UID" "Infrastructure / $Title" @("automatic-system", "infrastructure", $UID) $panels
}

if (Test-Path -LiteralPath $OutputDirectory) {
    Get-ChildItem -LiteralPath $OutputDirectory -Filter "*.json" | Remove-Item -Force
} else {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$services = @(
    @{ Name = "api-gateway"; Title = "API Gateway" },
    @{ Name = "auth-service"; Title = "Auth Service" },
    @{ Name = "ticket-service"; Title = "Ticket Service" },
    @{ Name = "department-service"; Title = "Department Service" },
    @{ Name = "brigade-service"; Title = "Brigade Service" },
    @{ Name = "profile-service"; Title = "Profile Service" },
    @{ Name = "location-service"; Title = "Location Service" },
    @{ Name = "routing-service"; Title = "Routing Service" },
    @{ Name = "dispatch-service"; Title = "Dispatch Service" },
    @{ Name = "file-service"; Title = "File Service" },
    @{ Name = "sla-service"; Title = "SLA Service" },
    @{ Name = "notification-service"; Title = "Notification Service" },
    @{ Name = "audit-service"; Title = "Audit Service" },
    @{ Name = "analytics-service"; Title = "Analytics Service" },
    @{ Name = "report-service"; Title = "Report Service" },
    @{ Name = "asset-service"; Title = "Asset Service" }
)

foreach ($service in $services) {
    Write-Dashboard (New-ServiceDashboard $service.Name $service.Title)
}

$postgresMetrics = @(
    @{ Title = "PostgreSQL availability"; Expression = 'pg_up{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Patroni role"; Expression = 'patroni_primary{__FILTER__}'; Legend = '{{name}} primary'; Unit = "short" },
    @{ Title = "Replication lag"; Expression = 'pg_replication_lag_seconds{__FILTER__}'; Legend = '{{pod}}'; Unit = "s" },
    @{ Title = "Database connections"; Expression = 'sum by (pod, datname) (pg_stat_database_numbackends{__FILTER__})'; Legend = '{{pod}} / {{datname}}'; Unit = "short" },
    @{ Title = "Connection utilization"; Expression = '100 * sum by (pod) (pg_stat_database_numbackends{__FILTER__}) / clamp_min(max by (pod) (pg_settings_max_connections{__FILTER__}), 1)'; Legend = '{{pod}}'; Unit = "percent" },
    @{ Title = "Maximum transaction duration"; Expression = 'max by (pod) (pg_stat_activity_max_tx_duration{__FILTER__})'; Legend = '{{pod}}'; Unit = "s" },
    @{ Title = "Commits"; Expression = 'sum by (pod, datname) (rate(pg_stat_database_xact_commit{__FILTER__}[5m]))'; Legend = '{{pod}} / {{datname}}'; Unit = "ops" },
    @{ Title = "Rollbacks"; Expression = 'sum by (pod, datname) (rate(pg_stat_database_xact_rollback{__FILTER__}[5m]))'; Legend = '{{pod}} / {{datname}}'; Unit = "ops" },
    @{ Title = "Cache hit ratio"; Expression = '100 * sum by (pod, datname) (rate(pg_stat_database_blks_hit{__FILTER__}[5m])) / clamp_min(sum by (pod, datname) (rate(pg_stat_database_blks_hit{__FILTER__}[5m]) + rate(pg_stat_database_blks_read{__FILTER__}[5m])), 0.001)'; Legend = '{{pod}} / {{datname}}'; Unit = "percent" },
    @{ Title = "Rows returned and fetched"; Expression = 'sum by (pod, datname) (rate(pg_stat_database_tup_returned{__FILTER__}[5m]))'; Legend = '{{pod}} / {{datname}} returned'; Unit = "ops" },
    @{ Title = "Rows fetched"; Expression = 'sum by (pod, datname) (rate(pg_stat_database_tup_fetched{__FILTER__}[5m]))'; Legend = '{{pod}} / {{datname}}'; Unit = "ops" },
    @{ Title = "Rows inserted"; Expression = 'sum by (pod, datname) (rate(pg_stat_database_tup_inserted{__FILTER__}[5m]))'; Legend = '{{pod}} / {{datname}}'; Unit = "ops" },
    @{ Title = "Rows updated"; Expression = 'sum by (pod, datname) (rate(pg_stat_database_tup_updated{__FILTER__}[5m]))'; Legend = '{{pod}} / {{datname}}'; Unit = "ops" },
    @{ Title = "Rows deleted"; Expression = 'sum by (pod, datname) (rate(pg_stat_database_tup_deleted{__FILTER__}[5m]))'; Legend = '{{pod}} / {{datname}}'; Unit = "ops" },
    @{ Title = "Deadlocks"; Expression = 'sum by (pod, datname) (rate(pg_stat_database_deadlocks{__FILTER__}[5m]))'; Legend = '{{pod}} / {{datname}}'; Unit = "ops" },
    @{ Title = "Conflicts"; Expression = 'sum by (pod, datname) (rate(pg_stat_database_conflicts{__FILTER__}[5m]))'; Legend = '{{pod}} / {{datname}}'; Unit = "ops" },
    @{ Title = "Locks by mode"; Expression = 'sum by (pod, datname, mode) (pg_locks_count{__FILTER__})'; Legend = '{{pod}} / {{datname}} / {{mode}}'; Unit = "short" },
    @{ Title = "Temporary files"; Expression = 'sum by (pod, datname) (rate(pg_stat_database_temp_files{__FILTER__}[5m]))'; Legend = '{{pod}} / {{datname}}'; Unit = "ops" },
    @{ Title = "Temporary bytes"; Expression = 'sum by (pod, datname) (rate(pg_stat_database_temp_bytes{__FILTER__}[5m]))'; Legend = '{{pod}} / {{datname}}'; Unit = "Bps" },
    @{ Title = "Block read time"; Expression = 'sum by (pod, datname) (rate(pg_stat_database_blk_read_time{__FILTER__}[5m]))'; Legend = '{{pod}} / {{datname}}'; Unit = "ms" },
    @{ Title = "Block write time"; Expression = 'sum by (pod, datname) (rate(pg_stat_database_blk_write_time{__FILTER__}[5m]))'; Legend = '{{pod}} / {{datname}}'; Unit = "ms" },
    @{ Title = "Database size"; Expression = 'sum by (pod, datname) (pg_database_size_bytes{__FILTER__})'; Legend = '{{pod}} / {{datname}}'; Unit = "bytes" },
    @{ Title = "WAL size"; Expression = 'max by (pod) (pg_wal_size_bytes{__FILTER__})'; Legend = '{{pod}}'; Unit = "bytes" },
    @{ Title = "WAL segments"; Expression = 'max by (pod) (pg_wal_segments{__FILTER__})'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Timed checkpoints"; Expression = 'sum by (pod) (rate(pg_stat_bgwriter_checkpoints_timed_total{__FILTER__}[5m]))'; Legend = '{{pod}}'; Unit = "ops" },
    @{ Title = "Requested checkpoints"; Expression = 'sum by (pod) (rate(pg_stat_bgwriter_checkpoints_req_total{__FILTER__}[5m]))'; Legend = '{{pod}}'; Unit = "ops" },
    @{ Title = "Checkpoint write time"; Expression = 'sum by (pod) (rate(pg_stat_bgwriter_checkpoint_write_time_total{__FILTER__}[5m]))'; Legend = '{{pod}}'; Unit = "ms" },
    @{ Title = "Exporter scrape errors"; Expression = 'max by (pod) (pg_exporter_last_scrape_error{__FILTER__})'; Legend = '{{pod}}'; Unit = "short" }
)

$postgresDatabaseMetricTitles = @(
    "Database connections",
    "Commits",
    "Rollbacks",
    "Cache hit ratio",
    "Rows returned and fetched",
    "Rows fetched",
    "Rows inserted",
    "Rows updated",
    "Rows deleted",
    "Deadlocks",
    "Conflicts",
    "Locks by mode",
    "Temporary files",
    "Temporary bytes",
    "Block read time",
    "Block write time",
    "Database size"
)
$postgresDatabaseMetrics = @(
    $postgresMetrics | Where-Object { $_.Title -in $postgresDatabaseMetricTitles }
)

$pgbouncerMetrics = @(
    @{ Title = "Exporter availability"; Expression = 'pgbouncer_up{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Client connections"; Expression = 'sum by (pod) (pgbouncer_client_connections{__FILTER__})'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Active / waiting clients"; Expression = 'sum by (pod) (pgbouncer_pools_client_active_connections{__FILTER__})'; Legend = '{{pod}} active'; Unit = "short" },
    @{ Title = "Waiting clients"; Expression = 'sum by (pod, database, user) (pgbouncer_pools_client_waiting_connections{__FILTER__})'; Legend = '{{pod}} / {{database}} / {{user}}'; Unit = "short" },
    @{ Title = "Client maximum wait"; Expression = 'max by (pod, database, user) (pgbouncer_pools_client_maxwait_seconds{__FILTER__})'; Legend = '{{pod}} / {{database}} / {{user}}'; Unit = "s" },
    @{ Title = "Active servers"; Expression = 'sum by (pod, database, user) (pgbouncer_pools_server_active_connections{__FILTER__})'; Legend = '{{pod}} / {{database}} / {{user}}'; Unit = "short" },
    @{ Title = "Idle servers"; Expression = 'sum by (pod, database, user) (pgbouncer_pools_server_idle_connections{__FILTER__})'; Legend = '{{pod}} / {{database}} / {{user}}'; Unit = "short" },
    @{ Title = "Used servers"; Expression = 'sum by (pod, database, user) (pgbouncer_pools_server_used_connections{__FILTER__})'; Legend = '{{pod}} / {{database}} / {{user}}'; Unit = "short" },
    @{ Title = "Login and testing servers"; Expression = 'sum by (pod) (pgbouncer_pools_server_login_connections{__FILTER__} + pgbouncer_pools_server_testing_connections{__FILTER__})'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Free clients"; Expression = 'sum by (pod) (pgbouncer_free_clients{__FILTER__})'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Free servers"; Expression = 'sum by (pod) (pgbouncer_free_servers{__FILTER__})'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Query rate"; Expression = 'sum by (pod) (rate(pgbouncer_stats_totals_queries_pooled_total{__FILTER__}[5m]))'; Legend = '{{pod}}'; Unit = "ops" },
    @{ Title = "Transaction rate"; Expression = 'sum by (pod) (rate(pgbouncer_stats_totals_sql_transactions_pooled_total{__FILTER__}[5m]))'; Legend = '{{pod}}'; Unit = "ops" },
    @{ Title = "Average query duration"; Expression = 'sum by (pod) (rate(pgbouncer_stats_totals_queries_duration_seconds_total{__FILTER__}[5m])) / clamp_min(sum by (pod) (rate(pgbouncer_stats_totals_queries_pooled_total{__FILTER__}[5m])), 0.001)'; Legend = '{{pod}}'; Unit = "s" },
    @{ Title = "Client wait time"; Expression = 'sum by (pod) (rate(pgbouncer_stats_totals_client_wait_seconds_total{__FILTER__}[5m]))'; Legend = '{{pod}}'; Unit = "s" },
    @{ Title = "Server transaction time"; Expression = 'sum by (pod) (rate(pgbouncer_stats_totals_server_in_transaction_seconds_total{__FILTER__}[5m]))'; Legend = '{{pod}}'; Unit = "s" },
    @{ Title = "Network received"; Expression = 'sum by (pod) (rate(pgbouncer_stats_totals_received_bytes_total{__FILTER__}[5m]))'; Legend = '{{pod}}'; Unit = "Bps" },
    @{ Title = "Network sent"; Expression = 'sum by (pod) (rate(pgbouncer_stats_totals_sent_bytes_total{__FILTER__}[5m]))'; Legend = '{{pod}}'; Unit = "Bps" },
    @{ Title = "Database current connections"; Expression = 'sum by (pod, database) (pgbouncer_databases_current_connections{__FILTER__})'; Legend = '{{pod}} / {{database}}'; Unit = "short" },
    @{ Title = "Database connection limit"; Expression = 'sum by (pod, database) (pgbouncer_databases_max_connections{__FILTER__})'; Legend = '{{pod}} / {{database}}'; Unit = "short" },
    @{ Title = "Database pool size"; Expression = 'sum by (pod, database) (pgbouncer_databases_pool_size{__FILTER__})'; Legend = '{{pod}} / {{database}}'; Unit = "short" },
    @{ Title = "Database reserve pool"; Expression = 'sum by (pod, database) (pgbouncer_databases_reserve_pool{__FILTER__})'; Legend = '{{pod}} / {{database}}'; Unit = "short" },
    @{ Title = "Configured maximum clients"; Expression = 'max by (pod) (pgbouncer_config_max_client_connections{__FILTER__})'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Configured maximum user connections"; Expression = 'max by (pod) (pgbouncer_config_max_user_connections{__FILTER__})'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "DNS cache and in-flight queries"; Expression = 'sum by (pod) (pgbouncer_cached_dns_names{__FILTER__} + pgbouncer_in_flight_dns_queries{__FILTER__})'; Legend = '{{pod}}'; Unit = "short" }
)

$patroniMetrics = @(
    @{ Title = "PostgreSQL running"; Expression = 'patroni_postgres_running{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Primary role"; Expression = 'patroni_primary{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Replica role"; Expression = 'patroni_replica{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Standby leader"; Expression = 'patroni_standby_leader{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Synchronous standby"; Expression = 'patroni_sync_standby{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Quorum standby"; Expression = 'patroni_quorum_standby{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Cluster unlocked"; Expression = 'patroni_cluster_unlocked{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "DCS observation age"; Expression = 'time() - patroni_dcs_last_seen{__FILTER__}'; Legend = '{{pod}}'; Unit = "s" },
    @{ Title = "Pause mode"; Expression = 'patroni_is_paused{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Pending restart"; Expression = 'patroni_pending_restart{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Failsafe mode"; Expression = 'patroni_failsafe_mode_is_active{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Archive recovery"; Expression = 'patroni_postgres_in_archive_recovery{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "PostgreSQL state"; Expression = 'patroni_postgres_state{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Streaming state"; Expression = 'patroni_postgres_streaming{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Timeline"; Expression = 'patroni_postgres_timeline{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Postmaster uptime"; Expression = 'time() - patroni_postmaster_start_time{__FILTER__}'; Legend = '{{pod}}'; Unit = "s" },
    @{ Title = "WAL location"; Expression = 'patroni_xlog_location{__FILTER__}'; Legend = '{{pod}}'; Unit = "bytes" },
    @{ Title = "WAL received"; Expression = 'patroni_xlog_received_location{__FILTER__}'; Legend = '{{pod}}'; Unit = "bytes" },
    @{ Title = "WAL replayed"; Expression = 'patroni_xlog_replayed_location{__FILTER__}'; Legend = '{{pod}}'; Unit = "bytes" },
    @{ Title = "WAL replay delay"; Expression = 'time() - patroni_xlog_replayed_timestamp{__FILTER__}'; Legend = '{{pod}}'; Unit = "s" },
    @{ Title = "WAL replay paused"; Expression = 'patroni_xlog_paused{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Patroni version"; Expression = 'patroni_version{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "PostgreSQL server version"; Expression = 'patroni_postgres_server_version{__FILTER__}'; Legend = '{{pod}}'; Unit = "short" }
)

$citusMetrics = @(
    @{ Title = "Active nodes"; Expression = 'max(citus_cluster_active_nodes{__FILTER__})'; Legend = 'active'; Unit = "short" },
    @{ Title = "Inactive nodes"; Expression = 'max(citus_cluster_inactive_nodes{__FILTER__})'; Legend = 'inactive'; Unit = "short" },
    @{ Title = "Primary and secondary nodes"; Expression = 'max(citus_cluster_primary_nodes{__FILTER__})'; Legend = 'primary'; Unit = "short" },
    @{ Title = "Secondary nodes"; Expression = 'max(citus_cluster_secondary_nodes{__FILTER__})'; Legend = 'secondary'; Unit = "short" },
    @{ Title = "Shard-bearing nodes"; Expression = 'max(citus_cluster_shard_bearing_nodes{__FILTER__})'; Legend = 'nodes'; Unit = "short" },
    @{ Title = "Node availability"; Expression = 'max by (node_name, node_role, group_id) (citus_nodes_active{__FILTER__})'; Legend = '{{node_name}} / {{node_role}} / group {{group_id}}'; Unit = "short" },
    @{ Title = "Metadata synchronization"; Expression = 'max by (node_name, group_id) (citus_nodes_metadata_synced{__FILTER__})'; Legend = '{{node_name}} / group {{group_id}}'; Unit = "short" },
    @{ Title = "Shards per table"; Expression = 'max by (table_name, colocation_id) (citus_tables_shards{__FILTER__})'; Legend = '{{table_name}} / colocation {{colocation_id}}'; Unit = "short" },
    @{ Title = "Placements per table"; Expression = 'max by (table_name, colocation_id) (citus_tables_placements{__FILTER__})'; Legend = '{{table_name}} / colocation {{colocation_id}}'; Unit = "short" },
    @{ Title = "Inactive placements"; Expression = 'max by (table_name) (citus_tables_inactive_placements{__FILTER__})'; Legend = '{{table_name}}'; Unit = "short" },
    @{ Title = "Distributed query activity"; Expression = 'sum by (state, wait_event_type) (citus_activity_queries{__FILTER__})'; Legend = '{{state}} / {{wait_event_type}}'; Unit = "short" },
    @{ Title = "Distributed lock waits"; Expression = 'max(citus_locks_waits{__FILTER__})'; Legend = 'waits'; Unit = "short" }
)

$redisMetrics = @(
    @{ Title = "Memory"; Expression = 'redis_memory_used_bytes{__FILTER__}'; Legend = '{{instance}}'; Unit = "bytes" },
    @{ Title = "Connected clients"; Expression = 'redis_connected_clients{__FILTER__}'; Legend = '{{instance}}'; Unit = "short" },
    @{ Title = "Commands"; Expression = 'sum by (instance) (rate(redis_commands_total{__FILTER__}[5m]))'; Legend = '{{instance}}'; Unit = "ops" },
    @{ Title = "Hit ratio"; Expression = 'rate(redis_keyspace_hits_total{__FILTER__}[5m]) / clamp_min(rate(redis_keyspace_hits_total{__FILTER__}[5m]) + rate(redis_keyspace_misses_total{__FILTER__}[5m]), 0.001)'; Legend = '{{instance}}'; Unit = "percentunit" },
    @{ Title = "Network input"; Expression = 'rate(redis_net_input_bytes_total{__FILTER__}[5m])'; Legend = '{{instance}}'; Unit = "Bps" },
    @{ Title = "Evicted / expired keys"; Expression = 'rate(redis_evicted_keys_total{__FILTER__}[5m]) + rate(redis_expired_keys_total{__FILTER__}[5m])'; Legend = '{{instance}}'; Unit = "ops" }
)

$kafkaMetrics = @(
    @{ Title = "Discovered brokers"; Expression = 'kafka_brokers{__FILTER__}'; Legend = 'brokers'; Unit = "short" },
    @{ Title = "Topic partitions"; Expression = 'kafka_topic_partitions{__FILTER__}'; Legend = '{{topic}}'; Unit = "short" },
    @{ Title = "Current offsets"; Expression = 'sum by (topic) (kafka_topic_partition_current_offset{__FILTER__})'; Legend = '{{topic}}'; Unit = "short" },
    @{ Title = "Oldest offsets"; Expression = 'min by (topic) (kafka_topic_partition_oldest_offset{__FILTER__})'; Legend = '{{topic}}'; Unit = "short" },
    @{ Title = "Consumer group lag"; Expression = 'sum by (consumergroup, topic) (kafka_consumergroup_lag{__FILTER__})'; Legend = '{{consumergroup}} / {{topic}}'; Unit = "short" },
    @{ Title = "Consumer group members"; Expression = 'kafka_consumergroup_members{__FILTER__}'; Legend = '{{consumergroup}}'; Unit = "short" }
)

$etcdMetrics = @(
    @{ Title = "Cluster has leader"; Expression = 'etcd_server_has_leader{__FILTER__}'; Legend = '{{etcd_node}}'; Unit = "short" },
    @{ Title = "Current leader"; Expression = 'etcd_server_is_leader{__FILTER__}'; Legend = '{{etcd_node}}'; Unit = "short" },
    @{ Title = "Leader changes"; Expression = 'increase(etcd_server_leader_changes_seen_total{__FILTER__}[1h])'; Legend = '{{etcd_node}}'; Unit = "short" },
    @{ Title = "Pending proposals"; Expression = 'etcd_server_proposals_pending{__FILTER__}'; Legend = '{{etcd_node}}'; Unit = "short" },
    @{ Title = "Failed proposals"; Expression = 'rate(etcd_server_proposals_failed_total{__FILTER__}[5m])'; Legend = '{{etcd_node}}'; Unit = "ops" },
    @{ Title = "Committed and applied proposals"; Expression = 'rate(etcd_server_proposals_committed_total{__FILTER__}[5m])'; Legend = '{{etcd_node}} committed'; Unit = "ops" },
    @{ Title = "Backend commit p99"; Expression = 'histogram_quantile(0.99, sum by (le, etcd_node) (rate(etcd_disk_backend_commit_duration_seconds_bucket{__FILTER__}[5m])))'; Legend = '{{etcd_node}}'; Unit = "s" },
    @{ Title = "WAL fsync p99"; Expression = 'histogram_quantile(0.99, sum by (le, etcd_node) (rate(etcd_disk_wal_fsync_duration_seconds_bucket{__FILTER__}[5m])))'; Legend = '{{etcd_node}}'; Unit = "s" },
    @{ Title = "Database allocated size"; Expression = 'etcd_mvcc_db_total_size_in_bytes{__FILTER__}'; Legend = '{{etcd_node}}'; Unit = "bytes" },
    @{ Title = "Database in-use size"; Expression = 'etcd_mvcc_db_total_size_in_use_in_bytes{__FILTER__}'; Legend = '{{etcd_node}}'; Unit = "bytes" },
    @{ Title = "gRPC requests"; Expression = 'sum by (grpc_method, grpc_code, etcd_node) (rate(grpc_server_handled_total{__FILTER__}[5m]))'; Legend = '{{etcd_node}} / {{grpc_method}} / {{grpc_code}}'; Unit = "reqps" },
    @{ Title = "Process memory"; Expression = 'process_resident_memory_bytes{__FILTER__}'; Legend = '{{etcd_node}}'; Unit = "bytes" }
)

Write-Dashboard (New-InfrastructureDashboard "postgres-platform" "PostgreSQL Platform Cluster" 'db_cluster="postgres-platform"' 'kubernetes.pod.name: postgres-platform-*' $postgresMetrics)
Write-Dashboard (New-InfrastructureDashboard "patroni-platform" "Patroni / Platform Cluster" 'db_cluster="postgres-platform"' 'kubernetes.pod.name: postgres-platform-*' $patroniMetrics)
foreach ($node in 0..2) {
    Write-Dashboard (New-InfrastructureDashboard "postgres-platform-$node" "PostgreSQL Platform / Node $node" "pod=`"postgres-platform-$node`"" "kubernetes.pod.name: postgres-platform-$node" $postgresMetrics)
}

Write-Dashboard (New-InfrastructureDashboard "citus" "Citus Ticket Cluster" 'db_cluster="postgres-ticket-citus"' '(kubernetes.pod.name: coordinator-ticket-citus-* OR kubernetes.pod.name: worker-*-ticket-citus-*)' @($postgresMetrics + $citusMetrics))
Write-Dashboard (New-InfrastructureDashboard "patroni-citus" "Patroni / Citus Cluster" 'db_cluster="postgres-ticket-citus"' '(kubernetes.pod.name: coordinator-ticket-citus-* OR kubernetes.pod.name: worker-*-ticket-citus-*)' $patroniMetrics)
$citusNodes = @("coordinator-ticket-citus-0", "coordinator-ticket-citus-1", "coordinator-ticket-citus-2", "worker-1-ticket-citus-0", "worker-1-ticket-citus-1", "worker-2-ticket-citus-0", "worker-2-ticket-citus-1")
foreach ($node in $citusNodes) {
    Write-Dashboard (New-InfrastructureDashboard "citus-$node" "Citus / $node" "pod=`"$node`"" "kubernetes.pod.name: $node" $postgresMetrics)
}

$platformDatabases = @(
    "auth_db",
    "department_db",
    "brigade_db",
    "profile_db",
    "location",
    "routing",
    "dispatch",
    "file",
    "sla",
    "notification",
    "audit",
    "report",
    "asset"
)
foreach ($database in $platformDatabases) {
    Write-Dashboard (New-InfrastructureDashboard "postgres-database-$database" "PostgreSQL Database / $database" "db_cluster=`"postgres-platform`",datname=`"$database`"" "kubernetes.pod.name: postgres-platform-*" $postgresDatabaseMetrics)
}
Write-Dashboard (New-InfrastructureDashboard "postgres-database-ticket-db" "PostgreSQL Database / ticket_db" 'db_cluster="postgres-ticket-citus",datname="ticket_db"' '(kubernetes.pod.name: coordinator-ticket-citus-* OR kubernetes.pod.name: worker-*-ticket-citus-*)' $postgresDatabaseMetrics)

foreach ($pool in @("platform-primary", "platform-replicas", "ticket-primary", "ticket-replicas")) {
    Write-Dashboard (New-InfrastructureDashboard "pgbouncer-$pool" "PgBouncer / $pool" "db_cluster=`"$pool`"" "kubernetes.pod.name: pgbouncer-$pool-*" $pgbouncerMetrics)
}

foreach ($instance in @("gateway", "location-master", "location-replica-1", "location-replica-2", "notification")) {
    Write-Dashboard (New-InfrastructureDashboard "redis-$instance" "Redis / $instance" "instance=`"redis-$instance`"" "kubernetes.pod.name: redis-$instance-*" $redisMetrics)
}

$kafkaBrokerMetrics = @(
    @{ Title = "CPU usage"; Expression = 'sum(rate(container_cpu_usage_seconds_total{__FILTER__,container!="",container!="POD"}[5m]))'; Legend = '{{pod}}'; Unit = "cores" },
    @{ Title = "Memory working set"; Expression = 'sum(container_memory_working_set_bytes{__FILTER__,container!="",container!="POD"})'; Legend = '{{pod}}'; Unit = "bytes" },
    @{ Title = "Container restarts"; Expression = 'sum(kube_pod_container_status_restarts_total{__FILTER__})'; Legend = '{{pod}}'; Unit = "short" },
    @{ Title = "Network receive"; Expression = 'sum(rate(container_network_receive_bytes_total{__FILTER__}[5m]))'; Legend = '{{pod}}'; Unit = "Bps" },
    @{ Title = "Network transmit"; Expression = 'sum(rate(container_network_transmit_bytes_total{__FILTER__}[5m]))'; Legend = '{{pod}}'; Unit = "Bps" }
)
foreach ($broker in @("kafka-1", "kafka-2", "kafka-3")) {
    Write-Dashboard (New-InfrastructureDashboard $broker "Kafka / $broker" "namespace=`"automatic-system`",pod=`"$broker-0`"" "kubernetes.pod.name: $broker-0" $kafkaBrokerMetrics)
}

Write-Dashboard (New-InfrastructureDashboard "etcd" "etcd Cluster" 'etcd_node=~".+"' 'kubernetes.pod.name: etcd-*' $etcdMetrics)

$genericComponents = @(
    @{ ID = "frontend"; Title = "Frontend"; Pod = "frontend-*"; Filter = 'namespace="automatic-system",pod=~"frontend-.+"' },
    @{ ID = "otel-collector"; Title = "OpenTelemetry Collector"; Pod = "otel-collector-*"; Filter = 'namespace="automatic-system",pod=~"otel-collector-.+"' },
    @{ ID = "prometheus"; Title = "Prometheus"; Pod = "prometheus-*"; Filter = 'namespace="automatic-system",pod=~"prometheus-.+"' },
    @{ ID = "grafana"; Title = "Grafana"; Pod = "grafana-*"; Filter = 'namespace="automatic-system",pod=~"grafana-.+"' },
    @{ ID = "jaeger"; Title = "Jaeger"; Pod = "jaeger-*"; Filter = 'namespace="automatic-system",pod=~"jaeger-.+"' },
    @{ ID = "istio"; Title = "Istio Control Plane and Ingress"; Pod = "istio*"; Filter = 'namespace="istio-system",pod=~"istio(d|-ingressgateway)-.+"' },
    @{ ID = "minio"; Title = "MinIO"; Pod = "minio-*"; Filter = 'namespace="automatic-system",pod=~"minio-.+"' },
    @{ ID = "clickhouse"; Title = "ClickHouse"; Pod = "clickhouse-*"; Filter = 'namespace="automatic-system",pod=~"clickhouse-.+"' },
    @{ ID = "elasticsearch"; Title = "Elasticsearch"; Pod = "elasticsearch-*"; Filter = 'namespace="automatic-system",pod=~"elasticsearch-.+"' },
    @{ ID = "kibana"; Title = "Kibana"; Pod = "kibana-*"; Filter = 'namespace="automatic-system",pod=~"kibana-.+"' },
    @{ ID = "filebeat"; Title = "Filebeat"; Pod = "filebeat-*"; Filter = 'namespace="automatic-system",pod=~"filebeat-.+"' },
    @{ ID = "valhalla"; Title = "Valhalla"; Pod = "valhalla-*"; Filter = 'namespace="automatic-system",pod=~"valhalla-.+"' },
    @{ ID = "kiali"; Title = "Kiali"; Pod = "kiali-*"; Filter = 'namespace="istio-system",pod=~"kiali-.+"' }
)
$genericMetrics = @(
    @{ Title = "CPU usage"; Expression = 'sum by (pod) (rate(container_cpu_usage_seconds_total{__FILTER__,container!="",container!="POD"}[5m]))'; Legend = '{{pod}}'; Unit = "cores" },
    @{ Title = "Memory working set"; Expression = 'sum by (pod) (container_memory_working_set_bytes{__FILTER__,container!="",container!="POD"})'; Legend = '{{pod}}'; Unit = "bytes" },
    @{ Title = "Container restarts"; Expression = 'sum by (pod) (kube_pod_container_status_restarts_total{__FILTER__})'; Legend = '{{pod}}'; Unit = "short" }
)
foreach ($component in $genericComponents) {
    Write-Dashboard (New-InfrastructureDashboard $component.ID $component.Title $component.Filter "kubernetes.pod.name: $($component.Pod)" $genericMetrics)
}

$count = @(Get-ChildItem -LiteralPath $OutputDirectory -Filter "*.json").Count
Write-Host "Generated $count Grafana dashboards in $OutputDirectory."


