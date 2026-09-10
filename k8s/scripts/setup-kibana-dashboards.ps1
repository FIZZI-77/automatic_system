[CmdletBinding()]
param(
    [string]$KibanaURL = "http://localhost:5601",
    [string]$DataViewID = "automatic-system-logs",
    [string]$IndexPattern = "logs-automatic-system-*"
)

$ErrorActionPreference = "Stop"
$headers = @{ "kbn-xsrf" = "automatic-system-dashboard-setup" }

$workloads = @(
    @{ ID = "frontend"; Title = "Frontend"; Group = "Service"; Query = 'kubernetes.pod.name: frontend-*' },
    @{ ID = "api-gateway"; Title = "API Gateway"; Group = "Service"; Query = 'kubernetes.pod.name: api-gateway-*' },
    @{ ID = "auth-service"; Title = "Auth Service"; Group = "Service"; Query = 'kubernetes.pod.name: auth-service-*' },
    @{ ID = "ticket-service"; Title = "Ticket Service"; Group = "Service"; Query = 'kubernetes.pod.name: ticket-service-*' },
    @{ ID = "department-service"; Title = "Department Service"; Group = "Service"; Query = 'kubernetes.pod.name: department-service-*' },
    @{ ID = "brigade-service"; Title = "Brigade Service"; Group = "Service"; Query = 'kubernetes.pod.name: brigade-service-*' },
    @{ ID = "profile-service"; Title = "Profile Service"; Group = "Service"; Query = 'kubernetes.pod.name: profile-service-*' },
    @{ ID = "location-service"; Title = "Location Service"; Group = "Service"; Query = 'kubernetes.pod.name: location-service-*' },
    @{ ID = "routing-service"; Title = "Routing Service"; Group = "Service"; Query = 'kubernetes.pod.name: routing-service-*' },
    @{ ID = "dispatch-service"; Title = "Dispatch Service"; Group = "Service"; Query = 'kubernetes.pod.name: dispatch-service-*' },
    @{ ID = "file-service"; Title = "File Service"; Group = "Service"; Query = 'kubernetes.pod.name: file-service-*' },
    @{ ID = "sla-service"; Title = "SLA Service"; Group = "Service"; Query = 'kubernetes.pod.name: sla-service-*' },
    @{ ID = "notification-service"; Title = "Notification Service"; Group = "Service"; Query = 'kubernetes.pod.name: notification-service-*' },
    @{ ID = "audit-service"; Title = "Audit Service"; Group = "Service"; Query = 'kubernetes.pod.name: audit-service-*' },
    @{ ID = "analytics-service"; Title = "Analytics Service"; Group = "Service"; Query = 'kubernetes.pod.name: analytics-service-*' },
    @{ ID = "report-service"; Title = "Report Service"; Group = "Service"; Query = 'kubernetes.pod.name: report-service-*' },
    @{ ID = "asset-service"; Title = "Asset Service"; Group = "Service"; Query = 'kubernetes.pod.name: asset-service-*' },

    @{ ID = "postgres-platform"; Title = "PostgreSQL / Patroni Platform"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: postgres-platform-*' },
    @{ ID = "citus-ticket"; Title = "Citus Ticket Cluster"; Group = "Infrastructure"; Query = '(kubernetes.pod.name: coordinator-ticket-citus-* OR kubernetes.pod.name: worker-1-ticket-citus-* OR kubernetes.pod.name: worker-2-ticket-citus-*)' },
    @{ ID = "pgbouncer-platform"; Title = "PgBouncer Platform"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: pgbouncer-platform-*' },
    @{ ID = "pgbouncer-ticket"; Title = "PgBouncer Ticket"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: pgbouncer-ticket-*' },
    @{ ID = "kafka"; Title = "Kafka Cluster"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: kafka-*' },
    @{ ID = "redis-location"; Title = "Redis Location / Sentinel"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: redis-location-*' },
    @{ ID = "redis-gateway"; Title = "Redis Gateway"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: redis-gateway-*' },
    @{ ID = "redis-notification"; Title = "Redis Notification"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: redis-notification-*' },
    @{ ID = "minio"; Title = "MinIO"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: minio-*' },
    @{ ID = "clickhouse"; Title = "ClickHouse"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: clickhouse-*' },
    @{ ID = "valhalla"; Title = "Valhalla"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: valhalla-*' },
    @{ ID = "elasticsearch"; Title = "Elasticsearch"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: elasticsearch-*' },
    @{ ID = "kibana"; Title = "Kibana"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: kibana-*' },
    @{ ID = "filebeat"; Title = "Filebeat"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: filebeat-*' },
    @{ ID = "otel-collector"; Title = "OpenTelemetry Collector"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: otel-collector-*' },
    @{ ID = "prometheus"; Title = "Prometheus"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: prometheus-*' },
    @{ ID = "grafana"; Title = "Grafana"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: grafana-*' },
    @{ ID = "jaeger"; Title = "Jaeger"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: jaeger-*' },
    @{ ID = "istiod"; Title = "Istio Control Plane"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: istiod-*' },
    @{ ID = "kiali"; Title = "Kiali"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: kiali-*' },
    @{ ID = "mailhog"; Title = "MailHog"; Group = "Infrastructure"; Query = 'kubernetes.pod.name: mailhog-*' },
    @{ ID = "database-jobs"; Title = "Database Migrations / Backups"; Group = "Infrastructure"; Query = '(kubernetes.pod.name: migrator-* OR kubernetes.pod.name: postgres-*-backup*)' },
    @{ ID = "kubernetes-network"; Title = "Kubernetes Network"; Group = "Infrastructure"; Query = '(kubernetes.pod.name: kindnet-* OR kubernetes.pod.name: kube-proxy-*)' }
)

function Ensure-DataView {
    try {
        Invoke-RestMethod `
            -Uri "$KibanaURL/api/data_views/data_view/$DataViewID" `
            -Method Get `
            -Headers $headers | Out-Null

        return
    }
    catch {
        if ($_.Exception.Response.StatusCode -ne 404) {
            throw
        }
    }

    $body = @{
        data_view = @{
            id            = $DataViewID
            title         = $IndexPattern
            name          = "Automatic System Logs"
            timeFieldName = "@timestamp"
            allowNoIndex  = $true
        }
    } | ConvertTo-Json -Depth 6

    Invoke-RestMethod `
        -Uri "$KibanaURL/api/data_views/data_view" `
        -Method Post `
        -Headers $headers `
        -ContentType "application/json" `
        -Body $body | Out-Null
}

function New-SearchObject {
    param(
        [hashtable]$Workload,
        [string]$Kind,
        [string]$Title,
        [string]$Query
    )

    $id = "automatic-system-$($Workload.ID)-$Kind"
    $searchSource = @{
        query        = @{ language = "kuery"; query = $Query }
        filter       = @()
        indexRefName = "kibanaSavedObjectMeta.searchSourceJSON.index"
    } | ConvertTo-Json -Depth 8 -Compress

    return @{
        type       = "search"
        id         = $id
        attributes = @{
            title                 = "[Automatic System] $($Workload.Title) - $Title"
            description           = "$($Workload.Group) logs filtered by workload identity"
            columns               = @("@timestamp", "log.level", "message", "trace_id", "span_id", "kubernetes.pod.name")
            sort                  = @(, @("@timestamp", "desc"))
            hideChart             = $false
            isTextBasedQuery      = $false
            kibanaSavedObjectMeta = @{ searchSourceJSON = $searchSource }
        }
        references = @(
            @{
                id   = $DataViewID
                name = "kibanaSavedObjectMeta.searchSourceJSON.index"
                type = "index-pattern"
            }
        )
    }
}

function New-DashboardObject {
    param([hashtable]$Workload)

    $recentID = "automatic-system-$($Workload.ID)-recent"
    $errorsID = "automatic-system-$($Workload.ID)-errors"
    $warningsID = "automatic-system-$($Workload.ID)-warnings"
    $infoID = "automatic-system-$($Workload.ID)-info"
    $tracesID = "automatic-system-$($Workload.ID)-traces"

    $panels = @(
        @{
            type = "search"; panelIndex = "1"; panelRefName = "panel_1"; title = "Recent logs"
            gridData = @{ x = 0; y = 0; w = 48; h = 22; i = "1" }; embeddableConfig = @{}
        },
        @{
            type = "search"; panelIndex = "2"; panelRefName = "panel_2"; title = "Errors and failures"
            gridData = @{ x = 0; y = 22; w = 16; h = 14; i = "2" }; embeddableConfig = @{}
        },
        @{
            type = "search"; panelIndex = "3"; panelRefName = "panel_3"; title = "Warnings"
            gridData = @{ x = 16; y = 22; w = 16; h = 14; i = "3" }; embeddableConfig = @{}
        },
        @{
            type = "search"; panelIndex = "4"; panelRefName = "panel_4"; title = "Info"
            gridData = @{ x = 32; y = 22; w = 16; h = 14; i = "4" }; embeddableConfig = @{}
        },
        @{
            type = "search"; panelIndex = "5"; panelRefName = "panel_5"; title = "Trace-correlated events"
            gridData = @{ x = 0; y = 36; w = 48; h = 14; i = "5" }; embeddableConfig = @{}
        }
    ) | ConvertTo-Json -Depth 8 -Compress

    $options = @{
        hidePanelTitles = $false
        useMargins       = $true
        syncColors       = $true
        syncCursor       = $true
        syncTooltips     = $true
    } | ConvertTo-Json -Compress

    $searchSource = @{
        query  = @{ language = "kuery"; query = "" }
        filter = @()
    } | ConvertTo-Json -Depth 5 -Compress

    return @{
        type       = "dashboard"
        id         = "automatic-system-$($Workload.ID)"
        attributes = @{
            title                 = "[Automatic System][$($Workload.Group)] $($Workload.Title)"
            description           = "Recent logs, errors and trace-correlated events for $($Workload.Title)"
            panelsJSON            = $panels
            optionsJSON           = $options
            timeRestore           = $true
            timeFrom              = "now-24h"
            timeTo                = "now"
            refreshInterval       = @{ pause = $false; value = 30000 }
            version               = 1
            tags                  = @()
            kibanaSavedObjectMeta = @{ searchSourceJSON = $searchSource }
        }
        references = @(
            @{ id = $recentID; name = "panel_1"; type = "search" },
            @{ id = $errorsID; name = "panel_2"; type = "search" },
            @{ id = $warningsID; name = "panel_3"; type = "search" },
            @{ id = $infoID; name = "panel_4"; type = "search" },
            @{ id = $tracesID; name = "panel_5"; type = "search" }
        )
    }
}

Ensure-DataView

$objects = [System.Collections.Generic.List[object]]::new()
foreach ($workload in $workloads) {
    $baseQuery = $workload.Query
    $objects.Add((New-SearchObject -Workload $workload -Kind "recent" -Title "Recent Logs" -Query $baseQuery))
    $objects.Add((New-SearchObject `
        -Workload $workload `
        -Kind "errors" `
        -Title "Errors" `
        -Query "($baseQuery) AND log.level: error"))
    $objects.Add((New-SearchObject `
        -Workload $workload `
        -Kind "warnings" `
        -Title "Warnings" `
        -Query "($baseQuery) AND log.level: warn"))
    $objects.Add((New-SearchObject `
        -Workload $workload `
        -Kind "info" `
        -Title "Info" `
        -Query "($baseQuery) AND log.level: info"))
    $objects.Add((New-SearchObject `
        -Workload $workload `
        -Kind "traces" `
        -Title "Traced Events" `
        -Query "($baseQuery) AND trace_id: *"))
    $objects.Add((New-DashboardObject -Workload $workload))
}

$body = $objects | ConvertTo-Json -Depth 20
$result = Invoke-RestMethod `
    -Uri "$KibanaURL/api/saved_objects/_bulk_create?overwrite=true" `
    -Method Post `
    -Headers $headers `
    -ContentType "application/json" `
    -Body $body `
    -TimeoutSec 120

$failures = @($result.saved_objects | Where-Object { $_.error })
if ($failures.Count -gt 0) {
    $failures | ConvertTo-Json -Depth 8 | Write-Error
    throw "Kibana returned $($failures.Count) saved object errors"
}

$dashboardCount = @($result.saved_objects | Where-Object { $_.type -eq "dashboard" }).Count
$searchCount = @($result.saved_objects | Where-Object { $_.type -eq "search" }).Count
Write-Host "Created or updated $dashboardCount dashboards and $searchCount saved searches."
