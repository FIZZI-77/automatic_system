$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$dashboardDirectory = Join-Path $repoRoot "k8s\base\observability\dashboards\community"

$dashboards = @(
  @{ ID = 9628; Revision = 8; File = "postgresql-database.json"; UID = "community-postgresql"; Title = "Community / PostgreSQL Database" },
  @{ ID = 763; Revision = 6; File = "redis-exporter.json"; UID = "community-redis"; Title = "Community / Redis Exporter" },
  @{ ID = 24565; Revision = 1; File = "kafka-exporter.json"; UID = "community-kafka"; Title = "Community / Kafka Exporter" },
  @{ ID = 24155; Revision = 6; File = "kubernetes-overview.json"; UID = "community-kubernetes"; Title = "Community / Kubernetes Overview" },
  @{ ID = 1860; Revision = 45; File = "node-exporter-full.json"; UID = "community-node-exporter"; Title = "Community / Node Exporter Full" },
  @{ ID = 3070; Revision = 3; File = "etcd-prometheus.json"; UID = "community-etcd"; Title = "Community / etcd" },
  @{ ID = 3662; Revision = 2; File = "prometheus-overview.json"; UID = "community-prometheus"; Title = "Community / Prometheus Overview" },
  @{ ID = "clickhouse-official"; SourceUri = "https://raw.githubusercontent.com/ClickHouse/clickhouse-mixin/main/dashboard.json"; File = "clickhouse-official.json"; UID = "community-clickhouse"; Title = "Community / ClickHouse Official" },
  @{ ID = "minio-official"; SourceUri = "https://raw.githubusercontent.com/minio/minio/master/docs/metrics/prometheus/grafana/minio-dashboard.json"; File = "minio-official.json"; UID = "community-minio"; Title = "Community / MinIO Official" }
)

function Remove-WindowsTargets {
  param([object[]]$Panels)

  foreach ($panel in $Panels) {
    if ($panel.PSObject.Properties['targets']) {
      $panel.targets = @(
        $panel.targets | Where-Object {
          -not $_.expr -or $_.expr -notmatch '\bwindows_[a-zA-Z0-9_:]+'
        }
      )
    }
    if ($panel.PSObject.Properties['panels']) {
      Remove-WindowsTargets -Panels $panel.panels
    }
  }
}

function Remove-UnsupportedTargets {
  param(
    [object[]]$Panels,
    [string[]]$MetricPatterns
  )

  foreach ($panel in $Panels) {
    if ($panel.PSObject.Properties['targets']) {
      $panel.targets = @(
        $panel.targets | Where-Object {
          $expression = [string]$_.expr
          -not ($MetricPatterns | Where-Object { $expression -match $_ })
        }
      )
    }
    if ($panel.PSObject.Properties['panels']) {
      Remove-UnsupportedTargets -Panels $panel.panels -MetricPatterns $MetricPatterns
    }
  }
}

function Add-ZeroFallbacks {
  param([object[]]$Panels)

  foreach ($panel in $Panels) {
    foreach ($target in @($panel.targets)) {
      if ($target.expr -match 'container_oom_events_total|kube_pod_container_status_restarts_total') {
        $target.expr = "($($target.expr)) or vector(0)"
      }
    }
    if ($panel.PSObject.Properties['panels']) {
      Add-ZeroFallbacks -Panels $panel.panels
    }
  }
}

function Add-ZeroFallbacksToAllTargets {
  param([object[]]$Panels)

  foreach ($panel in $Panels) {
    foreach ($target in @($panel.targets)) {
      if ($target.expr -and $target.expr -notmatch '\bor\s+vector\(0\)\s*$') {
        $target.expr = "($($target.expr)) or vector(0)"
      }
    }
    if ($panel.PSObject.Properties['panels']) {
      Add-ZeroFallbacksToAllTargets -Panels $panel.panels
    }
  }
}

function Adapt-ClickHouseTargets {
  param([object[]]$Panels)

  foreach ($panel in $Panels) {
    foreach ($target in @($panel.targets)) {
      if ($target.expr) {
        $target.expr = $target.expr.Replace(
          'ClickHouse_ServiceInfo{clickhouse_service="$service_id"}',
          'up{job="clickhouse"}'
        )
        $target.expr = $target.expr.Replace(
          'clickhouse_service="$service_id"',
          'job="clickhouse"'
        )
        $target.expr = $target.expr.Replace('clickhouse_service', 'instance')
      }
      if ($target.legendFormat) {
        $target.legendFormat = $target.legendFormat.Replace('clickhouse_service', 'instance')
      }
    }
    if ($panel.PSObject.Properties['panels']) {
      Adapt-ClickHouseTargets -Panels $panel.panels
    }
  }
}

New-Item -ItemType Directory -Path $dashboardDirectory -Force | Out-Null
$obsoleteDashboard = Join-Path $dashboardDirectory "node-exporter-full.json"
if (Test-Path -LiteralPath $obsoleteDashboard) {
  Remove-Item -LiteralPath $obsoleteDashboard -Force
}

foreach ($dashboard in $dashboards) {
  if ($dashboard.SourceUri) {
    $uri = $dashboard.SourceUri
    Write-Host "Downloading official dashboard $($dashboard.ID)..."
  } else {
    $uri = "https://grafana.com/api/dashboards/$($dashboard.ID)/revisions/$($dashboard.Revision)/download"
    Write-Host "Downloading Grafana dashboard $($dashboard.ID), revision $($dashboard.Revision)..."
  }
  $raw = (Invoke-WebRequest -Uri $uri -UseBasicParsing).Content
  $raw = $raw.Replace('${DS_PROMETHEUS}', 'prometheus')
  $raw = $raw.Replace('${DS_PROM}', 'prometheus')
  $raw = $raw.Replace('${DS_THEMIS}', 'prometheus')
  $raw = $raw.Replace('${VAR_PROMETHEUS}', 'prometheus')
  $raw = $raw.Replace('${DS_LOCAL_PROMETHEUS}', 'prometheus')
  if ($dashboard.ID -eq 24565) {
    $raw = $raw.Replace('pod=~\"kafka-cluster.*\"', 'pod=~\"kafka-[1-3]-0\"')
  }
  if ($dashboard.ID -eq 9628) {
    $raw = $raw.Replace('release=\"$release\", ', '')
    $raw = $raw.Replace(', release=\"$release\"', '')
    $raw = $raw.Replace('release=\"$release\"', 'job=\"postgres-exporter\"')
    $raw = $raw.Replace('instance=\"$instance\"', 'instance=~\"$instance\"')
  }
  if ($dashboard.ID -eq 24155) {
    $raw = $raw.Replace('${datasource}', 'prometheus')
    $raw = $raw.Replace('cluster_name=\"$cluster\", ', '')
    $raw = $raw.Replace(', cluster_name=\"$cluster\"', '')
    $raw = $raw.Replace('cluster_name=\"$cluster\"', 'job=~\".+\"')
    $raw = $raw.Replace('job=\"$job\"', 'job=\"node-exporter\"')
  }
  if ($dashboard.ID -eq 'clickhouse-official') {
    $raw = $raw.Replace('${datasource}', 'prometheus')
  }
  $model = $raw | ConvertFrom-Json
  if ($dashboard.ID -eq 24565) {
    $namespaceVariable = $model.templating.list |
      Where-Object { $_.name -eq 'namespace' }
    $namespaceVariable.current = [pscustomobject]@{
      selected = $true
      text = 'automatic-system'
      value = 'automatic-system'
    }
  }
  if ($dashboard.ID -in 1860, 3070, 3662) {
    Add-ZeroFallbacksToAllTargets -Panels $model.panels
    Add-ZeroFallbacksToAllTargets -Panels $model.rows
  }
  if ($dashboard.ID -eq 'clickhouse-official') {
    $model.templating.list = @()
    Adapt-ClickHouseTargets -Panels $model.panels
    Add-ZeroFallbacksToAllTargets -Panels $model.panels
  }
  if ($dashboard.ID -eq 'minio-official') {
    $scrapeJobVariable = $model.templating.list | Where-Object { $_.name -eq 'scrape_jobs' }
    $scrapeJobVariable.includeAll = $false
    $scrapeJobVariable.multi = $false
    $scrapeJobVariable.regex = '^minio$'
    $scrapeJobVariable.current = [pscustomobject]@{
      selected = $true
      text = 'minio'
      value = 'minio'
    }
    Add-ZeroFallbacksToAllTargets -Panels $model.panels
  }
  if ($dashboard.ID -eq 24155) {
    $model.templating.list = @(
      $model.templating.list | Where-Object { $_.name -notin 'cluster', 'datasource' }
    )
    Remove-WindowsTargets -Panels $model.panels
    Remove-UnsupportedTargets -Panels $model.panels -MetricPatterns @(
      'node_cpu_core_throttles_total',
      'resource=~\"\.\*gpu\.\*\"',
      'sum\(max_over_time',
      'kube_(namespace_labels|service_info|endpoint_info|ingress_info|deployment_labels|statefulset_labels|daemonset_labels|hpa_labels|configmap_info|secret_info|networkpolicy_labels)'
    )
    Add-ZeroFallbacks -Panels $model.panels
  }
  if ($dashboard.ID -eq 9628) {
    Remove-UnsupportedTargets -Panels $model.panels -MetricPatterns @(
      'pg_postmaster_start_time_seconds'
    )
  }
  if ($model.PSObject.Properties['id']) {
    $model.id = $null
  } else {
    $model | Add-Member -NotePropertyName id -NotePropertyValue $null
  }
  if ($model.PSObject.Properties['uid']) {
    $model.uid = $dashboard.UID
  } else {
    $model | Add-Member -NotePropertyName uid -NotePropertyValue $dashboard.UID
  }
  if ($model.PSObject.Properties['title']) {
    $model.title = $dashboard.Title
  } else {
    $model | Add-Member -NotePropertyName title -NotePropertyValue $dashboard.Title
  }
  $model.PSObject.Properties.Remove('__inputs')
  $model.PSObject.Properties.Remove('__requires')

  $path = Join-Path $dashboardDirectory $dashboard.File
  $json = $model | ConvertTo-Json -Depth 100 -Compress
  if ($json -match '\$\{DS_[^}]+\}') {
    throw "Unresolved datasource placeholder in $($dashboard.File): $($Matches[0])"
  }
  [System.IO.File]::WriteAllText($path, $json + [Environment]::NewLine)
}

Write-Host "Community dashboards are stored in $dashboardDirectory"
