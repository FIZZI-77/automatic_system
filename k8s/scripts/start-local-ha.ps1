param(
    [switch]$SkipBuild,
    [switch]$SkipImageImport,
    [switch]$ResetSecrets,
    [switch]$ResetData,
    [switch]$SkipApplications
)

$ErrorActionPreference = "Stop"
$namespace = "automatic-system"
$k8sRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $k8sRoot
$overlayRoot = Join-Path $k8sRoot "overlays/local-ha"

function Invoke-Kubectl {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    & kubectl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "kubectl failed: $($Arguments -join ' ')"
    }
}

function New-LocalPassword {
    return [guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")
}

function Wait-StatefulSet {
    param([string]$Name, [int]$TimeoutSeconds = 900)

    Invoke-Kubectl -n $namespace rollout status "statefulset/$Name" "--timeout=${TimeoutSeconds}s"
}

function Wait-Deployment {
    param([string]$Name, [int]$TimeoutSeconds = 600)

    Invoke-Kubectl -n $namespace rollout status "deployment/$Name" "--timeout=${TimeoutSeconds}s"
}

function Wait-Job {
    param([string]$Name, [int]$TimeoutSeconds = 900)

    Invoke-Kubectl -n $namespace wait --for=condition=complete "job/$Name" "--timeout=${TimeoutSeconds}s"
}

function Set-RuntimeSecret {
    $platformSuperuser = New-LocalPassword
    $platformReplication = New-LocalPassword
    $ticketSuperuser = New-LocalPassword
    $ticketReplication = New-LocalPassword
    $minioPassword = New-LocalPassword
    $clickHousePassword = New-LocalPassword
    $reportToken = New-LocalPassword

    $databaseUsers = [ordered]@{
        AUTH = "auth_user"
        DEPARTMENT = "department_user"
        BRIGADE = "brigade_user"
        PROFILE = "profile_user"
        LOCATION = "location"
        ROUTING = "routing"
        DISPATCH = "dispatch"
        FILE = "file"
        SLA = "sla"
        NOTIFICATION = "notification"
        AUDIT = "audit"
        REPORT = "report"
        ASSET = "asset"
    }
    $databaseNames = [ordered]@{
        AUTH = "auth_db"
        DEPARTMENT = "department_db"
        BRIGADE = "brigade_db"
        PROFILE = "profile_db"
        LOCATION = "location"
        ROUTING = "routing"
        DISPATCH = "dispatch"
        FILE = "file"
        SLA = "sla"
        NOTIFICATION = "notification"
        AUDIT = "audit"
        REPORT = "report"
        ASSET = "asset"
    }

    $secretValues = [ordered]@{
        PLATFORM_POSTGRES_SUPERUSER_PASSWORD = $platformSuperuser
        PLATFORM_POSTGRES_REPLICATION_PASSWORD = $platformReplication
        TICKET_POSTGRES_SUPERUSER_PASSWORD = $ticketSuperuser
        TICKET_POSTGRES_REPLICATION_PASSWORD = $ticketReplication
        MINIO_ROOT_USER = "automatic-system"
        MINIO_ROOT_PASSWORD = $minioPassword
        S3_ACCESS_KEY = "automatic-system"
        S3_SECRET_KEY = $minioPassword
        CLICKHOUSE_PASSWORD = $clickHousePassword
        REPORT_INTERNAL_TOKEN = $reportToken
        SMTP_PASSWORD = ""
        REDIS_PASSWORD = ""
        REDIS_SENTINEL_PASSWORD = ""
        TRANSPONDER_API_KEY = "local-ha-transponder"
    }

    foreach ($service in $databaseUsers.Keys) {
        $password = New-LocalPassword
        $user = $databaseUsers[$service]
        $database = $databaseNames[$service]
        $secretValues["${service}_DB_PASSWORD"] = $password
        $secretValues["${service}_GOOSE_DBSTRING"] = "postgres://${user}:${password}@postgres-platform-primary:5432/${database}?sslmode=disable"

        if ($service -in @("LOCATION", "ROUTING", "DISPATCH", "FILE", "SLA", "NOTIFICATION", "AUDIT", "REPORT", "ASSET")) {
            $secretValues["${service}_DATABASE_URL"] = "postgres://${user}:${password}@pgbouncer-platform-primary:6432/${database}?sslmode=disable"
            $secretValues["${service}_READ_DATABASE_URL"] = "postgres://${user}:${password}@pgbouncer-platform-replicas:6432/${database}?sslmode=disable"
        }
    }

    $ticketPassword = New-LocalPassword
    $secretValues["TICKET_DB_PASSWORD"] = $ticketPassword
    $secretValues["TICKET_GOOSE_DBSTRING"] = "postgres://ticket_user:${ticketPassword}@postgres-ticket-primary:5432/ticket_db?sslmode=disable"

    $arguments = @("create", "secret", "generic", "runtime-secrets", "--namespace=$namespace")
    foreach ($entry in $secretValues.GetEnumerator()) {
        $arguments += "--from-literal=$($entry.Key)=$($entry.Value)"
    }
    $arguments += @("--dry-run=client", "--output=yaml")

    & kubectl @arguments | kubectl apply -f -
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to create runtime-secrets"
    }
}

function Set-JwtSecrets {
    $privateKey = Join-Path $repoRoot "keys/private.pem"
    $publicKey = Join-Path $repoRoot "keys/public.pem"
    if (-not (Test-Path -LiteralPath $privateKey) -or -not (Test-Path -LiteralPath $publicKey)) {
        throw "JWT keys are missing under $repoRoot\keys"
    }

    Invoke-Kubectl -n $namespace delete secret jwt-private-key jwt-public-key --ignore-not-found
    Invoke-Kubectl -n $namespace create secret generic jwt-private-key "--from-file=private.pem=$privateKey"
    Invoke-Kubectl -n $namespace create secret generic jwt-public-key "--from-file=public.pem=$publicKey"
}

function Build-Images {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "build-images.ps1")
    if ($LASTEXITCODE -ne 0) {
        throw "Application image build failed"
    }

    $extraBuilds = @(
        @{ Dockerfile = "Frontend/Dockerfile"; Tag = "automatic-system/frontend:dev"; Context = "Frontend" },
        @{ Dockerfile = "k8s/build/postgres-ha/Dockerfile"; Tag = "automatic-system-postgres-ha:dev-psy" },
        @{ Dockerfile = "k8s/build/postgres-citus-ha/Dockerfile"; Tag = "automatic-system-postgres-citus-ha:dev-psy" },
        @{ Dockerfile = "k8s/build/pgbouncer/Dockerfile"; Tag = "automatic-system-pgbouncer:dev" },
        @{ Dockerfile = "k8s/build/kubectl/Dockerfile"; Tag = "automatic-system-kubectl:dev-shell" }
    )
    foreach ($build in $extraBuilds) {
        $buildContext = $repoRoot
        if ($build.Context) {
            $buildContext = Join-Path $repoRoot $build.Context
        }

        & docker build --file (Join-Path $repoRoot $build.Dockerfile) --tag $build.Tag $buildContext
        if ($LASTEXITCODE -ne 0) {
            throw "Image build failed: $($build.Tag)"
        }
    }
}

function Import-ImagesToNodes {
    $images = @(
        "automatic-system/api-gateway:dev",
        "automatic-system/auth:dev",
        "automatic-system/ticket:dev",
        "automatic-system/department:dev",
        "automatic-system/brigade:dev",
        "automatic-system/profile:dev",
        "automatic-system/location:dev",
        "automatic-system/routing:dev",
        "automatic-system/dispatch:dev",
        "automatic-system/file:dev",
        "automatic-system/sla:dev",
        "automatic-system/notification:dev",
        "automatic-system/audit:dev",
        "automatic-system/analytics:dev",
        "automatic-system/report:dev",
        "automatic-system/asset:dev",
        "automatic-system/transponder-simulator:dev",
        "automatic-system/frontend:dev",
        "automatic-system-postgres-ha:dev-psy",
        "automatic-system-postgres-citus-ha:dev-psy",
        "automatic-system-pgbouncer:dev",
        "automatic-system-kubectl:dev-shell",
        "automatic-system/analytics-clickhouse-init:dev"
    )
    foreach ($service in @(
        "auth", "ticket", "department", "brigade", "profile", "location", "routing",
        "dispatch", "file", "sla", "notification", "audit", "report", "asset"
    )) {
        $images += "automatic-system/${service}-migrator:dev"
    }

    $nodes = @(
        & kubectl get nodes --output=name |
            ForEach-Object { $_ -replace '^node/', '' }
    )
    if ($LASTEXITCODE -ne 0 -or $nodes.Count -eq 0) {
        throw "Unable to list Kubernetes nodes"
    }
    foreach ($node in $nodes) {
        if (-not $node) {
            continue
        }
        & docker inspect $node | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Kubernetes node '$node' is not a local Docker container"
        }

        Write-Host "Streaming local images into $node..."
        $quotedImages = ($images | ForEach-Object { '"' + $_ + '"' }) -join ' '
        $importCommand = "docker image save $quotedImages | docker exec --interactive `"$node`" ctr --namespace k8s.io images import -"
        & cmd.exe /d /s /c $importCommand
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to import images into node '$node'"
        }
    }
}

Push-Location $repoRoot
try {
    Invoke-Kubectl cluster-info
    & (Join-Path $PSScriptRoot "install-metrics-server.ps1")
    if ($LASTEXITCODE -ne 0) {
        throw "Metrics Server installation failed"
    }

    if (-not $SkipBuild) {
        Build-Images
    }
    if (-not $SkipImageImport) {
        Import-ImagesToNodes
    }

    if ($ResetData) {
        Write-Host "Deleting namespace '$namespace' and all local cluster data..."
        Invoke-Kubectl delete namespace $namespace --ignore-not-found --wait=true "--timeout=300s"
    }

    Invoke-Kubectl apply -k (Join-Path $k8sRoot "base/namespace")
    $secretExists = & kubectl -n $namespace get secret runtime-secrets --ignore-not-found --output=name
    $platformDataExists = & kubectl -n $namespace get pvc -l "app.kubernetes.io/name=postgres-platform" --ignore-not-found --output=name
    if ($ResetSecrets -and $platformDataExists -and -not $ResetData) {
        throw "Refusing to rotate database secrets while PostgreSQL data exists. Use -ResetData for a clean local cluster."
    }
    if ($ResetData -or $ResetSecrets -or -not $secretExists) {
        Set-RuntimeSecret
        Set-JwtSecrets
    }

    Invoke-Kubectl apply `
        --server-side `
        --force-conflicts `
        --field-manager=automatic-system `
        -k $overlayRoot
    foreach ($statefulSet in @(
        "postgres-platform",
        "coordinator-ticket-citus",
        "worker-1-ticket-citus",
        "worker-2-ticket-citus",
        "minio"
    )) {
        Wait-StatefulSet $statefulSet
    }

    Invoke-Kubectl apply -k (Join-Path $overlayRoot "support")
    foreach ($statefulSet in @(
        "redis-gateway",
        "redis-notification",
        "redis-location-master",
        "redis-location-replica-1",
        "redis-location-replica-2",
        "redis-location-sentinel",
        "kafka-1",
        "kafka-2",
        "kafka-3",
        "clickhouse"
    )) {
        Wait-StatefulSet $statefulSet
    }
    Write-Host "Valhalla bootstrap continues asynchronously because initial map download depends on Geofabrik availability."
    foreach ($deployment in @("mailhog")) {
        Wait-Deployment $deployment
    }

    Invoke-Kubectl -n $namespace delete job -l automatic-system.io/job-type=migration --ignore-not-found
    Invoke-Kubectl -n $namespace delete job -l automatic-system.io/job-type=init --ignore-not-found
    Invoke-Kubectl apply -k (Join-Path $overlayRoot "migrations")
    foreach ($job in @(
        "kafka-init",
        "migrator-auth",
        "migrator-ticket",
        "migrator-department",
        "migrator-brigade",
        "migrator-profile",
        "migrator-location",
        "migrator-routing",
        "migrator-dispatch",
        "migrator-file",
        "migrator-sla",
        "migrator-notification",
        "migrator-audit",
        "migrator-report",
        "migrator-asset",
        "clickhouse-init"
    )) {
        Wait-Job $job
    }

    Invoke-Kubectl -n $namespace delete job postgres-ticket-citus-distribute --ignore-not-found --wait=true
    Invoke-Kubectl apply -f (Join-Path $k8sRoot "overlays/prod/infra/postgres-ticket-citus/distribution-job.yaml")
    Wait-Job "postgres-ticket-citus-distribute"

    if (-not $SkipApplications) {
        Invoke-Kubectl apply -k (Join-Path $overlayRoot "apps")
        foreach ($deployment in @(
            "auth-service",
            "ticket-service",
            "department-service",
            "brigade-service",
            "profile-service",
            "location-service",
            "routing-service",
            "dispatch-service",
            "file-service",
            "sla-service",
            "notification-service",
            "audit-service",
            "analytics-service",
            "report-service",
            "asset-service",
            "api-gateway",
            "frontend"
        )) {
            Wait-Deployment $deployment
        }
    }

    Write-Host "Local HA deployment is ready."
    Invoke-Kubectl -n $namespace get pods
} finally {
    Pop-Location
}
