$ErrorActionPreference = "Stop"
$k8sDir = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $k8sDir
Push-Location $repoRoot
try {
  $builds = @(
    @{Tag="automatic-system/api-gateway:dev"; Args="-f API_Gateway/Dockerfile ."},
    @{Tag="automatic-system/auth:dev"; Args="Auth_Service"},
    @{Tag="automatic-system/ticket:dev"; Args="Ticket_Service"},
    @{Tag="automatic-system/department:dev"; Args="Department_Service"},
    @{Tag="automatic-system/brigade:dev"; Args="Brigade_Service"},
    @{Tag="automatic-system/profile:dev"; Args="Profile_service"},
    @{Tag="automatic-system/location:dev"; Args="Location_Service"},
    @{Tag="automatic-system/routing:dev"; Args="Routing_Service"},
    @{Tag="automatic-system/dispatch:dev"; Args="-f Dispatch_Service/Dockerfile ."},
    @{Tag="automatic-system/file:dev"; Args="File_Service"},
    @{Tag="automatic-system/sla:dev"; Args="-f SLA_Service/Dockerfile ."},
    @{Tag="automatic-system/notification:dev"; Args="-f Notification_Service/Dockerfile ."},
    @{Tag="automatic-system/audit:dev"; Args="-f Audit_Service/Dockerfile ."},
    @{Tag="automatic-system/analytics:dev"; Args="-f Analytics_Service/Dockerfile ."},
    @{Tag="automatic-system/report:dev"; Args="-f Report_Service/Dockerfile ."},
    @{Tag="automatic-system/asset:dev"; Args="-f Asset_Service/Dockerfile ."},
    @{Tag="automatic-system/transponder-simulator:dev"; Args="Transponder_Simulator"}
  )
  foreach ($b in $builds) {
    Write-Host "Building $($b.Tag)"
    Invoke-Expression "docker build -t $($b.Tag) $($b.Args)"
    if ($LASTEXITCODE -ne 0) { throw "Failed to build $($b.Tag)" }
  }

  $services = @(
    "Auth_Service:auth","Ticket_Service:ticket","Department_Service:department","Brigade_Service:brigade",
    "Profile_service:profile","Location_Service:location","Routing_Service:routing","Dispatch_Service:dispatch",
    "File_Service:file","SLA_Service:sla","Notification_Service:notification","Audit_Service:audit",
    "Report_Service:report","Asset_Service:asset"
  )
  foreach ($item in $services) {
    $parts=$item.Split(':'); $dir=$parts[0]; $name=$parts[1]
    Write-Host "Building automatic-system/$name-migrator:dev"
    docker build -t "automatic-system/$name-migrator:dev" -f "$k8sDir/build/Dockerfile.migrator" --build-arg "MIGRATIONS_DIR=scheme" "$repoRoot/$dir"
    if ($LASTEXITCODE -ne 0) { throw "Failed to build automatic-system/$name-migrator:dev" }
  }

  Write-Host "Building automatic-system/analytics-clickhouse-init:dev"
  docker build -t automatic-system/analytics-clickhouse-init:dev -f "$k8sDir/build/Dockerfile.clickhouse-init" .
  if ($LASTEXITCODE -ne 0) { throw "Failed to build automatic-system/analytics-clickhouse-init:dev" }
  Write-Host "All images built successfully."
} finally { Pop-Location }
