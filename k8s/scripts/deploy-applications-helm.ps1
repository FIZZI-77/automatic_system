param(
    [ValidateSet("local", "local-ha", "dev", "prod")]
    [string]$Environment = "local",
    [string]$ImageTag,
    [string]$MigratorTag,
    [switch]$SkipMigrations,
    [switch]$TakeOwnership
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$helm = Join-Path $repoRoot ".tools\mesh\helm.exe"
$chart = Join-Path $repoRoot "k8s\helm\applications"
$namespace = if ($Environment -eq "dev") { "automatic-system-dev" } else { "automatic-system" }
$values = Join-Path $chart "values-$Environment.yaml"

if (-not (Test-Path -LiteralPath $helm)) { throw "Helm is missing at $helm" }

$arguments = @("upgrade", "--install", "applications", $chart, "--namespace", $namespace, "-f", $values, "--atomic", "--wait", "--timeout", "15m")
if ($TakeOwnership) { $arguments += "--take-ownership" }
if ($SkipMigrations) {
    $arguments += @(
        "--set", "migrations.enabled=false",
        "--set", "analyticsInit.enabled=false",
        "--set", "dispatch.migration.enabled=false"
    )
}

if ($Environment -in @("dev", "prod")) {
    if ([string]::IsNullOrWhiteSpace($ImageTag)) { throw "-ImageTag is required for $Environment" }
    if (-not $SkipMigrations -and [string]::IsNullOrWhiteSpace($MigratorTag)) { throw "-MigratorTag is required for $Environment" }
    $arguments += @("--set-string", "globalImage.tag=$ImageTag")
    if (-not $SkipMigrations) {
        $arguments += @(
            "--set-string", "migrations.tag=$MigratorTag",
            "--set-string", "analyticsInit.tag=$MigratorTag"
        )
    }
}

& $helm @arguments
if ($LASTEXITCODE -ne 0) { throw "Applications Helm release failed" }
& $helm status applications --namespace $namespace
