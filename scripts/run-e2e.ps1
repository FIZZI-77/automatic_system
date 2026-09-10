param(
    [switch]$SkipBuild,
    [switch]$Headed
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

Push-Location $repoRoot
try {
    docker compose up -d
    if (-not $SkipBuild) {
        docker compose -f Frontend/compose.yml up -d --build
    } else {
        docker compose -f Frontend/compose.yml up -d
    }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot/seed-demo-data.ps1"
    if ($LASTEXITCODE -ne 0) { throw "Не удалось подготовить тестовые данные" }

    Push-Location "$repoRoot/Frontend"
    try {
        if ($Headed) { npm run e2e:headed } else { npm run e2e }
        if ($LASTEXITCODE -ne 0) { throw "E2E-тесты завершились с ошибкой" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}
