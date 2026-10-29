#requires -Version 7.0
[CmdletBinding()]
param([string]$Task = 'help')

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$env:GOCACHE = Join-Path $repoRoot '.gocache'
$shell = (Get-Process -Id $PID).Path
$helm = Join-Path $repoRoot '.tools/mesh/helm.exe'
$frontend = Join-Path $repoRoot 'Frontend'

function Get-Option([string]$Name, [string]$Default = '') {
    $value = [Environment]::GetEnvironmentVariable("ACS_$Name")
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

function Get-Flag([string]$Name) {
    $value = Get-Option $Name '0'
    if ($value -notin @('0', '1')) { throw "$Name must be 0 or 1" }
    return $value -eq '1'
}

function Get-PositiveInt([string]$Name, [int]$Default) {
    $number = 0
    if (-not [int]::TryParse((Get-Option $Name "$Default"), [ref]$number) -or $number -lt 1) {
        throw "$Name must be a positive integer"
    }
    return $number
}

$dryRun = Get-Flag 'DRY_RUN'
$environment = Get-Option 'ENV' 'local'
if ($environment -notin @('local', 'local-ha', 'dev', 'prod')) { throw 'ENV must be local, local-ha, dev or prod' }
$defaultNamespace = if ($environment -eq 'dev') { 'automatic-system-dev' } else { 'automatic-system' }
$namespace = Get-Option 'NAMESPACE' $defaultNamespace
if ($namespace -notmatch '^[a-z0-9][a-z0-9-]*$') { throw 'Invalid NAMESPACE' }

$descriptions = [ordered]@{
    help = 'Show commands and parameters'
    doctor = 'Check tools, Docker daemon and Kubernetes access'
    bootstrap = 'Download Go and frontend dependencies (no tool installation)'
    'deps-go' = 'Download dependencies of selected Go modules'
    'deps-frontend' = 'Install frontend dependencies with npm ci'
    'go-build' = 'Build Go packages in selected modules without running services'
    fmt = 'Format Go files of selected modules'
    'fmt-check' = 'Check Go formatting without modifying files'
    vet = 'Run go vet in selected modules'
    test = 'Run all default Go tests; some packages require Docker'
    'test-unit' = 'Run Go tests outside dedicated integration/e2e packages'
    'test-integration' = 'Run Go tests with integration build tag; needs dependencies'
    'test-compile' = 'Compile Go tests without running them'
    'test-tools' = 'Test Make targets, argument forwarding and validation without deployment'
    lint = 'Go vet, frontend ESLint and TypeScript'
    check = 'Formatting, vet, frontend lint/types, OpenAPI and inventory; no cluster'
    'frontend-dev' = 'Start frontend development server'
    'frontend-build' = 'Build frontend'
    'frontend-test' = 'Build frontend and run rendered HTML tests'
    'frontend-lint' = 'Run frontend ESLint'
    'frontend-typecheck' = 'Run TypeScript without emitting files'
    'test-inventory' = 'Run static OpenAPI inventory without Gateway or seed'
    'test-api' = 'Run cluster API E2E; optional TEST_FILE and INCLUDE_SMTP=1'
    'test-ui' = 'Start Compose stack and run UI E2E; needs DEMO_PASSWORD'
    'test-ui-ha' = 'Run local HA UI E2E; needs DEMO_PASSWORD'
    'test-report' = 'Open Playwright HTML report'
    up = 'Build and start Docker Compose'
    down = 'Stop Docker Compose, retaining volumes'
    'compose-config' = 'Validate Compose configuration without printing secrets'
    'compose-status' = 'Show Compose containers'
    'compose-logs' = 'Show Compose logs; SERVICE, FOLLOW and TAIL'
    'simulation-up' = 'Start Compose with transponder simulation profile'
    build = 'Build existing Kubernetes application and migrator images'
    deploy = 'Deploy ENV using existing scripts; Kubernetes must already exist'
    'deploy-local' = 'Deploy simple local stack to existing Kubernetes'
    'deploy-ha' = 'Build/import images and deploy local HA stack'
    'deploy-infra' = 'Deploy local HA infrastructure without applications'
    'deploy-apps' = 'Deploy Helm applications for ENV; tags required for dev/prod'
    'cluster-check' = 'Show context and check Kubernetes API and nodes'
    'cluster-status' = 'Show nodes, pods, services, jobs, PVC and canaries'
    status = 'Alias for cluster-status'
    logs = 'Show Kubernetes logs for SERVICE; FOLLOW and TAIL'
    'rollout-status' = 'Wait for application deployments and stateful sets'
    'cluster-verify' = 'Check rollouts and run cluster API E2E'
    'cluster-delete' = 'Delete namespace via existing interactive DELETE confirmation'
    'mesh-install' = 'Install Istio/Kiali; supported ENV=local or prod'
    'metrics-install' = 'Install Metrics Server'
    'ingress-setup' = 'Configure local ingress and trusted certificate'
    'flux-install' = 'Install Flux controllers without enabling Git sync'
    'flux-sync' = 'Install Flux and enable existing local HA Git sync'
    'flux-status' = 'Show Flux sources, kustomizations and Helm releases'
    observability = 'Open existing public observability URL in browser'
    'observability-password' = 'Set Basic Auth password using hidden prompt'
    'pgadmin-setup' = 'Install/configure pgAdmin using existing script'
    'funnel-setup' = 'Configure existing Tailscale Funnel publication'
    'dashboards-generate' = 'Generate tracked Grafana dashboards'
    'dashboards-import' = 'Download configured Grafana community dashboards'
    'kibana-setup' = 'Configure Kibana through existing script and its defaults'
    'transponders-apply' = 'Apply optional Kubernetes transponders'
    seed = 'Seed demo data; ENV=local uses Compose, local-ha uses Kubernetes'
    'seed-analytics' = 'Seed analytics volume in Kubernetes; SCALE controls size'
    openapi = 'Generate API Gateway OpenAPI'
    'openapi-check' = 'Check generated OpenAPI matches source'
    'manifests-render' = 'Render selected Kustomize overlay without applying it'
    'helm-check' = 'Lint and render applications chart with ENV values'
    'docs-context' = 'Refresh ignored Repomix compact context'
    'load-prepare' = 'Generate deterministic load fixtures (seed 77, count 100)'
    load = 'Run k6 scenario; writes require ALLOW_WRITES=1'
    'load-suite' = 'Run local suite; temporarily replaces Gateway image, needs DEMO_PASSWORD'
    'test-chaos' = 'Run destructive local HA chaos; requires EXECUTE=1 and DEMO_PASSWORD'
    'test-k6-chaos' = 'Run Kubernetes k6; EXECUTE=1 also enables chaos'
}

function Invoke-Tool([string]$Name, [string[]]$Arguments = @()) {
    Write-Host ("[{0}] {1} {2}" -f (Get-Location).Path, $Name, ($Arguments -join ' '))
    if ($dryRun) { return }
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) { throw "Missing tool: $Name" }
    & $Name @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Name exited with code $LASTEXITCODE" }
}

function Invoke-Script([string]$RelativePath, [hashtable]$Parameters = @{}) {
    $path = Join-Path $repoRoot $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing script: $RelativePath" }
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $path)
    foreach ($name in ($Parameters.Keys | Sort-Object)) {
        $value = $Parameters[$name]
        if ($value -is [bool]) {
            if ($value) { $arguments += "-$name" }
        } elseif ($null -ne $value -and "$value" -ne '') {
            $arguments += "-$name"
            $arguments += $value
        }
    }
    Invoke-Tool $shell $arguments
}

function Invoke-Frontend([string[]]$Arguments) {
    Push-Location $frontend
    try { Invoke-Tool 'npm.cmd' $Arguments } finally { Pop-Location }
}

function Get-Modules {
    $modules = @(Get-Content (Join-Path $repoRoot 'go.work') | ForEach-Object {
        if ($_ -match '^\s*(\.|\./[A-Za-z_]+|[A-Za-z_]+)\s*$') {
            $relative = $Matches[1] -replace '^\./', ''
            $directory = Join-Path $repoRoot $relative
            if (Test-Path (Join-Path $directory 'go.mod')) { $relative }
        }
    })
    if ($modules.Count -eq 0) { throw 'No Go modules found in go.work' }
    $service = Get-Option 'SERVICE' 'all'
    if ($service -eq 'all') { return $modules }
    $selected = @($modules | Where-Object {
        $_ -ieq $service -or ($_ -replace '_Service$', '' -replace '_', '-') -ieq $service -or
        ($_ -eq '.' -and $service -eq 'root')
    })
    if ($selected.Count -ne 1) { throw "Unknown SERVICE '$service'. Use all, root or a module name from go.work (short names like ticket also work)." }
    return $selected
}

function Invoke-GoTask([string]$Action) {
    :modules foreach ($module in @(Get-Modules)) {
        Push-Location (Join-Path $repoRoot $module)
        try {
            $arguments = @()
            switch ($Action) {
                'deps-go' { $arguments = @('mod', 'download') }
                'go-build' { $arguments = @('build') }
                'vet' { $arguments = @('vet') }
                { $_ -in @('fmt', 'fmt-check') } {
                    if ($dryRun) {
                        Invoke-Tool 'go' @('list', '-f', '{{.Dir}}', '-tags=integration', './...')
                        Write-Host "gofmt $Action on Go files in listed package directories"
                        continue modules
                    }
                    $directories = @(& go list -f '{{.Dir}}' -tags=integration ./... | Where-Object { $_ -notmatch '[\\/]node_modules[\\/]' })
                    if ($LASTEXITCODE -ne 0) { throw "go list failed in $module" }
                    foreach ($directory in $directories) {
                        $files = @(Get-ChildItem -LiteralPath $directory -Filter '*.go' -File | ForEach-Object FullName)
                        if ($files.Count -eq 0) { continue }
                        if ($Action -eq 'fmt') { Invoke-Tool 'gofmt' (@('-w') + $files) }
                        else {
                            $unformatted = & gofmt -l @files
                            if ($LASTEXITCODE -ne 0) { throw "gofmt failed in $module" }
                            if ($unformatted) { throw "Unformatted files: $($unformatted -join ', ')" }
                        }
                    }
                    continue modules
                }
                default {
                    $arguments = @('test', '-count=1')
                    if (Get-Flag 'RACE') { $arguments += '-race' }
                    if ($Action -eq 'test-compile') { $arguments += @('-run', '^$') }
                    elseif (Get-Option 'TEST_RUN') { $arguments += @('-run', (Get-Option 'TEST_RUN')) }
                    if ($Action -eq 'test-integration') { $arguments += @('-tags=integration', '-timeout=15m') }
                }
            }
            if ($Action -ne 'deps-go') {
                if ($dryRun) {
                    Invoke-Tool 'go' @('list', './...')
                    $arguments += if ($Action -eq 'test-unit') { '<packages excluding node_modules and integration/e2e>' } else { '<packages excluding node_modules>' }
                } else {
                    $listArguments = @('list')
                    if ($Action -eq 'test-integration') { $listArguments += '-tags=integration' }
                    $listArguments += './...'
                    $packages = @(& go @listArguments | Where-Object {
                        $_ -notmatch '/node_modules/' -and ($Action -ne 'test-unit' -or $_ -notmatch '/(integration|e2e)(/|$)')
                    })
                    if ($LASTEXITCODE -ne 0) { throw "go list failed in $module" }
                    if ($packages.Count -eq 0) { throw "No Go packages selected in $module" }
                    $arguments += $packages
                }
            }
            Invoke-Tool 'go' $arguments
        } finally { Pop-Location }
    }
}

function Show-ClusterTarget {
    Write-Host "ENV=$environment NAMESPACE=$namespace EXPECTED_CONTEXT=$(Get-Option 'CONTEXT' '(current)')"
    if ($dryRun) { return }
    $context = & kubectl config current-context
    if ($LASTEXITCODE -ne 0) { throw 'Unable to read Kubernetes context' }
    Write-Host "Current context: $context"
    if ((Get-Option 'CONTEXT') -and $context -ne (Get-Option 'CONTEXT')) { throw 'Kubernetes context differs from CONTEXT; no context was switched' }
}

function Require-Namespace([string]$Expected) {
    if ($namespace -ne $Expected) { throw "This script targets '$Expected'; NAMESPACE=$namespace is not supported" }
}

function Get-Workload {
    $service = Get-Option 'SERVICE' 'all'
    if ($service -eq 'frontend') { return 'frontend' }
    $module = @(Get-Modules)
    if ($module.Count -ne 1 -or $module[0] -in @('.', 'Transponder_Simulator')) { throw 'Select one deployed SERVICE, for example ticket or api-gateway' }
    if ($module[0] -eq 'API_Gateway') { return 'api-gateway' }
    return (($module[0] -replace '_Service$', '') + '-service').ToLowerInvariant()
}

function Invoke-Task([string]$Name) {
    switch ($Name) {
        'help' {
            Write-Host 'Automatic City Services - GNU Make + PowerShell'
            foreach ($entry in $descriptions.GetEnumerator()) { Write-Host ('  {0,-25} {1}' -f $entry.Key, $entry.Value) }
            Write-Host "`nSERVICE=all|root|ticket|API_Gateway ENV=local|local-ha|dev|prod DRY_RUN=1"
            Write-Host 'CONTEXT, NAMESPACE, IMAGE_TAG, MIGRATOR_TAG, SKIP_BUILD, SKIP_IMPORT, SKIP_MIGRATIONS'
            Write-Host 'TEST_FILE, TEST_RUN, GATEWAY_URL, SKIP_SEED, HEADED, INCLUDE_SMTP, RACE'
            Write-Host 'FOLLOW, TAIL, BASE_URL, SCENARIO, RATES, WARMUP, MEASUREMENT, STABILIZATION'
            Write-Host 'SCENARIO_FILTER, ALLOW_WRITES, EXECUTE, PUBLIC_URL, USERNAME, SCALE'
            Write-Host 'Set DEMO_PASSWORD in your environment; do not put passwords on the make command line.'
        }
        'doctor' {
            $missing = @()
            foreach ($tool in @('git', 'go', 'node', 'npm.cmd', 'docker', 'kubectl')) {
                $command = Get-Command $tool -ErrorAction SilentlyContinue
                if ($command) { Write-Host "OK $tool -> $($command.Source)" }
                else { $missing += $tool; Write-Host "MISSING $tool" }
            }
            Write-Host "Helm: $helm (present=$(Test-Path -LiteralPath $helm))"
            if ($missing.Count -gt 0 -and -not $dryRun) { throw "Missing tools: $($missing -join ', ')" }
            Invoke-Tool 'docker' @('info', '--format', '{{.ServerVersion}}')
            Invoke-Task 'cluster-check'
        }
        'bootstrap' { Invoke-Task 'deps-go'; Invoke-Task 'deps-frontend' }
        { $_ -in @('deps-go', 'go-build', 'fmt', 'fmt-check', 'vet', 'test', 'test-unit', 'test-integration', 'test-compile') } { Invoke-GoTask $Name }
        'deps-frontend' { Invoke-Frontend @('ci') }
        'test-tools' { Invoke-Script 'scripts/tests/project.test.ps1' }
        'lint' { Invoke-Task 'vet'; Invoke-Task 'frontend-lint'; Invoke-Task 'frontend-typecheck' }
        'check' { foreach ($step in @('fmt-check', 'lint', 'openapi-check', 'test-inventory')) { Invoke-Task $step } }
        'frontend-dev' { Invoke-Frontend @('run', 'dev') }
        'frontend-build' { Invoke-Frontend @('run', 'build') }
        'frontend-test' { Invoke-Frontend @('test') }
        'frontend-lint' { Invoke-Frontend @('run', 'lint') }
        'frontend-typecheck' { Push-Location $frontend; try { Invoke-Tool 'npx.cmd' @('--no-install', 'tsc', '--noEmit', '--incremental', 'false') } finally { Pop-Location } }
        'test-inventory' { Push-Location $frontend; try { Invoke-Tool 'npx.cmd' @('--no-install', 'playwright', 'test', '--config', 'playwright.inventory.config.ts', '--project', 'desktop-chromium') } finally { Pop-Location } }
        'test-api' {
            Show-ClusterTarget
            $parameters = @{ Namespace = $namespace; GatewayUrl = Get-Option 'GATEWAY_URL'; SkipSeed = Get-Flag 'SKIP_SEED'; IncludeSMTP = Get-Flag 'INCLUDE_SMTP' }
            if (Get-Option 'TEST_FILE') { $parameters.TestFile = Get-Option 'TEST_FILE' }
            Invoke-Script 'scripts/run-api-gateway-e2e.ps1' $parameters
        }
        'test-ui' { Invoke-Script 'scripts/run-e2e.ps1' @{ SkipBuild = Get-Flag 'SKIP_BUILD'; Headed = Get-Flag 'HEADED' } }
        'test-ui-ha' { Require-Namespace 'automatic-system'; Show-ClusterTarget; Invoke-Script 'k8s/scripts/run-local-ha-e2e.ps1' @{ SkipSeed = Get-Flag 'SKIP_SEED'; Headed = Get-Flag 'HEADED' } }
        'test-report' { Invoke-Frontend @('run', 'e2e:report') }
        'up' { $arguments = @('compose', 'up', '-d'); if (-not (Get-Flag 'SKIP_BUILD')) { $arguments += '--build' }; Invoke-Tool 'docker' $arguments }
        'down' { Invoke-Tool 'docker' @('compose', 'down') }
        'compose-config' { Invoke-Tool 'docker' @('compose', 'config', '--quiet') }
        'compose-status' { Invoke-Tool 'docker' @('compose', 'ps') }
        'compose-logs' {
            $arguments = @('compose', 'logs', '--tail', (Get-PositiveInt 'TAIL' 100))
            if (Get-Flag 'FOLLOW') { $arguments += '--follow' }
            if ((Get-Option 'SERVICE' 'all') -ne 'all') { $arguments += Get-Option 'SERVICE' }
            Invoke-Tool 'docker' $arguments
        }
        'simulation-up' { Invoke-Tool 'docker' @('compose', '--profile', 'simulation', 'up', '-d', '--build') }
        'build' { Invoke-Script 'k8s/scripts/build-images.ps1' }
        'deploy' { if ($environment -eq 'local') { Invoke-Task 'deploy-local' } elseif ($environment -eq 'local-ha') { Invoke-Task 'deploy-ha' } else { throw 'For dev/prod, prepare infrastructure using deployment.md and use deploy-apps with image tags' } }
        'deploy-local' { if ($environment -ne 'local') { throw 'deploy-local requires ENV=local' }; Require-Namespace 'automatic-system'; Show-ClusterTarget; Invoke-Script 'k8s/scripts/apply.ps1' }
        { $_ -in @('deploy-ha', 'deploy-infra') } {
            if ($environment -ne 'local-ha') { throw "$Name requires ENV=local-ha" }
            Require-Namespace 'automatic-system'; Show-ClusterTarget
            Invoke-Script 'k8s/scripts/start-local-ha.ps1' @{ SkipBuild = Get-Flag 'SKIP_BUILD'; SkipImageImport = Get-Flag 'SKIP_IMPORT'; SkipApplications = ($Name -eq 'deploy-infra') }
        }
        'deploy-apps' {
            Require-Namespace $defaultNamespace; Show-ClusterTarget
            if ($environment -in @('dev', 'prod') -and -not (Get-Option 'IMAGE_TAG')) { throw 'IMAGE_TAG is required for dev/prod' }
            if ($environment -in @('dev', 'prod') -and -not (Get-Flag 'SKIP_MIGRATIONS') -and -not (Get-Option 'MIGRATOR_TAG')) { throw 'MIGRATOR_TAG is required for dev/prod migrations' }
            Invoke-Script 'k8s/scripts/deploy-applications-helm.ps1' @{ Environment = $environment; ImageTag = Get-Option 'IMAGE_TAG'; MigratorTag = Get-Option 'MIGRATOR_TAG'; SkipMigrations = Get-Flag 'SKIP_MIGRATIONS' }
        }
        'cluster-check' { Show-ClusterTarget; Invoke-Tool 'kubectl' @('cluster-info', '--request-timeout=10s'); Invoke-Tool 'kubectl' @('get', 'nodes', '--request-timeout=10s') }
        { $_ -in @('cluster-status', 'status') } {
            Show-ClusterTarget
            Invoke-Tool 'kubectl' @('get', 'nodes')
            Invoke-Tool 'kubectl' @('-n', $namespace, 'get', 'pods,services,jobs,pvc')
            if ($dryRun) { Write-Host 'Also list canaries if the Flagger CRD is installed' }
            else {
                $resources = & kubectl api-resources -o name
                if ($LASTEXITCODE -ne 0) { throw 'Unable to discover Kubernetes resources' }
                if ($resources -contains 'canaries.flagger.app') { Invoke-Tool 'kubectl' @('-n', $namespace, 'get', 'canaries.flagger.app') }
                else { Write-Host 'Flagger CRD is not installed in this cluster' }
            }
        }
        'logs' { Show-ClusterTarget; $arguments = @('-n', $namespace, 'logs', "deployment/$(Get-Workload)", '--all-containers=true', '--tail', (Get-PositiveInt 'TAIL' 100)); if (Get-Flag 'FOLLOW') { $arguments += '--follow' }; Invoke-Tool 'kubectl' $arguments }
        'rollout-status' {
            Show-ClusterTarget
            if ((Get-Option 'SERVICE' 'all') -ne 'all') { Invoke-Tool 'kubectl' @('-n', $namespace, 'rollout', 'status', "deployment/$(Get-Workload)", '--timeout=600s') }
            else {
                if ($dryRun) {
                    Invoke-Tool 'kubectl' @('-n', $namespace, 'get', 'deployments,statefulsets', '-o', 'name')
                    Write-Host 'kubectl rollout status <each returned workload> --timeout=600s'
                } else {
                    $workloads = @(& kubectl -n $namespace get deployments,statefulsets -o name)
                    if ($LASTEXITCODE -ne 0) { throw 'Unable to list workloads' }
                    if ($workloads.Count -eq 0) { throw "No workloads found in $namespace" }
                    foreach ($workload in $workloads) { Invoke-Tool 'kubectl' @('-n', $namespace, 'rollout', 'status', $workload, '--timeout=600s') }
                }
            }
        }
        'cluster-verify' { Invoke-Task 'rollout-status'; Invoke-Task 'test-api' }
        'cluster-delete' { Require-Namespace 'automatic-system'; Show-ClusterTarget; Invoke-Script 'k8s/scripts/delete-local.ps1' }
        'mesh-install' { Show-ClusterTarget; if ($environment -notin @('local', 'prod')) { throw 'mesh-install supports ENV=local or prod' }; Invoke-Script 'k8s/scripts/install-mesh.ps1' @{ Environment = $environment } }
        'metrics-install' { Show-ClusterTarget; Invoke-Script 'k8s/scripts/install-metrics-server.ps1' }
        'ingress-setup' { Show-ClusterTarget; Invoke-Script 'k8s/scripts/setup-ingress.ps1' @{ Namespace = $namespace } }
        'flux-install' { Show-ClusterTarget; Invoke-Script 'k8s/scripts/install-flux.ps1' }
        'flux-sync' { Require-Namespace 'automatic-system'; Show-ClusterTarget; Invoke-Script 'k8s/scripts/install-flux.ps1' @{ ConfigureLocalHASync = $true } }
        'flux-status' { Show-ClusterTarget; Invoke-Tool 'kubectl' @('-n', 'flux-system', 'get', 'gitrepositories,kustomizations,helmreleases') }
        'observability' { Invoke-Script 'k8s/scripts/open-observability.ps1' @{ PublicUrl = Get-Option 'PUBLIC_URL' 'https://fizzi.tail2c9430.ts.net' } }
        'observability-password' { Show-ClusterTarget; Invoke-Script 'k8s/scripts/set-observability-password.ps1' @{ Username = Get-Option 'USERNAME' 'admin' } }
        'pgadmin-setup' { Show-ClusterTarget; Invoke-Script 'k8s/scripts/setup-pgadmin.ps1' @{ Namespace = $namespace } }
        'funnel-setup' { Show-ClusterTarget; Invoke-Script 'k8s/scripts/setup-tailscale-funnel.ps1' @{ Namespace = $namespace } }
        'dashboards-generate' { Invoke-Script 'k8s/scripts/generate-grafana-dashboards.ps1' }
        'dashboards-import' { Invoke-Script 'k8s/scripts/import-grafana-community-dashboards.ps1' }
        'kibana-setup' { Invoke-Script 'k8s/scripts/setup-kibana-dashboards.ps1' }
        'transponders-apply' { Require-Namespace 'automatic-system'; Show-ClusterTarget; Invoke-Script 'k8s/scripts/apply-transponders.ps1' }
        'seed' {
            if ($environment -notin @('local', 'local-ha')) { throw 'seed supports ENV=local (Compose) or local-ha (Kubernetes)' }
            $target = if ($environment -eq 'local-ha') { 'Kubernetes' } else { 'Compose' }
            if ($target -eq 'Kubernetes') { Show-ClusterTarget }
            Invoke-Script 'scripts/seed-demo-data.ps1' @{ Target = $target; Namespace = $namespace; BaseUrl = Get-Option 'BASE_URL' 'http://localhost:8081' }
        }
        'seed-analytics' { Show-ClusterTarget; Invoke-Script 'scripts/seed-analytics-volume.ps1' @{ Namespace = $namespace; Scale = Get-PositiveInt 'SCALE' 1000; SkipDemoSeed = Get-Flag 'SKIP_SEED' } }
        { $_ -in @('openapi', 'openapi-check') } { Push-Location (Join-Path $repoRoot 'API_Gateway'); try { $arguments = @('run', './tools/openapi'); if ($Name -eq 'openapi-check') { $arguments += '-check' }; Invoke-Tool 'go' $arguments } finally { Pop-Location } }
        'manifests-render' { Invoke-Tool 'kubectl' @('kustomize', "k8s/overlays/$environment") }
        'helm-check' { $values = "k8s/helm/applications/values-$environment.yaml"; Invoke-Tool $helm @('lint', 'k8s/helm/applications', '-f', $values); Invoke-Tool $helm @('template', 'applications', 'k8s/helm/applications', '--namespace', $namespace, '-f', $values) }
        'docs-context' { Invoke-Tool 'repomix.cmd' @('--config', 'repomix.config.json') }
        'load-prepare' { Invoke-Tool 'node' @('load-tests/data/generators/generate.js', '77', '100') }
        'load' { Invoke-Script 'load-tests/scripts/run.ps1' @{ Scenario = Get-Option 'SCENARIO' 'gateway'; Rates = Get-Option 'RATES' '10,25,50'; BaseUrl = Get-Option 'BASE_URL' 'http://localhost:8081'; Warmup = Get-Option 'WARMUP' '5s'; Measurement = Get-Option 'MEASUREMENT' '20s'; Stabilization = Get-Option 'STABILIZATION' '5s'; AllowWrites = Get-Flag 'ALLOW_WRITES' } }
        'load-suite' { Show-ClusterTarget; Invoke-Script 'load-tests/scripts/run-local-suite.ps1' @{ Namespace = $namespace; ParallelRates = Get-Option 'RATES' '10,25,50'; ScenarioFilter = Get-Option 'SCENARIO_FILTER'; Warmup = Get-Option 'WARMUP' '5s'; Measurement = Get-Option 'MEASUREMENT' '20s'; Stabilization = Get-Option 'STABILIZATION' '5s'; AllowWrites = Get-Flag 'ALLOW_WRITES' } }
        'test-chaos' { Require-Namespace 'automatic-system'; Show-ClusterTarget; Invoke-Script 'k8s/scripts/run-local-ha-chaos.ps1' @{ Execute = Get-Flag 'EXECUTE' } }
        'test-k6-chaos' { Require-Namespace 'automatic-system'; Show-ClusterTarget; Invoke-Script 'k8s/scripts/run-k6-chaos.ps1' @{ ExecuteChaos = Get-Flag 'EXECUTE' } }
        default { throw "Unknown task '$Name'. Run make help." }
    }
}

Push-Location $repoRoot
try { Invoke-Task $Task } finally { Pop-Location }
