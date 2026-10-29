#requires -Version 7.0
[CmdletBinding()]
param([string]$Make = 'make.exe')

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$dispatcher = Join-Path $repoRoot 'scripts/project.ps1'
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($dispatcher, [ref]$null, [ref]$errors) | Out-Null
if ($errors) { throw ($errors | Out-String) }

function Invoke-Make([string[]]$Arguments, [int]$ExpectedExit = 0) {
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Make -C $repoRoot --no-print-directory @Arguments 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    if ($code -ne $ExpectedExit) { throw "make $Arguments exited $code, expected $ExpectedExit`n$output" }
    return $output
}

$help = Invoke-Make @('help')
$tasks = @([regex]::Matches($help, '(?m)^  ([a-z][a-z-]+)\s+') | ForEach-Object { $_.Groups[1].Value })
if ($tasks.Count -lt 50) { throw 'Incomplete task inventory' }
foreach ($task in $tasks) {
    $output = Invoke-Make @($task, 'DRY_RUN=1', 'SERVICE=ticket')
    # Named arguments must exist in the real script, even for paths not executed here.
    foreach ($match in [regex]::Matches($output, '(?m)-File (.+?\.ps1)([^\r\n]*)')) {
        $scriptPath = $match.Groups[1].Value
        $scriptErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$scriptErrors)
        if ($scriptErrors) { throw "Invalid script: $scriptPath" }
        $names = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        foreach ($argument in [regex]::Matches($match.Groups[2].Value, '(?:^|\s)-([A-Za-z]+)(?=\s|$)')) {
            if ($names -notcontains $argument.Groups[1].Value) { throw "Unknown argument $($argument.Value) in $scriptPath" }
        }
    }
}

$ha = Invoke-Make @('deploy-ha', 'DRY_RUN=1', 'SKIP_BUILD=1', 'SKIP_IMPORT=1')
if ($ha -notmatch 'ENV=local-ha' -or $ha -notmatch '-SkipBuild' -or $ha -notmatch '-SkipImageImport') { throw 'HA flags were not forwarded' }
$dev = Invoke-Make @('deploy-apps', 'DRY_RUN=1', 'ENV=dev', 'IMAGE_TAG=sha-test', 'MIGRATOR_TAG=sha-test')
if ($dev -notmatch 'NAMESPACE=automatic-system-dev' -or $dev -notmatch '-Environment dev') { throw 'Dev environment was not forwarded' }
$api = Invoke-Make @('test-api', 'DRY_RUN=1', 'TEST_FILE=e2e/gateway-tickets-stateful.spec.ts', 'INCLUDE_SMTP=1', 'GATEWAY_URL=http://127.0.0.1:8081')
if ($api -notmatch '-TestFile e2e/gateway-tickets-stateful.spec.ts' -or $api -notmatch '-IncludeSMTP' -or $api -notmatch '-SkipSeed') { throw 'E2E flags were not forwarded' }
$format = Invoke-Make @('fmt-check', 'DRY_RUN=1', 'SERVICE=all')
if (([regex]::Matches($format, 'go list -f')).Count -ne 18) { throw 'Formatting did not cover all 18 workspace modules' }
$unit = Invoke-Make @('test-unit', 'DRY_RUN=1', 'SERVICE=API_Gateway')
if ($unit -notmatch 'API_Gateway' -or $unit -notmatch 'excluding node_modules and integration/e2e') { throw 'Unit module/package selection is incorrect' }

$invalidCases = @(
    @('test', 'DRY_RUN=1', 'SERVICE=not-a-service'),
    @('deploy', 'DRY_RUN=1', 'ENV=unknown'),
    @('deploy-apps', 'DRY_RUN=1', 'ENV=prod'),
    @('deploy-local', 'DRY_RUN=1', 'NAMESPACE=wrong'),
    @('deploy-ha', 'DRY_RUN=1', 'ENV=prod'),
    @('load', 'DRY_RUN=1', 'ALLOW_WRITES=yes'),
    @('logs', 'DRY_RUN=1', 'SERVICE=ticket', 'TAIL=invalid')
)
foreach ($arguments in $invalidCases) { Invoke-Make $arguments 2 | Out-Null }

# Exercise failure propagation and context protection using isolated command stubs.
$stubDirectory = Join-Path ([IO.Path]::GetTempPath()) ("automatic-system-make-tests-" + [guid]::NewGuid())
$savedPath = $env:PATH
try {
    New-Item -ItemType Directory -Path $stubDirectory | Out-Null
    Set-Content -LiteralPath (Join-Path $stubDirectory 'npx.cmd') -Value '@exit /b 9' -Encoding ascii
    Set-Content -LiteralPath (Join-Path $stubDirectory 'kubectl.cmd') -Value "@echo wrong-context`r`n@exit /b 0" -Encoding ascii
    $env:PATH = "$stubDirectory;$savedPath"
    $failedTool = Invoke-Make @('frontend-typecheck', 'DRY_RUN=0') 2
    if ($failedTool -notmatch 'exited with code 9') { throw 'Native command failure was not propagated' }
    $wrongContext = Invoke-Make @('deploy-ha', 'DRY_RUN=0', 'CONTEXT=expected-context') 2
    if ($wrongContext -notmatch 'context differs') { throw 'Context mismatch did not prevent deployment' }
} finally {
    $env:PATH = $savedPath
    # Remove only files created above, without recursive deletion.
    foreach ($file in @('npx.cmd', 'kubectl.cmd')) {
        $path = Join-Path $stubDirectory $file
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
    }
    if (Test-Path -LiteralPath $stubDirectory) { Remove-Item -LiteralPath $stubDirectory }
}
Write-Host "PASS: $($tasks.Count) targets, script parameters, module selection, flags, $($invalidCases.Count) invalid cases, native failure and context mismatch"
