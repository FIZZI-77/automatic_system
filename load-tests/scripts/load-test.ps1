param(
    [ValidateSet('baseline','read','write','mixed','saturation')][string]$Scenario = 'mixed',
    [int]$RPS = 100,
    [string]$Rates = '',
    [string]$BaseUrl = 'http://172.21.0.4',
    [string]$Warmup = '30s',
    [string]$Duration = '3m',
    [string]$Stabilization = '15s'
)

$ErrorActionPreference = 'Stop'
if ($BaseUrl -match '(?i)prod|production') { throw 'Production targets are forbidden.' }
$effectiveRates = if ($Rates) { $Rates } else { [string]$RPS }
$write = $Scenario -in @('write','mixed','saturation')
$args = @{
    Scenario = "ticket-$Scenario"
    Rates = $effectiveRates
    BaseUrl = $BaseUrl
    Warmup = $Warmup
    Measurement = $Duration
    Stabilization = $Stabilization
}
if ($write) { $args.AllowWrites = $true }
& (Join-Path $PSScriptRoot 'run.ps1') @args
