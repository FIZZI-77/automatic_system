param([int]$Seed = 77, [int]$Count = 100)
$ErrorActionPreference='Stop'
if ($env:LOAD_TEST_ALLOW_DESTRUCTIVE -ne 'true') { throw 'Fixture preparation requires LOAD_TEST_ALLOW_DESTRUCTIVE=true' }
node (Join-Path $PSScriptRoot '..\data\generators\generate.js') $Seed $Count
