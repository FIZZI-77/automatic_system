[CmdletBinding()]
param(
    [string]$PublicUrl = "https://fizzi.tail2c9430.ts.net"
)

$url = "$($PublicUrl.TrimEnd('/'))/observe/"
$pgAdminUrl = "$($PublicUrl.TrimEnd('/'))/observe/pgadmin/"
Start-Process $url
Write-Host "Observability: $url"
Write-Host "pgAdmin: $pgAdminUrl"
