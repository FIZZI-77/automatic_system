[CmdletBinding()]
param(
    [string]$PublicUrl = "https://fizzi.tail2c9430.ts.net"
)

$url = "$($PublicUrl.TrimEnd('/'))/observe/"
Start-Process $url
Write-Host "Observability: $url"
