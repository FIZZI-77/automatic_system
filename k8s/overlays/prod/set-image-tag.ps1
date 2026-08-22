$ErrorActionPreference = "Stop"

$prodDir = $PSScriptRoot
$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $prodDir))

Push-Location $repoRoot
try {
    $sha = (git rev-parse --short=12 HEAD).Trim()
    if (-not $sha) { throw "Unable to determine git SHA" }

    $tag = "sha-$sha"
    $targets = @(
        (Join-Path $prodDir "apps\kustomization.yaml"),
        (Join-Path $prodDir "migrations\kustomization.yaml")
    )

    foreach ($file in $targets) {
        $content = Get-Content $file -Raw
        $content = $content -replace 'newTag:\s*sha-[0-9a-fA-F]+', "newTag: $tag"
        Set-Content -Path $file -Value $content -NoNewline
        Write-Host "Updated $file -> $tag"
    }
}
finally {
    Pop-Location
}
