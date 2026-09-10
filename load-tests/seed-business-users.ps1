param(
    [int]$Count = 10,
    [string]$BaseUrl = "http://localhost:8081",
    [string]$Password = "Password123!",
    [string]$Role = "admin",
    [string]$OutputPath = "load-tests/users.json"
)

$ErrorActionPreference = "Stop"

function Invoke-JsonPost {
    param(
        [string]$Url,
        [hashtable]$Body,
        [hashtable]$Headers = @{},
        [int]$MaxAttempts = 6
    )

    $json = $Body | ConvertTo-Json -Depth 20
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return Invoke-WebRequest -Uri $Url -Method POST -Body $json -ContentType "application/json" -Headers $Headers -UseBasicParsing
        }
        catch {
            $status = $_.Exception.Response.StatusCode.value__
            if (($status -eq 429 -or $status -eq 503 -or $status -eq 504) -and $attempt -lt $MaxAttempts) {
                Start-Sleep -Seconds ([Math]::Min(10, $attempt * 2))
                continue
            }
            throw
        }
    }
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null

$users = @()
for ($i = 1; $i -le $Count; $i++) {
    $suffix = "{0:D4}" -f $i
    $email = "k6-business-$suffix@load.local"
    $username = "k6biz$suffix"

    try {
        Invoke-JsonPost -Url "$BaseUrl/auth/register" -Body @{
            email = $email
            password = $Password
            username = $username
        } | Out-Null
        Write-Host "registered $email"
    }
    catch {
        $status = $_.Exception.Response.StatusCode.value__
        if ($status -eq 409) {
            Write-Host "already exists $email"
        }
        else {
            throw
        }
    }

    $users += [ordered]@{
        email = $email
        password = $Password
        client_id = "k6-business-$suffix"
    }
}

$sql = @"
INSERT INTO roles (name, description)
VALUES ('$Role', 'Load-test $Role role')
ON CONFLICT (name) DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u
CROSS JOIN roles r
WHERE u.email LIKE 'k6-business-%@load.local'
  AND r.name = '$Role'
ON CONFLICT (user_id, role_id) DO NOTHING;
"@

$sql | docker compose exec -T postgres-auth psql -U postgres -d authdb

$json = $users | ConvertTo-Json -Depth 20
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Resolve-Path -LiteralPath $OutputPath).Path, $json, $utf8NoBom)
Write-Host "wrote $OutputPath"
