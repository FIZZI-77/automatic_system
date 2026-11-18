[CmdletBinding()]
param(
    [string]$Namespace = "automatic-system",
    [string]$AdminEmail = "admin@automatic-system.dev",
    [string]$ReleaseName = "pgadmin",
    [string]$ChartVersion = "1.70.4",
    [switch]$GeneratePasswords
)

$ErrorActionPreference = "Stop"
$k8sRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$valuesFile = Join-Path $k8sRoot "base/observability/pgadmin-values.yaml"
$networkPolicyFile = Join-Path $k8sRoot "base/observability/pgadmin-network-policy.yaml"
$routeFile = Join-Path $k8sRoot "mesh/ingress/observability-routes.yaml"
$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ("pgadmin-setup-" + [guid]::NewGuid())

function Invoke-Kubectl {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    & kubectl @Arguments

    if ($LASTEXITCODE -ne 0) {
        throw "kubectl failed: kubectl $($Arguments -join ' ')"
    }
}

function Get-PlainText {
    param([Parameter(Mandatory = $true)][Security.SecureString]$SecureValue)

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)

    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function New-RandomPassword {
    $bytes = [byte[]]::new(32)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)

    try {
        return [Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Get-PrimaryPod {
    param([Parameter(Mandatory = $true)][string]$Selector)

    $pod = (& kubectl -n $Namespace get pod -l $Selector -o jsonpath='{.items[0].metadata.name}').Trim()

    if ($LASTEXITCODE -ne 0 -or -not $pod) {
        throw "Unable to find a primary PostgreSQL pod for selector '$Selector'."
    }

    return $pod
}

function Set-DatabaseViewerRole {
    param(
        [Parameter(Mandatory = $true)][string]$Pod,
        [Parameter(Mandatory = $true)][string]$Database,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $sql = @'
\set ON_ERROR_STOP on
SELECT format('CREATE ROLE pgadmin_viewer LOGIN PASSWORD %L', :'viewer_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pgadmin_viewer') \gexec
SELECT format('ALTER ROLE pgadmin_viewer PASSWORD %L', :'viewer_password') \gexec
ALTER ROLE pgadmin_viewer CONNECTION LIMIT 10;
ALTER ROLE pgadmin_viewer SET default_transaction_read_only = on;
GRANT pg_read_all_data, pg_monitor TO pgadmin_viewer;
'@

    $sql | & kubectl -n $Namespace exec -i $Pod -- psql `
        --username postgres `
        --dbname $Database `
        "--set=viewer_password=$Password"

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to configure pgadmin_viewer in pod '$Pod'."
    }
}

function Set-CitusViewerAuthInfo {
    param(
        [Parameter(Mandatory = $true)][string]$Pod,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $sql = @'
\set ON_ERROR_STOP on
INSERT INTO pg_dist_authinfo (nodeid, rolename, authinfo)
VALUES (0, 'pgadmin_viewer', format('password=%s', :'viewer_password'))
ON CONFLICT (nodeid, rolename)
DO UPDATE SET authinfo = EXCLUDED.authinfo;
'@

    $sql | & kubectl -n $Namespace exec -i $Pod -- psql `
        --username postgres `
        --dbname ticket_db `
        "--set=viewer_password=$Password"

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to configure Citus authentication in pod '$Pod'."
    }
}

if ($GeneratePasswords) {
    $adminPassword = New-RandomPassword
    $databasePassword = New-RandomPassword
}
else {
    $adminSecurePassword = Read-Host "Password for pgAdmin user $AdminEmail" -AsSecureString
    $databaseSecurePassword = Read-Host "Password for read-only database user pgadmin_viewer" -AsSecureString
    $adminPassword = Get-PlainText -SecureValue $adminSecurePassword
    $databasePassword = Get-PlainText -SecureValue $databaseSecurePassword
}

if ($adminPassword.Length -lt 12) {
    throw "The pgAdmin password must contain at least 12 characters."
}

if ($databasePassword.Length -lt 12) {
    throw "The database viewer password must contain at least 12 characters."
}

if ($databasePassword -notmatch '^[a-zA-Z0-9_-]+$') {
    throw "The database viewer password may contain only letters, digits, underscores, and hyphens."
}

New-Item -ItemType Directory -Force -Path $temporaryDirectory | Out-Null

try {
    $adminPasswordFile = Join-Path $temporaryDirectory "admin-password"
    $databasePasswordFile = Join-Path $temporaryDirectory "database-password"
    $pgpassFile = Join-Path $temporaryDirectory "pgpass"
    $escapedDatabasePassword = $databasePassword.Replace('\', '\\').Replace(':', '\:')
    $pgpass = @(
        "postgres-platform-primary.automatic-system.svc.cluster.local:5432:*:pgadmin_viewer:$escapedDatabasePassword"
        "postgres-ticket-primary.automatic-system.svc.cluster.local:5432:*:pgadmin_viewer:$escapedDatabasePassword"
    ) -join "`n"

    [IO.File]::WriteAllText($adminPasswordFile, $adminPassword, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($databasePasswordFile, $databasePassword, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($pgpassFile, ($pgpass + "`n"), [Text.UTF8Encoding]::new($false))

    $adminSecret = & kubectl -n $Namespace create secret generic pgadmin-admin `
        "--from-file=password=$adminPasswordFile" `
        --dry-run=client -o yaml

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to prepare pgadmin-admin Secret."
    }

    $adminSecret | & kubectl apply -f - | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to save pgadmin-admin Secret."
    }

    $databaseSecret = & kubectl -n $Namespace create secret generic pgadmin-database-viewer `
        "--from-file=password=$databasePasswordFile" `
        "--from-file=pgpass=$pgpassFile" `
        --dry-run=client -o yaml

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to prepare pgadmin-database-viewer Secret."
    }

    $databaseSecret | & kubectl apply -f - | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to save pgadmin-database-viewer Secret."
    }

    $platformPrimary = Get-PrimaryPod -Selector 'cluster-name=postgres-platform,role=primary'
    $ticketCoordinator = Get-PrimaryPod -Selector 'cluster-name=postgres-ticket-citus,citus-group=0,role=primary'
    $ticketWorker1 = Get-PrimaryPod -Selector 'cluster-name=postgres-ticket-citus,citus-group=1,role=primary'
    $ticketWorker2 = Get-PrimaryPod -Selector 'cluster-name=postgres-ticket-citus,citus-group=2,role=primary'

    Set-DatabaseViewerRole -Pod $platformPrimary -Database postgres -Password $databasePassword
    Set-DatabaseViewerRole -Pod $ticketCoordinator -Database ticket_db -Password $databasePassword
    Set-CitusViewerAuthInfo -Pod $ticketCoordinator -Password $databasePassword
    Set-CitusViewerAuthInfo -Pod $ticketWorker1 -Password $databasePassword
    Set-CitusViewerAuthInfo -Pod $ticketWorker2 -Password $databasePassword

    & helm repo add runix https://helm.runix.net --force-update | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to configure the runix Helm repository."
    }

    & helm repo update runix | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to update the runix Helm repository."
    }

    & helm upgrade $ReleaseName runix/pgadmin4 `
        --namespace $Namespace `
        --version $ChartVersion `
        --reset-values `
        --values $valuesFile `
        --wait `
        --timeout 10m

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to upgrade pgAdmin."
    }

    Invoke-Kubectl apply -f $networkPolicyFile | Out-Null
    Invoke-Kubectl apply -f $routeFile | Out-Null
    Invoke-Kubectl -n $Namespace rollout restart "deployment/$ReleaseName-pgadmin4" | Out-Null
    Invoke-Kubectl -n $Namespace rollout status "deployment/$ReleaseName-pgadmin4" --timeout=300s | Out-Null

    $pod = (& kubectl -n $Namespace get pod `
        -l "app.kubernetes.io/instance=$ReleaseName,app.kubernetes.io/name=pgadmin4" `
        -o jsonpath='{.items[0].metadata.name}').Trim()

    if ($LASTEXITCODE -ne 0 -or -not $pod) {
        throw "Unable to resolve the pgAdmin pod."
    }

    $usersJson = & kubectl -n $Namespace exec $pod -- /venv/bin/python /pgadmin4/setup.py `
        get-users --json 2>$null

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read the pgAdmin users."
    }

    $users = ($usersJson -join "`n") | ConvertFrom-Json
    $adminExists = $users | Where-Object { $_.email -eq $AdminEmail }

    if ($adminExists) {
        & kubectl -n $Namespace exec $pod -- /venv/bin/python /pgadmin4/setup.py `
            update-user $AdminEmail --password $adminPassword --admin --active | Out-Null

        if ($LASTEXITCODE -ne 0) {
            throw "Unable to update the pgAdmin administrator."
        }
    }
    else {
        & kubectl -n $Namespace exec $pod -- /venv/bin/python /pgadmin4/setup.py `
            add-user $AdminEmail $adminPassword --admin --active | Out-Null

        if ($LASTEXITCODE -ne 0) {
            throw "Unable to create the pgAdmin administrator."
        }
    }

    $usersJson = & kubectl -n $Namespace exec $pod -- /venv/bin/python /pgadmin4/setup.py `
        get-users --json 2>$null

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to verify the pgAdmin administrator."
    }

    $users = ($usersJson -join "`n") | ConvertFrom-Json
    $adminExists = $users | Where-Object { $_.email -eq $AdminEmail }

    if (-not $adminExists) {
        throw "pgAdmin did not create or update administrator '$AdminEmail'."
    }

    & kubectl -n $Namespace exec $pod -- /venv/bin/python /pgadmin4/setup.py `
        load-servers /pgadmin4/servers.json --user $AdminEmail --replace | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to load the managed pgAdmin server definitions."
    }

    if ($AdminEmail -ne "chart@domain.com") {
        & kubectl -n $Namespace exec $pod -- /venv/bin/python /pgadmin4/setup.py `
            delete-user chart@domain.com --yes 2>$null | Out-Null
    }

    & kubectl -n $Namespace exec $pod -- /usr/local/pgsql-16/psql `
        --host postgres-platform-primary.automatic-system.svc.cluster.local `
        --username pgadmin_viewer `
        --dbname postgres `
        --command 'SELECT current_database(), current_user, current_setting(''default_transaction_read_only'')' | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to verify the Platform PostgreSQL connection."
    }

    & kubectl -n $Namespace exec $pod -- /usr/local/pgsql-16/psql `
        --host postgres-ticket-primary.automatic-system.svc.cluster.local `
        --username pgadmin_viewer `
        --dbname ticket_db `
        --command 'SELECT current_database(), current_user, current_setting(''default_transaction_read_only''), (SELECT count(*) FROM tickets)' | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to verify the Ticket Citus connection."
    }

    & kubectl -n $Namespace exec $pod -- sh -ec `
        'test "$(wget -qO- http://127.0.0.1:80/observe/pgadmin/misc/ping)" = PING'

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to verify the pgAdmin health endpoint."
    }

    Write-Host "pgAdmin: https://fizzi.tail2c9430.ts.net/observe/pgadmin/"
    Write-Host "Admin email: $AdminEmail"
    Write-Host "Passwords are stored only in Kubernetes Secrets pgadmin-admin and pgadmin-database-viewer."
}
finally {
    $adminPassword = $null
    $databasePassword = $null
    $escapedDatabasePassword = $null

    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
