param(
    [string]$Image = 'postgres:16-alpine',
    [ValidateRange(1, 600)][int]$MaximumRestoreSeconds = 120,
    [ValidateRange(1, 300)][int]$MaximumArchiveLagSeconds = 30
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$runId = [guid]::NewGuid().ToString('N').Substring(0, 12)
$prefix = "codex-pitr-$runId"
$source = "$prefix-source"
$restored = "$prefix-restored"
$network = "$prefix-net"
$label = "codex.recovery-drill=$runId"
$containers = [System.Collections.Generic.List[string]]::new()
$volumes = [System.Collections.Generic.List[string]]::new()
$networkCreated = $false
$result = [ordered]@{ run_id = $runId; image = $Image; status = 'failed' }

function Invoke-Docker {
    $output = & docker @args 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed ($LASTEXITCODE): $($output -join "`n")" }
    return ($output -join "`n").Trim()
}

function Invoke-ProbeSql([string]$Container, [string]$Sql) {
    return Invoke-Docker exec $Container psql -X -h 127.0.0.1 -U postgres -d recovery_drill -v ON_ERROR_STOP=1 -Atc $Sql
}

function Wait-Postgres([string]$Container, [bool]$RequirePromoted = $false) {
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        $ready = & docker exec $Container pg_isready -h 127.0.0.1 -U postgres -d recovery_drill 2>&1
        if ($LASTEXITCODE -eq 0) {
            if (-not $RequirePromoted) { return }
            if ((Invoke-ProbeSql $Container 'SELECT NOT pg_is_in_recovery()') -eq 't') { return }
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "PostgreSQL readiness timeout: $Container ($ready)"
}

try {
    [void](Invoke-Docker network create --label $label $network)
    $networkCreated = $true
    foreach ($suffix in @('source-data', 'archive', 'backup', 'restored-data')) {
        $volume = "$prefix-$suffix"
        [void](Invoke-Docker volume create --label $label $volume)
        $volumes.Add($volume)
    }
    [void](Invoke-Docker run --rm --entrypoint sh -v "${prefix}-archive:/archive" $Image -c 'chown postgres:postgres /archive; chmod 700 /archive')
    [void](Invoke-Docker run --detach --name $source --label $label --network $network `
        -e POSTGRES_DB=recovery_drill -e POSTGRES_HOST_AUTH_METHOD=trust `
        -v "${prefix}-source-data:/var/lib/postgresql/data" -v "${prefix}-archive:/archive" -v "${prefix}-backup:/backup" `
        $Image -c wal_level=replica -c archive_mode=on `
        -c 'archive_command=test -f /archive/%f || cp %p /archive/%f')
    $containers.Add($source)
    Wait-Postgres $source
    [void](Invoke-ProbeSql $source "CREATE TABLE recovery_probe(id text PRIMARY KEY, written_at timestamptz NOT NULL DEFAULT clock_timestamp()); INSERT INTO recovery_probe(id) VALUES('baseline')")
    [void](Invoke-Docker exec $source chown postgres:postgres /backup)
    [void](Invoke-Docker exec --user postgres $source pg_basebackup -h 127.0.0.1 -U postgres -D /backup -X stream -c fast)
    [void](Invoke-ProbeSql $source "INSERT INTO recovery_probe(id) VALUES('before-target')")
    [void](Invoke-ProbeSql $source "SELECT pg_create_restore_point('codex_recovery_target')")
    [void](Invoke-ProbeSql $source "INSERT INTO recovery_probe(id) VALUES('after-target')")
    $segment = Invoke-ProbeSql $source 'SELECT pg_walfile_name(pg_current_wal_lsn())'
    if ($segment -notmatch '^[0-9A-F]{24}$') { throw "Invalid WAL segment name: $segment" }
    [void](Invoke-ProbeSql $source 'SELECT pg_switch_wal()')
    $archiveDeadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        $archived = Invoke-ProbeSql $source "SELECT last_archived_wal='$segment' FROM pg_stat_archiver"
        if ($archived -eq 't') { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $archiveDeadline)
    if ($archived -ne 't') { throw 'WAL segment did not reach the independent archive volume' }
    $archiveLagText = Invoke-ProbeSql $source "SELECT GREATEST(0,EXTRACT(EPOCH FROM (last_archived_time-(SELECT written_at FROM recovery_probe WHERE id='after-target')))) FROM pg_stat_archiver"
    $archiveLag = [double]::Parse($archiveLagText, [Globalization.CultureInfo]::InvariantCulture)
    $result.observed_archive_lag_seconds = [math]::Round($archiveLag, 3)

    # После остановки исходного узла восстановление использует только backup и WAL.
    $timer = [Diagnostics.Stopwatch]::StartNew()
    [void](Invoke-Docker stop --time 5 $source)
    $restoreScript = @'
set -eu
cp -a /backup/. /restore/
cat >> /restore/postgresql.auto.conf <<'CONFIG'
restore_command = 'cp /archive/%f %p'
recovery_target_name = 'codex_recovery_target'
recovery_target_action = 'promote'
CONFIG
touch /restore/recovery.signal
chown -R postgres:postgres /restore
chmod 700 /restore
'@
    [void](Invoke-Docker run --rm --entrypoint sh -v "${prefix}-backup:/backup:ro" `
        -v "${prefix}-restored-data:/restore" $Image -c $restoreScript)
    [void](Invoke-Docker run --detach --name $restored --label $label --network $network `
        -v "${prefix}-restored-data:/var/lib/postgresql/data" -v "${prefix}-archive:/archive:ro" `
        $Image -c archive_mode=off)
    $containers.Add($restored)
    Wait-Postgres $restored $true
    $rows = Invoke-ProbeSql $restored "SELECT string_agg(id,',' ORDER BY id) FROM recovery_probe"
    $timer.Stop()
    $result.restore_duration_seconds = [math]::Round($timer.Elapsed.TotalSeconds, 3)
    $result.recovered_rows = $rows
    $result.target = 'codex_recovery_target'
    if ($rows -ne 'baseline,before-target') { throw "PITR contents mismatch: $rows" }
    if ($timer.Elapsed.TotalSeconds -gt $MaximumRestoreSeconds) { throw 'Restore duration exceeded the drill RTO budget' }
    if ($archiveLag -gt $MaximumArchiveLagSeconds) { throw 'Observed WAL archive lag exceeded the drill budget' }
    $result.status = 'passed'
    Write-Host "PITR passed: restore=$($result.restore_duration_seconds)s, observed archive lag=$($result.observed_archive_lag_seconds)s"
} catch {
    $result.error = $_.Exception.Message
    foreach ($container in $containers) { & docker logs --tail 50 $container 2>&1 | Write-Host }
    throw
} finally {
    $reportDir = Join-Path $repoRoot 'output/recovery'
    New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $reportDir "postgres-pitr-$runId.json") -Encoding utf8
    # Удаляем только ресурсы, созданные этим запуском и сохранившие его метку.
    foreach ($container in $containers) {
        $owner = & docker inspect --format '{{index .Config.Labels "codex.recovery-drill"}}' $container 2>$null
        if ($owner -eq $runId) { & docker rm --force $container 2>&1 | Out-Null }
    }
    foreach ($volume in $volumes) {
        $owner = & docker volume inspect --format '{{index .Labels "codex.recovery-drill"}}' $volume 2>$null
        if ($owner -eq $runId) { & docker volume rm $volume 2>&1 | Out-Null }
    }
    if ($networkCreated) {
        $owner = & docker network inspect --format '{{index .Labels "codex.recovery-drill"}}' $network 2>$null
        if ($owner -eq $runId) { & docker network rm $network 2>&1 | Out-Null }
    }
}
