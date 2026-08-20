$ErrorActionPreference = "Stop"
$k8sDir = $PSScriptRoot
$ns="automatic-system"
kubectl apply -f $k8sDir/manifests/00-namespace-secrets.yaml
if (-not (kubectl -n $ns get secret jwt-private-key --ignore-not-found)) { throw "Create jwt-private-key first; see README.md" }
if (-not (kubectl -n $ns get secret jwt-public-key --ignore-not-found)) { throw "Create jwt-public-key first; see README.md" }
kubectl apply -f $k8sDir/manifests/10-postgres.yaml
 kubectl apply -f $k8sDir/manifests/11-redis.yaml
 kubectl apply -f $k8sDir/manifests/12-kafka.yaml
 kubectl apply -f $k8sDir/manifests/13-infra.yaml
Write-Host "Waiting for core stateful infrastructure..."
kubectl -n $ns wait --for=condition=Ready pod --all --timeout=900s
# Jobs are immutable: delete old completed/failed versions before re-run.
kubectl -n $ns delete job --all --ignore-not-found
kubectl apply -f $k8sDir/manifests/20-migrations.yaml
$jobs=@("kafka-init","migrator-auth","migrator-ticket","migrator-department","migrator-brigade","migrator-profile","migrator-location","migrator-routing","migrator-dispatch","migrator-file","migrator-sla","migrator-notification","migrator-audit","migrator-report","migrator-asset","clickhouse-init")
foreach($j in $jobs){ kubectl -n $ns wait --for=condition=complete "job/$j" --timeout=600s }
kubectl apply -f $k8sDir/manifests/30-apps.yaml
kubectl apply -f $k8sDir/manifests/31-gateway.yaml
# Optional simulators:
# kubectl apply -f $k8sDir/manifests/32-transponders.yaml
Write-Host "Done. Check: kubectl -n $ns get pods,svc"