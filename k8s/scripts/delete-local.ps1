$ErrorActionPreference = "Stop"
Write-Warning "This deletes the automatic-system namespace. PVC retention behavior depends on the cluster/storage class."
$answer = Read-Host "Type DELETE to continue"
if ($answer -ne "DELETE") { Write-Host "Cancelled"; exit 0 }
kubectl delete namespace automatic-system
