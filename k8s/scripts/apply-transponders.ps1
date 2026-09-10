$ErrorActionPreference = "Stop"
$k8sDir = Split-Path -Parent $PSScriptRoot
kubectl apply -k "$k8sDir/optional/transponders"
