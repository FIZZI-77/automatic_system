# Production overlay

Overlay собран поверх текущих `k8s/base/*` манифестов ветки `test`.

Что добавлено:
- API Gateway: 2 replicas, HPA, PDB, topology spread.
- GHCR images с immutable `sha-<git-sha>` tag.
- PDB для Kafka и Redis Sentinel quorum.
- Базовые ingress NetworkPolicy.
- MailHog и production secrets намеренно не подключаются.

Перед применением:
1. Образы с указанным SHA должны существовать в GHCR.
2. `kubectl top pods` должен работать, иначе HPA не получит метрики.
3. `runtime-secrets`, JWT secrets и прочие production secrets создаются отдельно.
4. Resource values для Gateway — стартовый baseline; финальный tuning делается по Prometheus.
5. PVC/storage здесь не переопределяются до выбора production StorageClass и backup policy.

Проверка:
```powershell
kubectl kustomize .\k8s\overlays\prod
kubectl apply --dry-run=client -k .\k8s\overlays\prod
```

Обновить tag под текущий commit:
```powershell
.\k8s\overlays\prod\set-image-tag.ps1
```

Не применяй prod overlay поверх текущего local окружения в том же namespace, если не хочешь заменить local workloads.
