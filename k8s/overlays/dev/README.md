# Development overlay

Этот overlay предназначен для удалённого dev/staging окружения, куда CI может деплоить feature-ветки.

## Основные отличия

- Namespace: `automatic-system-dev`
- Образы берутся из GHCR по immutable tag `sha-<git-sha>`
- API Gateway публикуется как `LoadBalancer`
- MailHog и auxiliary-инфраструктура остаются включены
- HPA/PDB/production NetworkPolicy намеренно не включены
- Production secrets не используются; dev secrets должны создаваться отдельно

## Проверка

```powershell
kubectl kustomize .\k8s\overlays\dev
kubectl apply --dry-run=client -k .\k8s\overlays\dev
```

## Обновление image tag

```powershell
.\k8s\overlays\dev\set-image-tag.ps1
```

## Деплой

```powershell
kubectl apply -k .\k8s\overlays\dev
```

CI для `feature/*` может:
1. собрать образы;
2. запушить их в GHCR с `sha-<commit>`;
3. обновить tag;
4. применить этот overlay.

Если несколько feature-веток должны жить одновременно, лучше позже сделать preview-environments с namespace на основе имени ветки.
