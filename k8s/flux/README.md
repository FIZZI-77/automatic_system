# Flux CD для локального отказоустойчивого контура

Flux согласует Helm-выпуск приложений, Flagger, входящие маршруты и политики
Istio. StatefulSet с данными, секреты, резервные копии и первичная подготовка
остаются вне этого контура. Миграционные Job приложений создаются Helm как часть
прикладного выпуска, а не отдельным ресурсом Flux Kustomization.

## Предварительные условия

- Kubernetes и Istio доступны; необходимые CRD Flagger установлены.
- В `automatic-system` уже созданы `runtime-secrets` и ключи JWT.
- Самостоятельный исполнитель GitHub Actions использует
  `ServiceAccount/github-runner` в `arc-runners`.
- Ветка `deploy/local` содержит проверенный снимок `k8s/flux` и Helm-чарта.

## Установка

Из корня репозитория:

```powershell
.\k8s\scripts\install-flux.ps1
```

Команда устанавливает закрепленную версию контроллеров и права исполнителя,
но без `-ConfigureLocalHASync` не включает источник Git.
Рабочий процесс CI публикует проверенный снимок в `deploy/local`, дожидается
его появления в GitRepository и запускает согласование.

Ручное первоначальное включение:

```powershell
.\k8s\scripts\install-flux.ps1 -ConfigureLocalHASync
kubectl patch kustomization automatic-system-local-ha `
  -n flux-system `
  --type merge `
  -p '{"spec":{"suspend":false}}'
```

## Границы владения

| Ресурс | Пространство объекта | Что он создает |
|---|---|---|
| `GitRepository/automatic-system` | `flux-system` | Снимок ветки `deploy/local`. |
| `Kustomization/automatic-system-local-ha` | `flux-system` | Flagger, HelmRelease приложений и отдельные Kustomization Istio. |
| `HelmRelease/applications` | `flux-system` | Ресурсы чарта в `automatic-system`. |
| `HelmRelease/flagger` | `flux-system` | Контроллер в `flagger-system`. |
| `HelmRelease/flagger-loadtester` | `flux-system` | Генератор трафика в `automatic-system`. |
| `automatic-system-mesh-policies`, `automatic-system-mesh-ingress` | `flux-system` | Политики и маршруты в `automatic-system`. |

Общие значения выпуска генерируются из
`clusters/local-ha/applications-values.yaml`. CI изменяет группы
неизменяемых меток образов и записывает снимок в `deploy/local` с
`[skip ci]`. Исходные ветки CI не изменяет. `test`, `feature` и
`feature/**` используют одну ветку развертывания и одну очередь, поскольку
направлены в один кластер.

`prune: true` удаляет исчезнувшие **управляемые Flux** ресурсы. Не добавляйте
сюда StatefulSet и PVC, пока отдельно не проверены передача владения, удаление
и восстановление.

Подробности — в [`deployment.md`](../docs/deployment.md) и
[`resource-fields.md`](../docs/resource-fields.md).
