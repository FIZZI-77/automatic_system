# Helm-выпуск приложений

`k8s/helm/applications` — единственный чарт прикладных сервисов:
Analytics, API Gateway, Asset, Audit, Auth, Brigade, Department, Dispatch,
File, Frontend, Location, Notification, Profile, Report, Routing, SLA и Ticket.
Отдельного чарта Dispatch больше нет; его ресурсы находятся в
`templates/dispatch.yaml`.

Чарт создает Deployment, Service и ConfigMap приложений, миграционные Job,
Canary Flagger и необязательные HPA/PDB. Хранилища данных, наблюдаемость,
политики Istio и первичная подготовка остаются в Kustomize.

## Значения

| Файл | Назначение |
|---|---|
| `values.yaml` | Общие порты, адреса, образы, настройки масштабирования, миграций и Canary. |
| `values-local.yaml` | Простой локальный контур. |
| `values-local-ha.yaml` | Локальный Patroni/Citus/PgBouncer и параметры распределения подов. |
| `values-dev.yaml` | Разработческий контур. |
| `values-prod.yaml` | Реестр GHCR и производственные ограничения ресурсов. |

Для `dev` и `prod` сценарий выпуска требует неизменяемые метки приложения
и мигратора. Общий HPA по умолчанию выключен. Dispatch имеет собственные
настройки `dispatch.autoscaling` и `dispatch.podDisruptionBudget`.

## Миграции

Задания Goose и подготовки ClickHouse выполняются до смены Deployment.
Неуспешный выпуск с `--atomic --wait` возвращает ресурсы Helm, но **не**
откатывает SQL-схему. Миграции должны оставаться совместимыми с предыдущим
образом приложения.

## Команды

Локальный выпуск:

```powershell
.\k8s\scripts\deploy-applications-helm.ps1 -Environment local
```

Локальный отказоустойчивый контур:

```powershell
.\k8s\scripts\deploy-applications-helm.ps1 -Environment local-ha
```

Производственный выпуск:

```powershell
.\k8s\scripts\deploy-applications-helm.ps1 `
  -Environment prod `
  -ImageTag sha-<commit> `
  -MigratorTag sha-<commit>
```

`-TakeOwnership` нужен только для первоначальной передачи существующих
ресурсов от Kustomize к Helm. При обычном обновлении его не используют.

Проверка истории и откат:

```powershell
& .\.tools\mesh\helm.exe history applications -n automatic-system
& .\.tools\mesh\helm.exe rollback applications <revision> -n automatic-system --wait
```

Подробный разбор полей Helm-ресурсов — в
[`resource-fields.md`](../docs/resource-fields.md), порядок развертывания —
в [`deployment.md`](../docs/deployment.md).
