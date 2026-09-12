# Эксплуатация и диагностика Kubernetes

## Сценарии каталога `k8s/scripts`

| Сценарий | Назначение |
|---|---|
| `apply.ps1` | Полное развертывание простого локального контура. |
| `start-local-ha.ps1` | Сборка и развертывание локального HA-контура. |
| `build-images.ps1` | Сборка образов сервисов и миграторов. |
| `deploy-applications-helm.ps1` | Установка или обновление единого Helm-выпуска. |
| `delete-local.ps1` | Удаление локального развертывания; перед запуском нужно проверить выбранный контекст. |
| `validate.ps1` | Клиентская проверка Kustomize и Helm. Содержит ссылку на удаленный чарт Dispatch, поэтому текущий запуск сценария завершится ошибкой. |
| `install-metrics-server.ps1` | Установка Metrics Server для метрик ресурсов и HPA. |
| `install-mesh.ps1` | Установка Istio, Kiali, базовых политик и входного шлюза. |
| `setup-ingress.ps1` | Создание локального сертификата и применение маршрутов Istio. |
| `install-flux.ps1` | Установка Flux и, при параметре, источника `deploy/local`. |
| `open-observability.ps1` | Фоновые port-forward Grafana, Jaeger, Prometheus, Kibana и Kiali. |
| `generate-grafana-dashboards.ps1` | Формирование проектных панелей Grafana. |
| `import-grafana-community-dashboards.ps1` | Обновление выбранных общественных панелей. |
| `setup-kibana-dashboards.ps1` | Создание объектов просмотра и панелей Kibana. |
| `setup-ngrok-tunnel.ps1` | Создание секрета и запуск ngrok. |
| `watch-ngrok-tunnel.ps1` | Наблюдение за состоянием туннеля. |
| `apply-transponders.ps1` | Запуск необязательных имитаторов координат. |
| `run-local-ha-e2e.ps1` | Заполнение демонстрационных данных и Playwright E2E через port-forward. |
| `run-local-ha-chaos.ps1` | Проверка поведения локального HA при отказах. |
| `run-k6-chaos.ps1` | Нагрузочный сценарий k6 при отказах. |

## Быстрая проверка состояния

```powershell
kubectl config current-context
kubectl get nodes -o wide
kubectl get pods -A
kubectl get events -A --sort-by=.lastTimestamp
```

Сначала проверяются узлы и управляющий API. Если `kubectl` сообщает
`connection refused` на `127.0.0.1:<port>`, Kubernetes Docker Desktop не
слушает адрес из kubeconfig; диагностика отдельных подов в этот момент
бессмысленна.

## Проверка приложений

```powershell
kubectl get deploy,rs,pod,svc -n automatic-system
kubectl rollout status deployment/<name> -n automatic-system --timeout=5m
kubectl describe pod/<pod> -n automatic-system
kubectl logs pod/<pod> -n automatic-system --all-containers --tail=200
```

Для завершившегося контейнера:

```powershell
kubectl logs pod/<pod> -n automatic-system -c <container> --previous
```

Состояние `0/0` у Deployment означает, что желаемое число реплик равно нулю.
Для `*-canary` это нормально после продвижения. ReplicaSet с нулем реплик
сохраняется для истории отката согласно `revisionHistoryLimit`; подов в нем
нет.

## Проверка данных

```powershell
kubectl get statefulset,pvc -n automatic-system
kubectl get endpoints,endpointslices -n automatic-system
kubectl rollout status statefulset/<name> -n automatic-system --timeout=15m
```

При ошибке подключения проверяются последовательно:

1. готовность StatefulSet;
2. соответствие селектора Service меткам пода;
3. наличие адресов EndpointSlice;
4. строка подключения в `runtime-secrets`;
5. политика сети и mTLS;
6. роль основного узла Patroni или Redis Sentinel.

Секреты нельзя выводить целиком в терминал или журнал CI. Для проверки
достаточно списка ключей и наличия объекта.

## Patroni, Citus и PgBouncer

```powershell
kubectl get pods -n automatic-system -l app.kubernetes.io/name=patroni
kubectl get pods -n automatic-system -l app.kubernetes.io/name=patroni-citus
kubectl get svc -n automatic-system | Select-String 'postgres|pgbouncer'
```

Основные приложения записывают через `pgbouncer-*-primary:6432`, а чтение
может идти через `pgbouncer-*-replicas:6432`. Миграции подключаются напрямую
к PostgreSQL primary на 5432. Детальные действия восстановления описаны в
[`postgres-ha.md`](postgres-ha.md).

## Kafka

```powershell
kubectl get pod,svc -n automatic-system -l app.kubernetes.io/name=kafka
kubectl logs deployment/kafka-exporter -n automatic-system --tail=200
kubectl get job/kafka-init -n automatic-system
```

`kafka-init` должен завершиться успешно. Экспортер не участвует в доставке
сообщений: его падение лишает только метрик, но часто указывает на недоступные
адреса брокеров или неверную готовность Kafka.

## Flux

```powershell
kubectl get pods -n flux-system
kubectl get gitrepository automatic-system -n flux-system
kubectl get kustomization automatic-system-local-ha -n flux-system
kubectl get helmrelease applications -n flux-system
```

Полезные поля `status.conditions`: `Ready`, `Reconciling`, причина и
сообщение последней ошибки. Проверяйте также
`status.artifact.revision` GitRepository: он должен соответствовать коммиту
ветки `deploy/local`, который создал CI.

Ручной запрос согласования без изменения объекта:

```powershell
kubectl annotate gitrepository automatic-system -n flux-system `
  reconcile.fluxcd.io/requestedAt="$(Get-Date -Format o)" --overwrite
```

## Flagger

```powershell
kubectl get canary -n automatic-system
kubectl describe canary <name> -n automatic-system
kubectl logs deployment/flagger -n flagger-system --tail=300
```

Основные фазы: `Initialized`, `Progressing`, `Succeeded`, `Failed`.
При `Failed` следует проверить события Canary, доступность Prometheus,
запросы анализа и работу Istio. Наличие нового исходного Deployment само по
себе не означает продвижение его образа в `*-primary`.

## Istio и Kiali

```powershell
kubectl get pods -n istio-system
kubectl get peerauthentication,destinationrule,virtualservice,gateway `
  -n automatic-system
& .\.tools\mesh\istioctl.exe analyze -n automatic-system
```

Ошибки Kiali следует подтверждать через `istioctl analyze` и фактические
селекторы. Flagger создает DestinationRule для `primary` и `canary`; их
удаление вручную во время анализа нарушает управление выпуском.

## Наблюдаемость

```powershell
.\k8s\scripts\open-observability.ps1
```

Адреса по умолчанию:

| Система | Адрес |
|---|---|
| Grafana | `http://localhost:3001` |
| Jaeger | `http://localhost:16686` |
| Prometheus | `http://localhost:9090` |
| Kibana | `http://localhost:5601` |
| Kiali | `http://localhost:20001` |

Отсутствие данных проверяется от источника к панели:

1. приложение действительно обрабатывает трафик;
2. `/metrics` доступна из пода Prometheus;
3. цель имеет состояние UP в Prometheus;
4. метрика и метки совпадают с запросом панели;
5. выбран подходящий период и переменная;
6. канареечный под существует в выбранный период.

## Сквозная проверка фронтенда

`run-local-ha-e2e.ps1` открывает API Gateway на 8081 и Frontend на 3000,
при необходимости заполняет демонстрационные данные и запускает Playwright.

| Параметр | Назначение |
|---|---|
| `-SkipSeed` | Не создавать демонстрационные данные. |
| `-Headed` | Показать браузер Playwright. |
| `-LocalFrontend` | Собрать и запустить Frontend с рабочей машины. |
| `-ExistingFrontend` | Использовать уже запущенный Frontend. |

Port-forward к API Gateway проверяет Gateway, JWT и внутренние сервисы, но
обходит Istio ingress. Для проверки Istio нужно отдельно использовать
`city.localhost`, `api.city.localhost` или действующий ngrok URL.

## Безопасное восстановление локального кластера

1. Проверить `docker info`, состояние WSL и Docker Desktop.
2. Дождаться доступности `kubectl cluster-info`.
3. Не удалять PVC, пока не определено, какие данные можно потерять.
4. Повторно применить только нужный Kustomize-набор.
5. Дождаться инфраструктуры и только затем запускать миграции.
6. Выпустить приложения Helm или разрешить Flux выполнить согласование.
7. Проверить Canary, журналы, метрики и реальный пользовательский путь.

`-ResetData` является разрушительным действием: он удаляет пространство
`automatic-system` и локальные данные. Его нельзя использовать как обычный
способ исправления одного неготового пода.
