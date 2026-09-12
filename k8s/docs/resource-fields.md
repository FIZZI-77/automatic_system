# Поля ключевых Kubernetes-ресурсов

Здесь разобраны поля, которые определяют поведение развертывания. Названия
полей оставлены как в YAML; объяснения основаны на манифестах репозитория.
Полный перечень файлов приведен в [карте манифестов](manifests.md).

## `StatefulSet/postgres-platform`

Источник: `overlays/prod/infra/postgres-platform/statefulset.yaml`.

| Поле | Значение | Роль |
|---|---|---|
| `metadata.name` | `postgres-platform` | Имя группы подов и основа их устойчивых имен. |
| `spec.serviceName` | `postgres-platform-nodes` | Безголовая служба для адресации отдельных узлов. |
| `spec.replicas` | `3` | Три участника Patroni. |
| `spec.podManagementPolicy` | `Parallel` | Узлы запускаются без последовательного ожидания соседей. |
| `spec.selector.matchLabels.cluster-name` | `postgres-platform` | Выбирает только поды этой группы. |
| `serviceAccountName` | `postgres-platform` | Права Patroni на чтение и изменение Kubernetes-объектов для выбора лидера. |
| `podAntiAffinity.required...` | `kubernetes.io/hostname` | В производстве требует размещать узлы на разных Kubernetes-узлах. При нехватке узлов поды останутся Pending. |
| `PATRONI_NAME`, `POD_IP` | значения из полей пода | Передают Patroni собственное имя и адрес. |
| `envFrom.secretRef` | `runtime-secrets` | Пароли и параметры хранилища резервных копий. |
| `readinessProbe` | `/readiness:8008` | Исключает неготовый узел из служб. |
| `livenessProbe` | `/liveness:8008` | Перезапускает зависший контейнер. |
| `volumeClaimTemplates.data` | `ReadWriteOnce`, `standard-rwo`, `200Gi` | Отдельный постоянный том каждому узлу; `local-ha` меняет класс и размер патчем на `standard` и `2Gi`. |
| `persistentVolumeClaimRetentionPolicy` | `Retain/Retain` | PVC сохраняются при удалении StatefulSet и уменьшении числа реплик. |
| контейнер `postgres-exporter` | порт `9187` | Отдает метрики PostgreSQL отдельно от приложения. |

Похожие узлы Citus создаются из
`overlays/prod/infra/postgres-ticket-citus/group-base/statefulset.yaml`.
Координатор использует группу `citus-group: "0"`, рабочие группы создаются
наложениями `worker-1` и `worker-2`. В отличие от платформенного узла,
у Citus есть `initContainer/clear-stale-patroni-member`: он удаляет из
аннотации устаревший IP участника после пересоздания пода. Экспортер Citus
монтирует дополнительные запросы из ConfigMap.

## Службы PostgreSQL

Источник: `overlays/prod/infra/postgres-platform/services.yaml`.

| Служба | Существенные поля | Назначение |
|---|---|---|
| `postgres-platform-nodes` | `clusterIP: None`, `publishNotReadyAddresses: true`, `cluster-name=postgres-platform` | Обнаружение отдельных членов Patroni, включая еще неготовые. |
| `postgres-platform-primary` | `role: primary`, порт `5432` | Направляет запись на текущего лидера. |
| `postgres-platform-replicas` | `role: replica`, порт `5432` | Направляет допустимые чтения на реплики. |
| `postgres-ticket-primary` | `cluster-name=postgres-ticket-citus`, `citus-group="0"`, `role=primary` | Лидер группы координаторов Citus. |
| `postgres-ticket-replicas` | те же метки, `role=replica` | Реплики координатора; чтение может отставать. |

Метка `role` выставляется Patroni. При пустом EndpointSlice сначала
проверяют состояние Patroni и фактические метки подов, а не меняют селектор
Service на все узлы: это могло бы направить запись на реплику.

## `Deployment/pgbouncer`

Источник: `overlays/prod/infra/pgbouncer/base/deployment.yaml`. Четыре
наложения меняют имя, источник подключения и проверочную базу:
`platform-primary`, `platform-replicas`, `ticket-primary`,
`ticket-replicas`.

| Поле | Значение или источник | Роль |
|---|---|---|
| `spec.replicas` | `2` | Два взаимозаменяемых пода одного маршрута пула. |
| `UPSTREAM_HOST` | изменяется наложением | Какая служба Patroni стоит за пулом. |
| `PGBOUNCER_CLUSTER` | изменяется наложением | Выбор набора баз и пользователей. |
| `HEALTHCHECK_*` | значения и `runtime-secrets` | Данные проверки реального запроса через пул. |
| `readinessProbe.exec` | `psql ... SELECT 1` | Под считается готовым только при успешном проходе через PgBouncer и БД. |
| `livenessProbe.tcpSocket` | `6432` | Перезапуск при отсутствии слушающего сокета. |
| `configMapRef/pgbouncer-config` | общий ConfigMap | Настройки пулов и подключения. |
| контейнер `pgbouncer-exporter` | порт `9127` | Метрики пула для Prometheus. |

## Шаблон приложения Helm

Пример: `helm/applications/templates/services/auth.yaml`. Остальные сервисы
следуют той же схеме, но отличаются портами, зависимостями и секретами.

| Ресурс или поле | Значение | Роль |
|---|---|---|
| `ConfigMap/auth-service-config` | адреса БД, Kafka, Profile, SMTP, порт gRPC | Несекретная конфигурация. `haDatabase.enabled` переключает адрес с `postgres-auth` на PgBouncer. |
| `Service/auth-service.spec.selector.app` | `auth-service` либо `auth-service-primary` | При `canary.enabled` клиентский трафик идет к основной версии под управлением Flagger. |
| `Deployment/auth-service.spec.replicas` | `applications.auth.replicaCount` | Число подов, если общий HPA выключен. |
| `strategy.rollingUpdate` | `maxSurge: 1`, `maxUnavailable: 0` | При обычном обновлении добавляет новый под до удаления старого. |
| `revisionHistoryLimit` | `3` | Число сохраняемых старых ReplicaSet. Нулевые ReplicaSet могут оставаться после выпуска. |
| аннотации `prometheus.io/*` | `/metrics`, `9464`, `true` | Обнаружение метрик Prometheus. |
| `startupProbe` | gRPC `50051` | Дает время приложению запуститься. |
| `readinessProbe` | gRPC `50051` | Допуск пода к трафику. |
| `livenessProbe` | gRPC `50051` | Перезапуск зависшего приложения. |
| `runtime-secrets.AUTH_DB_PASSWORD` | переменная `DB_PASSWORD` | Пароль БД; не хранится в ConfigMap. |
| `jwt-private-key` | `/app/keys/private.pem` | Закрытый ключ подписи токенов Auth. |
| `grafana-smtp` | SMTP-пользователь и пароль | Внешние учетные данные почты. |
| `telemetry-config` | `envFrom` | Адрес OpenTelemetry Collector и параметры трассировки. |

При переключении `canary.enabled` меняется селектор Service. Поэтому
переход от обычного Deployment к Flagger следует проверять по итоговым
Service/EndpointSlice и только после готовности основного пода.

## Миграционные `Job`

Источники: `helm/applications/templates/migrations.yaml`,
`dispatch.yaml` и `analytics-init.yaml`.

| Поле или механизм | Назначение |
|---|---|
| `metadata.name` с `.Release.Revision` | Новое имя при следующем выпуске: завершенный Job нельзя обновить новым шаблоном пода. |
| `helm.sh/hook: pre-install,pre-upgrade` | Выполняет миграцию до смены Deployment. |
| `migrations.enabled`, `dispatch.migration.enabled`, `analyticsInit.enabled` | Отдельно разрешают соответствующие наборы заданий. |
| `migrations.tags` | Выбирает образ мигратора по сервису; неизменившийся сервис может сохранить прошлую метку. |
| `runtime-secrets` | Дает строку подключения к primary PostgreSQL, не через транзакционный пул. |

Если Helm откатил приложение, база остается с примененной схемой. Миграция
должна быть обратно совместима с предыдущей версией приложения.

## `Canary` Flagger

Источник: `helm/applications/templates/canaries.yaml`.

| Поле | Назначение |
|---|---|
| `canary.enabled` | Глобально включает создание Canary. |
| `canary.serviceFilter` | При непустом списке создает Canary только для указанных сервисов. |
| `targetRef.name` | Исходный Deployment, образ которого анализирует Flagger. |
| `service.name/port/targetPort/portName` | Имя и порты управляемой службы. |
| `metricsServer` | URL Prometheus, который опрашивает Flagger. |
| `progressDeadlineSeconds` | Предел ожидания появления нового рабочего пода. |
| `analysis.interval` | Период между проверками. |
| `analysis.threshold` | Число неудачных проверок до остановки выпуска. |
| `analysis.maxWeight/stepWeight` | Максимальная доля и шаг канареечного трафика. |
| `analysis.metrics` | Пороги успешности и длительности запросов. |
| `webhooks` | Необязательная генерация трафика; в `values.yaml` задана для Frontend. |
| `revertOnDeletion` | При удалении Canary Flagger восстанавливает первоначальный способ управления целевыми ресурсами. |

`Canary` сохраняется после продвижения, но `*-canary` Deployment обычно
масштабируется до нуля. Для выяснения результата важнее `status.phase`,
события и образ `*-primary`, чем число канареечных подов после анализа.

## Источник и согласование Flux

Источник: `flux/bootstrap/local-ha-sync.yaml`.

| Поле | Значение | Роль |
|---|---|---|
| `GitRepository.spec.ref.branch` | `deploy/local` | Только эта ветка служит источником локального развертывания. |
| `GitRepository.spec.interval` | `1m` | Частота проверки Git. |
| `Kustomization.spec.path` | `./k8s/flux/clusters/local-ha` | Подкаталог, собираемый контроллером. |
| `Kustomization.spec.prune` | `true` | Удаляет объекты, исчезнувшие из управляемого набора; состояние БД этим набором не управляется. |
| `Kustomization.spec.suspend` | `true` при установке | Не начинает первое согласование до подготовки источника и кластера. |
| `Kustomization.spec.wait` | `true` | Ожидает готовность примененных ресурсов. |
| `Kustomization.spec.timeout` | `40m` | Общий предел ожидания. |

Источник: `flux/clusters/local-ha/applications-release.yaml`.

| Поле | Значение | Роль |
|---|---|---|
| `chart.spec.chart` | `./k8s/helm/applications` | Чарт берется из того же снимка Git. |
| `chart.spec.valuesFiles` | `values.yaml`, `values-local-ha.yaml` | Общие и окруженческие значения. |
| `dependsOn` | `flagger`, `flagger-loadtester` | Приложения с Canary выпускаются после контроллера анализа. |
| `valuesFrom` | `applications-release-values` | Добавляет метки образов, публикуемые CI. |
| `values.canary.enabled` | `true` | Включает Canary при выпуске Flux. |
| `upgrade.remediation.strategy` | `rollback` | При неудачном обновлении контроллер пытается вернуть предыдущий Helm-выпуск. |
| `targetNamespace` | `automatic-system` | Место создания ресурсов приложения. |
| `metadata.namespace` | `flux-system` | Место самого HelmRelease. |

Контроллеры `flagger` и `flagger-loadtester` устанавливаются отдельными
HelmRelease. Политики и маршруты Istio согласуются отдельными Flux
Kustomization, каждая с `prune: true`.

