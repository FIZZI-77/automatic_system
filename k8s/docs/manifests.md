# Карта Kubernetes-манифестов

Документ объясняет назначение манифестов и связи между ресурсами. Повторяющиеся
наборы одной формы сведены в таблицы, но их фактические имена сохранены.
Ключевые поля разобраны в [справочнике ресурсов](resource-fields.md).

## Основа `k8s/base`

`base/kustomization.yaml` объединяет пространство имен, данные,
вспомогательные службы, начальные задания, старый набор приложений,
наблюдаемость, журналы и сеть. Рабочие наложения подключают только нужные части,
поэтому применять весь `base` напрямую нельзя: его `kustomization.yaml`
ссылается на отсутствующий `base/apps`. Рабочие наложения этот файл обходят.

### Пространство имен

| Файл | Ресурс | Назначение |
|---|---|---|
| `base/namespace/namespace.yaml` | `Namespace/automatic-system` | Общее пространство основных компонентов. |
| `base/namespace/kustomization.yaml` | `Kustomization` | Подключает пространство имен. |

### PostgreSQL простого контура

Каждый каталог `base/data/postgres/<service>` содержит `StatefulSet`,
`Service`, `ConfigMap` и `kustomization.yaml`. StatefulSet хранит данные,
Service дает постоянное имя, а ConfigMap передает начальные параметры.

| Каталог | Имя StatefulSet и Service | Назначение базы |
|---|---|---|
| `asset` | `postgres-asset` | Городские объекты. |
| `audit` | `postgres-audit` | Записи аудита. |
| `auth` | `postgres-auth` | Пользователи, роли, сессии и токены. |
| `brigade` | `postgres-brigade` | Бригады, состав, навыки, смены и зоны. |
| `department` | `postgres-department` | Подразделения. |
| `dispatch` | `postgres-dispatch` | Операции назначения и резервы. |
| `file` | `postgres-file` | Метаданные файлов. |
| `location` | `postgres-location` | Координаты и географические зоны. |
| `notification` | `postgres-notification` | Уведомления, доставки и устройства. |
| `profile` | `postgres-profile` | Профили, сертификаты и навыки. |
| `report` | `postgres-report` | Задания формирования отчетов. |
| `routing` | `postgres-routing` | Сохраненные маршруты. |
| `sla` | `postgres-sla` | Правила и сроки исполнения. |
| `ticket` | `postgres-ticket` | Заявки, категории, история и отчеты о работах. |

В `prod` простые PostgreSQL получают `replicas: 0` и заменяются общей
платформенной группой Patroni и отдельным Citus-кластером заявок.

### Очереди, кэш и хранилища

| Каталог | Ресурсы | Назначение |
|---|---|---|
| `base/data/kafka/kafka-1..3` | три StatefulSet и Service | Три узла Kafka. |
| `base/data/redis/gateway` | `redis-gateway` | Ограничение частоты запросов шлюза. |
| `base/data/redis/notification` | `redis-notification` | Временные данные уведомлений. |
| `base/data/redis/location` | основной узел, две реплики, Sentinel и службы | Кэш текущих координат и выбор основного узла. |
| `base/data/minio` | `StatefulSet/minio`, `Service/minio` | S3-совместимое хранилище файлов. |
| `base/data/clickhouse` | StatefulSet, Service, ConfigMap | Аналитические события и выдача метрик. |
| `base/data/valhalla` | `StatefulSet/valhalla`, Service | Дорожный граф и построение маршрутов. |
| `base/data/kustomization.yaml` | Kustomization | Собирает данные и отключает Istio sidecar для StatefulSet. |

### Вспомогательные службы и начальные задания

| Файл | Ресурс | Назначение |
|---|---|---|
| `base/auxiliary/mailhog/deployment.yaml` | `Deployment/mailhog` | Прием тестовой почты. |
| `base/auxiliary/mailhog/service.yaml` | `Service/mailhog` | SMTP и веб-интерфейс MailHog. |
| `base/migrations/kafka-init.yaml` | `Job/kafka-init` | Создание требуемых разделов Kafka. |

SQL-миграции приложений создаются актуальным Helm-чартом, а `kafka-init`
остается отдельным заданием инфраструктуры.

## Наблюдаемость

| Файл | Ресурсы | Назначение |
|---|---|---|
| `base/observability/prometheus.yaml` | Deployment, Service | Сбор метрик приложений, Kubernetes, инфраструктуры и etcd. |
| `prometheus-config.yaml` | данные ConfigMap | Цели и правила сбора Prometheus. |
| `prometheus-plaintext.yaml` | PeerAuthentication | Исключение mTLS для входа на порт 9090. |
| `application-metrics-peerauth.yaml` | PeerAuthentication | Сбор `/metrics` приложений при включенном Istio. |
| `grafana.yaml` | PVC, Deployment, Service | Хранение и показ панелей. |
| `grafana-datasources.yaml` | данные ConfigMap | Источники данных Grafana. |
| `grafana-dashboard-provider.yaml` | данные ConfigMap | Автоматическая загрузка панелей. |
| `dashboards/*.json` | панели | Сервисы, БД, инфраструктура и канареечные выпуски. |
| `otel-collector.yaml` | Deployment, Service | Прием телеметрии OpenTelemetry. |
| `jaeger.yaml` | PVC, Deployment, Service | Хранение и просмотр трассировок. |
| `kube-state-metrics.yaml` | RBAC, Deployment, Service | Состояние объектов Kubernetes. |
| `node-exporter.yaml` | DaemonSet | Метрики узлов. |
| `infrastructure-exporters.yaml` | Redis/Kafka exporter | Метрики Redis и Kafka; etcd exporter отсутствует. |
| `service-account.yaml` | учетные записи и RBAC | Чтение объектов Prometheus и OpenTelemetry Collector. |

`base/observability/kustomization.yaml` создает `telemetry-config`,
конфигурации компонентов и ConfigMap с панелями. Суффиксы хеша отключены,
поскольку Deployment ссылаются на постоянные имена.

## Журналы

| Файл | Ресурсы | Назначение |
|---|---|---|
| `base/logging/elasticsearch.yaml` | StatefulSet, Service | Хранение журналов. |
| `base/logging/kibana.yaml` | Deployment, Service | Поиск и визуализация журналов. |
| `base/logging/filebeat.yaml` | RBAC, DaemonSet | Чтение журналов контейнеров на узлах. |
| `base/logging/filebeat-config.yaml` | данные ConfigMap | Разбор полей и отправка в Elasticsearch. |

## Сетевая политика

| Набор | Назначение |
|---|---|
| `base/network/default-deny-ingress.yaml` | Запрет входящих соединений по умолчанию. |
| `base/network/allow-internal-ingress.yaml` | Разрешение внутреннего обмена выбранных компонентов. |
| `base/network/allow-api-gateway-ingress.yaml` | Разрешение входа к API Gateway. |
| `overlays/prod/network/default-deny-egress.yaml` | Запрет исходящих соединений по умолчанию. |
| `overlays/prod/network/segmented-internal.yaml` | Разделение приложений и внутренних зависимостей. |
| `overlays/prod/network/metrics-scraping.yaml` | Разрешение Prometheus собирать метрики. |

## Helm-чарт приложений

`helm/applications/Chart.yaml` объявляет единый выпуск для Kubernetes 1.27 и
новее. Шаблоны `templates/services/*.yaml` создают прикладные ресурсы.

| Шаблон | Создаваемые ресурсы |
|---|---|
| `analytics.yaml` | Service и Deployment аналитики. |
| `api-gateway.yaml` | ConfigMap, Service и Deployment шлюза. |
| `asset.yaml`, `audit.yaml` | Service и Deployment. |
| `auth.yaml`, `brigade.yaml`, `department.yaml` | ConfigMap, Service и Deployment. |
| `file.yaml`, `profile.yaml`, `routing.yaml`, `sla.yaml`, `ticket.yaml` | ConfigMap, Service и Deployment. |
| `location.yaml` | ConfigMap, gRPC Service, HTTP Service и Deployment. |
| `notification.yaml` | ConfigMap, Service, Deployment и подключение секрета Firebase. |
| `report.yaml` | ConfigMap, внешний и внутренний Service, Deployment. |
| `frontend.yaml` | Service и Deployment фронтенда. |
| `dispatch.yaml` | ConfigMap, Service, Deployment, HPA/PDB и миграция. |
| `migrations.yaml` | Миграционные Job PostgreSQL-сервисов. |
| `analytics-init.yaml` | Инициализационное Job ClickHouse. |
| `canaries.yaml` | Canary Flagger для выбранных сервисов. |
| `application-autoscaling.yaml` | HPA при включенном `applicationAutoscaling`. |
| `api-gateway-scaling.yaml` | PDB и распределение API Gateway. |

`values.yaml` содержит основу, а `values-local.yaml`,
`values-local-ha.yaml`, `values-dev.yaml`, `values-prod.yaml` задают
различия окружений. `globalImage.tags` и `migrations.tags` позволяют менять
только образы затронутых сервисов.

## Производственная база данных

| Каталог | Назначение |
|---|---|
| `overlays/prod/infra/postgres-platform` | Patroni для баз большинства сервисов, службы primary/replicas, RBAC и резервные копии. |
| `overlays/prod/infra/postgres-ticket-citus` | Координатор и две группы рабочих узлов Citus, распределение таблиц и резервные копии. |
| `overlays/prod/infra/pgbouncer` | Точки platform/ticket и primary/replicas. |
| `overlays/prod/infra/pdb-kafka.yaml` | Ограничение одновременной недоступности Kafka. |
| `overlays/prod/infra/pdb-redis-sentinel.yaml` | Ограничение недоступности Redis Sentinel. |

Подробности приведены в [`postgres-ha.md`](postgres-ha.md).

## Istio

| Файл или каталог | Ресурс и назначение |
|---|---|
| `mesh/istio-operator.yaml` | Настройка управляющей части и входного шлюза. |
| `mesh/policies/strict-mtls.yaml` | Строгий mTLS для приложений. |
| `mesh/policies/clickhouse-plaintext.yaml` | Исключение для нативного порта ClickHouse. |
| `mesh/policies/destination-rules.yaml` | Пулы соединений прикладных клиентов. |
| `mesh/policies/infrastructure-plaintext.yaml` | Отключение Istio TLS к инфраструктуре без sidecar. |
| `mesh/policies/authorization-audit.yaml` | Аудит неаутентифицированного внутреннего трафика. |
| `mesh/ingress/gateway*.yaml` | Внутренняя TLS- и публичная HTTP-точки входа. |
| `mesh/ingress/routes*.yaml` | Маршруты фронтенда, API и WebSocket. |
| `mesh/ingress/network-policy.yaml` | Доступ входного шлюза к приложениям. |
| `mesh/ingress/public-port-authentication.yaml` | Открытые порты Frontend и API Gateway без mTLS. |
| `istio/gmail-smtp-serviceentry.yaml` | Разрешенное SMTP-направление Gmail. |

## Flux, Flagger и CI

| Файл | Ресурс | Назначение |
|---|---|---|
| `flux/bootstrap/local-ha-sync.yaml` | GitRepository | Читает `deploy/local` раз в минуту. |
| тот же файл | Flux Kustomization | Применяет кластерный каталог, удаляет исчезнувшие управляемые ресурсы и ожидает готовность; изначально приостановлен. |
| `flux/clusters/local-ha/applications-release.yaml` | HelmRelease | Выпускает общий чарт с включенными Canary. |
| `flagger-repository.yaml` | HelmRepository | Источник чарта Flagger. |
| `flagger-release.yaml` | HelmRelease | Контроллер Flagger. |
| `flagger-loadtester-release.yaml` | HelmRelease | Генератор проверочного трафика. |
| `mesh-policies.yaml`, `mesh-ingress.yaml` | Flux Kustomization | Согласование политик и маршрутов Istio. |
| `github-runner/rbac.yaml` | ServiceAccount, Role, RoleBinding | Права CI на приложения и чтение Canary. |
| `github-runner/flux-rbac.yaml` | Role, RoleBinding | Права CI на Flux и чтение HelmRelease. |

## Необязательные наборы

| Каталог | Назначение |
|---|---|
| `ngrok` | Туннель к Istio ingress; токен создается вне Git. |
| `optional/transponders` | Автоматический Simulator и сценарий отмены/ошибок. |
| `load-testing/k6-job.yaml` | k6 внутри кластера и его NetworkPolicy. |
| `mesh/scenarios/api-gateway-canary.yaml` | Ручной учебный сценарий 90/10, не входящий в обычную установку. |
