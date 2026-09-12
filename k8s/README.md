# Развертывание Automatic City Services в Kubernetes

Каталог `k8s` содержит декларативное описание инфраструктуры, прикладных
сервисов, сетевой политики, наблюдаемости и доставки изменений. Инфраструктура
собирается через Kustomize, приложения выпускаются единым Helm-чартом, а
локальный отказоустойчивый контур может получать изменения через Flux и
продвигать их через Flagger.

## Состав документации

| Документ | Назначение |
|---|---|
| [`docs/manifests.md`](docs/manifests.md) | Карта каталогов и семейств Kubernetes-ресурсов. |
| [`docs/resource-fields.md`](docs/resource-fields.md) | Поля StatefulSet, Service, Deployment, Job, Canary и ресурсов Flux. |
| [`docs/deployment.md`](docs/deployment.md) | Развертывание `local`, `local-ha`, `dev`, `prod`; Helm, Flux и Flagger. |
| [`docs/operations.md`](docs/operations.md) | Эксплуатационные команды, проверки, диагностика и восстановление. |
| [`docs/security-observability.md`](docs/security-observability.md) | Сеть, Istio, mTLS, секреты, метрики, трассировки и журналы. |
| [`docs/postgres-ha.md`](docs/postgres-ha.md) | Patroni, Citus, PgBouncer, резервные копии и восстановление PostgreSQL. |
| [`docs/decisions.md`](docs/decisions.md) | Зафиксированные архитектурные решения. |
| [`helm/README.md`](helm/README.md) | Специализированное описание Helm-выпуска приложений. |
| [`flux/README.md`](flux/README.md) | Специализированное описание доставки через Flux. |
| [`mesh/README.md`](mesh/README.md) | Специализированное описание Istio и входящего трафика. |
| [`base/observability/SLO.md`](base/observability/SLO.md) | Правила показателей надежности и оповещений. |

## Границы владения

| Механизм | Что он создает и обновляет |
|---|---|
| Kustomize | Пространства имен, хранилища, брокеры, сеть, наблюдаемость, журналы, начальные задания и инфраструктуру высокой доступности. |
| Helm | `Deployment`, `Service`, `ConfigMap`, миграционные задания, канареечные ресурсы, необязательные HPA и PDB приложений. |
| Flux | Следит за `deploy/local`, собирает `k8s/flux/clusters/local-ha` и согласует Helm-выпуски и манифесты Istio. |
| Flagger | Создает основной и канареечный варианты, анализирует Prometheus и продвигает либо откатывает новый образ. |
| GitHub Actions | Собирает изменившиеся образы, публикует метки `sha-*`, обновляет `deploy/local` и ожидает Flux/Flagger. |

Инфраструктура с состоянием, секреты, резервные копии и первичная подготовка
кластера намеренно не переданы Flux. Это ограничивает риск удаления данных при
`prune` и автоматического повторения административных операций.

## Каталоги

| Каталог | Содержимое |
|---|---|
| `base` | Повторно используемая основа: данные, сеть, наблюдаемость, журналы, вспомогательные службы и начальные задания. |
| `overlays/local` | Простой локальный контур с отдельной PostgreSQL большинства сервисов. |
| `overlays/local-ha` | Локальный отказоустойчивый контур с Patroni, Citus, PgBouncer, Istio и двумя репликами приложений. |
| `overlays/dev` | Контур в пространстве `automatic-system-dev` с образами из реестра. |
| `overlays/prod` | Производственные диски, сеть, PDB, Patroni/Citus и PgBouncer. |
| `helm/applications` | Единый Helm-чарт всех приложений и миграций. |
| `flux` | Источник Git, согласование `local-ha`, Flagger и HelmRelease. |
| `mesh` | Istio, mTLS, входящий трафик и настройки Kiali. |
| `github-runner` | Права самостоятельного исполнителя GitHub Actions. |
| `base/observability` | Prometheus, Grafana, OpenTelemetry Collector, Jaeger и системные метрики. |
| `base/logging` | Elasticsearch, Kibana и Filebeat. |
| `ngrok` | Необязательная публикация входного шлюза через ngrok. |
| `optional/transponders` | Необязательные имитаторы координат бригад. |
| `load-testing` | Задание k6 и сетевые разрешения для испытаний внутри кластера. |
| `build` | Dockerfile вспомогательных образов. |
| `scripts` | Установка, выпуск, проверка, наблюдение и восстановление. |

## Быстрый выбор контура

| Задача | Контур | Основная команда |
|---|---|---|
| Разработка без высокой доступности | `local` | `.\k8s\scripts\apply.ps1` |
| Локальная проверка Patroni, Citus и Istio | `local-ha` | `.\k8s\scripts\start-local-ha.ps1` |
| Ручной выпуск приложений в разработку | `dev` | `.\k8s\scripts\deploy-applications-helm.ps1 -Environment dev -ImageTag sha-... -MigratorTag sha-...` |
| Производственная сборка | `prod` | `kubectl kustomize k8s/overlays/prod` |
| Доставка `test` или `feature/**` в локальный кластер | Flux + Flagger | Рабочий процесс GitHub Actions публикует снимок в `deploy/local`. |

`start-local-ha.ps1` запрещает менять пароли при существующих томах. Для
полного удаления локальных данных используется `-ResetData`; параметр
`-ResetSecrets` допустим только без сохраненных данных.

## Пространства имен

| Пространство | Назначение |
|---|---|
| `automatic-system` | Основные приложения, данные и наблюдаемость для `local`, `local-ha` и `prod`. |
| `automatic-system-dev` | Разработческий контур. |
| `istio-system` | Управляющая часть Istio, входной шлюз и Kiali. |
| `flux-system` | Контроллеры Flux, источник Git и HelmRelease. |
| `flagger-system` | Контроллер Flagger. |
| `arc-runners` | Самостоятельный исполнитель GitHub Actions. |

## Важные ограничения

1. Метки `sha-0000000` в `prod` являются заготовками и заменяются
   неизменяемыми метками до применения.
2. Миграции выполняются до смены приложений и должны быть обратно совместимы:
   откат Helm не откатывает схему базы данных.
3. Автоматическое масштабирование подготовлено, но по умолчанию выключено.
4. Инфраструктурные `StatefulSet` не включаются в Istio. PostgreSQL, Kafka,
   Redis, MinIO и ClickHouse работают без бокового прокси.
5. После завершения канареечного анализа Flagger уменьшает канареечное
   развертывание до нуля, поэтому канареечные панели вне выпуска пусты.
6. `scripts/validate.ps1` содержит устаревшую проверку отдельного чарта
   `helm/dispatch`; фактически Dispatch входит в `helm/applications`.
7. `base/kustomization.yaml` ссылается на отсутствующий `base/apps`.
   Рабочие наложения собираются отдельно; корень `base` пока не собирается.
