# Наблюдаемость

Набор подключается через `kustomization.yaml` и создает Prometheus, Grafana,
OpenTelemetry Collector, Jaeger, kube-state-metrics, node-exporter и
экспортеры Redis/Kafka. Конфигурации и панели создаются из файлов как
ConfigMap с постоянными именами.

| Компонент | Путь данных |
|---|---|
| OpenTelemetry Collector | Принимает OTLP gRPC на `otel-collector:4317`; также отдает производные метрики на `8889`. |
| Jaeger | Показывает трассировки, переданные Collector. |
| Prometheus | Собирает `/metrics` сервисов, Istio, Flagger, Patroni, PostgreSQL, PgBouncer, Redis, Kafka, узлов и управляющего etcd. |
| Grafana | Читает источники Prometheus и Jaeger, загружает проектные и общественные панели. |
| pgAdmin | Показывает Platform PostgreSQL и Ticket Citus через заранее зарегистрированные подключения только для чтения. |
| kube-state-metrics | Отдает состояния объектов Kubernetes. |
| node-exporter | Отдает показатели узлов. |

Управляющий etcd опрашивается Prometheus напрямую на порту `2381` узлов
control-plane. Отдельного `etcd exporter` нет. Метрики Go-сервисов
опрашиваются на порту `9464`, метрики боковых прокси Istio — на `15020`.
Пути и метки целей определены в `prometheus-config.yaml`.

`telemetry-config` передает приложениям адрес Collector и параметры
трассировки. Наличие ConfigMap не доказывает, что каждое приложение
действительно передает полный путь ошибки: это проверяется по его коду,
журналу и трассировке.

Постоянный доступ к веб-интерфейсам через Istio и Tailscale Funnel:

```powershell
.\k8s\scripts\open-observability.ps1
```

Сценарий открывает `https://fizzi.tail2c9430.ts.net/observe/` и выводит
отдельный адрес pgAdmin. Grafana, Prometheus, Jaeger, Kibana, Kiali и pgAdmin требуют общий
логин и пароль. Подробности настройки — в
[`security-observability.md`](../../docs/security-observability.md).

pgAdmin разворачивается Helm-чартом `runix/pgadmin4` с параметрами из
`pgadmin-values.yaml`. Первичная настройка учетных данных и роли
`pgadmin_viewer` выполняется `k8s/scripts/setup-pgadmin.ps1`. Секреты
администратора и read-only подключения создаются только в Kubernetes и не
хранятся в репозитории.

Для производственного хранения нельзя полагаться только на готовность
Deployment: проверьте тип тома и срок хранения каждого компонента в
отрисованном манифесте. Дополнительные сведения — в
[`security-observability.md`](../../docs/security-observability.md).

