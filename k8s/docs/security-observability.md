# Безопасность, сеть и наблюдаемость

## Секреты

Манифесты не содержат закрытые ключи JWT, пароли баз данных, токен ngrok и
учетную запись Firebase. Секреты создаются отдельно от отслеживаемых файлов.

| Секрет | Потребители | Источник |
|---|---|---|
| `runtime-secrets` | приложения, миграции, PostgreSQL, MinIO и ClickHouse | `overlays/local/secrets/runtime.env` для `local` либо генерация `start-local-ha.ps1`. |
| `jwt-private-key` | Auth Service | `keys/private.pem`. |
| `jwt-public-key` | API Gateway и проверяющие токен сервисы | `keys/public.pem`. |
| `firebase-fcm` | Notification Service | внешний файл учетной записи, ключ `service-account.json`. |
| секрет ngrok | Deployment ngrok | создается `setup-ngrok-tunnel.ps1`. |
| TLS-секрет Istio ingress | входной шлюз | создается `setup-ingress.ps1`. |

Правила работы:

1. Не добавлять `runtime.env`, ключи, kubeconfig и учетную запись Firebase в
   Git.
2. Не выводить содержимое Secret в журнал CI.
3. Не менять пароли PostgreSQL при сохраненных PVC без согласованной ротации.
4. После публичной утечки ключ или токен отзывается у поставщика, а не только
   удаляется из истории Git.
5. Для производства локальный SecretGenerator следует заменить внешним
   хранилищем секретов и ограниченной учетной записью.

## Учетные записи и права

`base/observability/service-account.yaml` выдает Prometheus и OpenTelemetry
Collector права чтения, необходимые для обнаружения объектов и метаданных.
`kube-state-metrics.yaml` содержит отдельную учетную запись и кластерные права
на чтение состояния Kubernetes.

Исполнитель GitHub Actions работает как
`ServiceAccount/github-runner` из `arc-runners`:

- Role `github-runner-deployer` позволяет управлять приложениями в
  `automatic-system` и читать Canary;
- Role `github-runner-flux-deployer` позволяет запускать согласование Flux и
  читать HelmRelease в `flux-system`;
- кластерных административных прав этому исполнителю манифесты не выдают.

## NetworkPolicy

В базовом контуре входящий трафик запрещается по умолчанию и затем открывается
для внутренних компонентов и API Gateway. Производственный набор добавляет
запрет исходящего трафика и точечные разрешения.

Порядок диагностики сетевого отказа:

1. Проверить метки исходного и целевого подов.
2. Найти все NetworkPolicy, выбирающие целевой под.
3. Проверить разрешение входа на целевом и выхода на исходном поде.
4. Проверить DNS и EndpointSlice.
5. После L3/L4 проверить Istio mTLS и AuthorizationPolicy.

NetworkPolicy и Istio дополняют друг друга: первая ограничивает сетевые
соединения, вторая удостоверяет стороны и управляет прикладным трафиком.

## Istio sidecar

Пространство `automatic-system` в `local-ha` и `prod` помечено
`istio-injection=enabled`. Приложения получают sidecar, а StatefulSet
инфраструктуры явно получают `sidecar.istio.io/inject: "false"`.

Причина исключения инфраструктуры: PostgreSQL, PgBouncer, Kafka, Redis, MinIO,
ClickHouse и Valhalla используют собственные протоколы и топологию. Общий
`ISTIO_MUTUAL` для всех направлений сломал бы обращения к подам без sidecar.

## mTLS

`mesh/policies/strict-mtls.yaml` задает строгий mTLS для приложений. Исключения
ограничены конкретными рабочими нагрузками и портами:

| Манифест | Исключение | Причина |
|---|---|---|
| `mesh/ingress/public-port-authentication.yaml` | публичные порты Frontend и API Gateway | Клиент приходит извне mesh без сертификата Istio. |
| `base/observability/prometheus-plaintext.yaml` | порт Prometheus 9090 | Доступ компонентов анализа и панелей к HTTP API Prometheus. |
| `base/observability/application-metrics-peerauth.yaml` | порты метрик приложений | Prometheus должен читать `/metrics` при включенном mesh. |
| `mesh/policies/clickhouse-plaintext.yaml` | нативный порт ClickHouse | ClickHouse работает без sidecar. |
| `mesh/policies/infrastructure-plaintext.yaml` | выбранные инфраструктурные службы | Клиентский Envoy не должен начинать Istio TLS к обычному серверу. |

Исключение должно выбирать конкретный workload и порт. Широкий режим
`PERMISSIVE` для пространства имен скрывает ошибки конфигурации и ослабляет
границу внутренних сервисов.

## Входящий трафик

`mesh/ingress` создает две точки входа:

| Ресурс | Назначение |
|---|---|
| `Gateway/automatic-system` | Локальный TLS-вход для `city.localhost` и `api.city.localhost`. |
| `Gateway/automatic-system-public` | Публичная HTTP-точка, используемая ngrok. |
| `VirtualService/frontend` | Передача пользовательских страниц во Frontend. |
| `VirtualService/api-gateway` | Передача API в API Gateway по h2c. |
| `VirtualService/public-entrypoint` | Разделение публичных путей Frontend и API. |
| `DestinationRule/ingress-api-gateway-websocket` | Параметры длительных WebSocket-соединений. |

Локальный сертификат действует два года. Ротация:

```powershell
.\k8s\scripts\setup-ingress.ps1 -RotateCertificate
```

## AuthorizationPolicy

`authorization-audit.yaml` работает в режиме аудита и отмечает обращения к
внутренним службам без ожидаемой идентичности. Принудительный запрет намеренно
не включен, пока сервисы используют общую учетную запись `default`: при ней
нельзя надежно различить API Gateway и остальные приложения по SPIFFE.

Перед включением принудительного режима каждому приложению требуется отдельный
ServiceAccount, после чего правила должны быть проверены на gRPC, HTTP,
фоновых потребителях и миграционных Job.

## Prometheus

Prometheus собирает:

- `/metrics` Go-сервисов;
- состояние объектов через kube-state-metrics;
- ресурсы узлов через node-exporter;
- метрики Redis и Kafka через их exporter;
- метрики ClickHouse;
- метрики управляющего etcd напрямую с его `/metrics`;
- показатели Istio и Flagger, используемые канареечным анализом.

Отдельного etcd exporter в манифестах нет. Если панель etcd показывает метрики
других процессов, сначала проверяются метки цели `job`, `instance` и
`pod` в Prometheus, а затем переменные панели.

Проверка цели:

```powershell
kubectl port-forward -n automatic-system service/prometheus 9090:9090
```

Откройте `http://localhost:9090/targets`. Состояние DOWN требует проверки
адреса, порта, NetworkPolicy, mTLS и фактической выдачи `/metrics`.

## Grafana

Источники и поставщик панелей создаются ConfigMap. Проектные панели разделены
на группы, чтобы не превысить размер одного объекта Kubernetes:

- приложения;
- платформенные и Citus-базы;
- отдельные базы PostgreSQL;
- PgBouncer;
- Kafka и Redis;
- инфраструктура;
- развертывания и Flagger.

Панель канарейки показывает данные только в период существования
`*-canary` подов и прохождения через них трафика. Пустая правая половина вне
анализа ожидаема. Пустая основная половина при работающем сервисе означает
ошибку запроса, меток или сбора.

## OpenTelemetry и Jaeger

`telemetry-config` задает:

| Переменная | Значение |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://otel-collector:4317` |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc` |
| `OTEL_EXPORTER_OTLP_INSECURE` | `true` внутри кластера |
| `OTEL_TRACES_SAMPLER` | `parentbased_traceidratio` |
| `OTEL_TRACES_SAMPLER_ARG` | `1.0` |
| `OTEL_DEPLOYMENT_ENVIRONMENT` | `kubernetes` |

Приложение создает span и передает контекст дальше по gRPC/HTTP.
OpenTelemetry Collector принимает OTLP и направляет трассировки в Jaeger.
Полный путь ошибки появляется только если контекст не заменяется новым
`context.Background()` и идентификаторы трассировки сохраняются в журнале.

## Elasticsearch, Filebeat и Kibana

Контейнер пишет структурированный JSON в stdout/stderr. Kubernetes сохраняет
поток в журнал узла. Filebeat читает журналы всех узлов, добавляет сведения о
Kubernetes и отправляет записи в Elasticsearch. Kibana работает поверх этих
индексов.

Чтобы ошибка нижнего слоя была пригодна для поиска, запись должна содержать:

- уровень и сообщение;
- имя сервиса;
- `trace_id` и `span_id`;
- имя операции или функции;
- завернутую цепочку ошибки;
- предметные идентификаторы без паролей и токенов.

Istio не формирует внутренний стек Go-приложения. Он видит сетевой запрос,
задержку и код ответа. Полный путь по функциям создают OpenTelemetry и
структурированный журнал самого сервиса.

## Kiali

Kiali читает состояние Kubernetes, конфигурацию Istio, Prometheus и Jaeger.
Предупреждение `Connecting to Prometheus` означает, что графы трафика,
задержки и ошибки временно недоступны, даже если сами конфигурационные объекты
видны.

Проверка:

```powershell
kubectl get pods -n istio-system
kubectl get svc prometheus -n automatic-system
kubectl exec -n istio-system deployment/kiali -- `
  wget -qO- http://prometheus.automatic-system.svc.cluster.local:9090/-/ready
```

Список `IstioConfig has errors` следует сверять с
`istioctl analyze -n automatic-system`. Ресурсы `*-primary` и
`*-canary`, созданные Flagger, оцениваются в контексте активного или
завершенного анализа; простое наличие имени в списке Kiali не доказывает
ошибку трафика.

