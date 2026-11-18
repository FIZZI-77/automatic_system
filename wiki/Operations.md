# Эксплуатация

## Сначала кластер

```powershell
kubectl config current-context
kubectl get nodes -o wide
kubectl get pods -A
kubectl get events -A --sort-by=.lastTimestamp
```

Если `kubectl` получает connection refused к control plane, диагностика application pods преждевременна.

## Приложение

```powershell
kubectl get deploy,rs,pod,svc -n automatic-system
kubectl rollout status deployment/<name> -n automatic-system --timeout=5m
kubectl describe pod/<pod> -n automatic-system
kubectl logs pod/<pod> -n automatic-system --all-containers --tail=200
kubectl logs pod/<pod> -n automatic-system -c <container> --previous
```

## Данные компонентов с состоянием

```powershell
kubectl get statefulset,pvc -n automatic-system
kubectl get endpoints,endpointslices -n automatic-system
```

Порядок диагностики ошибки соединения:

1. Готовность StatefulSet.
2. Селектор Service.
3. EndpointSlice.
4. Строка подключения и наличие ключа в секрете.
5. NetworkPolicy и mTLS.
6. Роль primary в HA или состояние Redis Sentinel, где применимо.

## Kafka

```powershell
kubectl get pod,svc -n automatic-system -l app.kubernetes.io/name=kafka
kubectl get job/kafka-init -n automatic-system
kubectl logs deployment/kafka-exporter -n automatic-system --tail=200
```

Kafka exporter не участвует в message delivery, но его failure часто указывает на connectivity/readiness issue.

## Flux

```powershell
kubectl get gitrepository,kustomization,helmrelease -n flux-system
kubectl describe kustomization automatic-system-local-ha -n flux-system
```

Проверять `status.conditions` и `status.artifact.revision`.

## Flagger

```powershell
kubectl get canary -n automatic-system
kubectl describe canary <name> -n automatic-system
```

## Наблюдаемость UIs

```powershell
.\k8s\scripts\open-observability.ps1
```

Стандартные локальные пробросы портов:

| Tool | URL |
|---|---|
| Grafana | `http://localhost:3001` |
| Jaeger | `http://localhost:16686` |
| Prometheus | `http://localhost:9090` |
| Kibana | `http://localhost:5601` |
| Kiali | `http://localhost:20001` |

### Источники
[Operations guide](https://github.com/FIZZI-77/automatic_system/blob/test/k8s/docs/operations.md)

## Устойчивые адреса Citus и архивирование Ticket

В `postgres-ticket-citus` адреса REST API Patroni и PostgreSQL используют DNS
StatefulSet pod: `<pod>.postgres-ticket-citus-nodes.<namespace>.svc.cluster.local`
вместо изменяющегося Pod IP. Init-контейнер удаляет устаревшую аннотацию `status`,
если записанный адрес не совпадает с ожидаемым DNS. Это устраняет зависимость
адресов участников от смены Pod IP; фактическое восстановление проверяется
запросами к Citus, а не только готовностью pod.

`k8s/scripts/run-local-ha-chaos.ps1` после отказа coordinator и worker group 1
ожидает новый primary и выполняет распределенный запрос Ticket. Этот сценарий
перезапускает компоненты и предназначен для локального HA-контура.

В retention worker Ticket исправлены SQL-параметры `archived_at`, `updated_at`
и порога возраста. Есть интеграционная проверка архивации с outbox event;
порог архивации по умолчанию — 24 часа, удаления — 30 дней. Конкретные значения
зависят от конфигурации запуска. См. `Ticket_Service/src/infrastructure/retentionworker/worker.go`
и `Ticket_Service/src/integration/retention_worker_test.go`.

CI при ожидании Flux дополнительно выводит последние Jobs миграций. Наличие
этой диагностики не подтверждает успешное выполнение миграции.
