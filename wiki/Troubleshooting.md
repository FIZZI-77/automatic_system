# Диагностика неисправностей

## 1. `kubectl` не подключается

Сначала:

```powershell
kubectl config current-context
kubectl cluster-info
kubectl get nodes
```

`connection refused` к control-plane address — проблема Kubernetes/kubeconfig, а не конкретного pod.

## 2. Pod не Ready / рестартует

```powershell
kubectl describe pod/<pod> -n automatic-system
kubectl logs pod/<pod> -n automatic-system --all-containers --tail=200
kubectl logs pod/<pod> -n automatic-system -c <container> --previous
kubectl get events -n automatic-system --sort-by=.lastTimestamp
```

Проверить probes, image, config/secrets, resource limits и dependency readiness.

## 3. Service недоступен

```powershell
kubectl get svc,endpoints,endpointslices -n automatic-system
```

Проверить selector → endpoint → NetworkPolicy → Istio mTLS/AuthorizationPolicy.

## 4. PostgreSQL/Citus/PgBouncer connection error

Порядок:

1. DB/Patroni StatefulSet Ready?
2. Primary действительно выбран?
3. Service имеет endpoints?
4. PgBouncer endpoints готовы?
5. Secret содержит ожидаемые keys?
6. Migration version совместима?
7. NetworkPolicy/mTLS не блокируют traffic?

Не менять DB password при сохранённых PVC без согласованной rotation procedure.

## 5. Kafka events «пропали»

Проверить:

- `kafka-init`;
- broker readiness;
- consumer logs;
- consumer group lag;
- publisher worker/outbox;
- действительно ли publisher существует для этого topic.

Издатель `files.events.v1` — File_Service, `notifications.events.v1` —
Notification_Service. Для обоих проверить миграцию
`20261116000100_create_event_outbox.sql`, `KAFKA_BROKERS` и логи
`outbox publish failed; retrying`.

В БД соответствующего сервиса состояние очереди можно проверить так:

```sql
SELECT event_type, count(*) AS pending, min(created_at) AS oldest
FROM outbox_events
WHERE sent_at IS NULL
GROUP BY event_type;

SELECT id, event_type, attempts, next_attempt_at, last_error
FROM outbox_events
WHERE sent_at IS NULL
ORDER BY sequence
LIMIT 20;
```

Не удалять ожидающие строки ради сброса ошибки: после восстановления Kafka
передатчик повторит отправку. Если outbox уже отправлен, искать событие у
потребителя по `event_id`. Файловое событие не обязано создавать уведомление:
Notification применяет фильтр `isUserFacingEvent`. Для записей, существовавших
до миграции, историческая публикация автоматически не выполняется.

## 6. Flagger `Failed`

Проверить:

1. `kubectl describe canary`;
2. Flagger logs;
3. Prometheus availability;
4. analysis query;
5. Istio routes/DestinationRules;
6. new image readiness;
7. трафик через canary.

Не удалять вручную Flagger-managed `primary/canary` resources во время analysis.

## 7. Dashboard пустой

Идти от producer к UI:

application traffic → `/metrics` → Prometheus target UP → metric labels → PromQL → time range/dashboard variables.

## 8. `0/0` canary

После успешного promotion это нормально: Flagger масштабирует canary Deployment в 0.

## 9. Valhalla pod Ready, но route не работает

Readiness pod не гарантирует, что дорожный graph уже загружен/построен. Проверять реальный `/locate` и `/route`.

## 10. Reset

`-ResetData` удаляет namespace и локальные volumes. Не использовать как стандартный fix одного неготового pod.

### Источники
- [Operations](https://github.com/FIZZI-77/automatic_system/blob/test/k8s/docs/operations.md)
- [Deployment](https://github.com/FIZZI-77/automatic_system/blob/test/k8s/docs/deployment.md)
- [Security/observability](https://github.com/FIZZI-77/automatic_system/blob/test/k8s/docs/security-observability.md)
