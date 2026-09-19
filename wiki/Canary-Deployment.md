# Канареечное развёртывание

Canary deployment реализован через Flagger + Istio + Prometheus.

## Параметры анализа по умолчанию

| Parameter | Value |
|---|---:|
| Analysis interval | 1 minute |
| Failed checks threshold | 5 |
| Max canary traffic | 25% |
| Traffic step | 5% |
| Min request success rate | 99% |
| Max request duration | 1500 ms |
| Promotion timeout used by delivery flow | 600 s |

## Модель ресурсов

Во время анализа Flagger управляет:

- `<service>-primary`;
- `<service>-canary`.

После успешного promotion canary Deployment масштабируется до `0`. Поэтому `0/0` после успешного rollout — нормальное состояние сохранённого canary object.

## Анализ

Точка доступа Prometheus:

```text
http://prometheus.automatic-system.svc.cluster.local:9090
```

Flagger использует service metrics для acceptance checks. Пустой canary dashboard вне активного анализа не является сам по себе инцидентом.

## Диагностика

```powershell
kubectl get canary -n automatic-system
kubectl describe canary <service> -n automatic-system
kubectl get deploy,rs,pod -n automatic-system -l app=<service>
kubectl logs deployment/flagger -n flagger-system --tail=300
```

Основные phases: `Initialized`, `Progressing`, `Succeeded`, `Failed`.

При `Failed` проверяются:

1. События Canary;
2. Доступность Prometheus;
3. Аналитические запросы;
4. Маршрутизация Istio;
5. readiness и фактический image в `primary/canary`.

### Источники
[Deployment / Flagger](https://github.com/FIZZI-77/automatic_system/blob/test/k8s/docs/deployment.md)
