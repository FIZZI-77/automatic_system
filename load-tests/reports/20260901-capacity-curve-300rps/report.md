# Capacity-кривая параллельных Go-сервисов

Дата: 2026-09-01. Raw: `load-tests/results/raw/20260901T101016Z-20260901T101133Z-services-parallel`.

## Конфигурация

- 15 сервисных read-only потоков выполнялись одновременно.
- API Gateway: две фиксированные реплики, limit 500m CPU / 512Mi на реплику.
- HPA: `minReplicas=2`, `maxReplicas=2`.
- Ступени: 10 секунд warmup, 30 секунд measurement, 10 секунд stabilization.
- Docker preflight перед тестом успешно подтвердил доступ к Gateway.
- Rate limiter обходился только для маркированных тестовых запросов; после теста штатный образ и limiter восстановлены.

## Итоговая кривая

`Dispatch List` исключён из успешной capacity-кривой: endpoint возвращает 503 при любой нагрузке, включая одиночный запрос.

| RPS на сервис | Общий входящий RPS | RPS исправных сервисов | Ошибки исправных сервисов | Максимальный p95 | Самый медленный сервис |
|---:|---:|---:|---:|---:|---|
| 3 | 45 | 42 | 0% | 31.68 ms | Analytics |
| 5 | 75 | 70 | 0% | 37.72 ms | Ticket |
| 10 | 150 | 140 | 0% | 89.69 ms | Analytics |
| 15 | 225 | 210 | 0% | 64.63 ms | Analytics |
| 20 | 300 | 280 | 0.262% | 88.44 ms | Analytics |

До 225 входящих RPS система обслуживает все 14 исправных сервисных потоков без ошибок. На ступени 300 RPS начинается деградация транспорта: 22 EOF на 8403 measurement-запроса исправных сервисов.

Практический SLO-порог при `error rate < 0.1%` находится между 225 и 300 общими RPS. Для текущего железа и двух Gateway разумная оценка:

- подтверждённая стабильная capacity: 225 входящих RPS;
- полезная capacity без Dispatch: 210 RPS;
- рекомендуемый рабочий уровень с запасом 25%: около 165–170 RPS;
- зона начала деградации: около 280 полезных / 300 входящих RPS.

## Ступень 300 RPS

| Сервис | Ошибки | p95 |
|---|---:|---:|
| Auth | 0% | 32.62 ms |
| Ticket | 0.833% | 49.53 ms |
| File | 0.333% | 29.99 ms |
| SLA | 0% | 29.32 ms |
| Notification | 0% | 26.44 ms |
| Audit | 0% | 30.27 ms |
| Analytics | 0.500% | 88.44 ms |
| Report | 0.333% | 30.09 ms |
| Asset | 0.667% | 29.57 ms |
| Department | 0% | 29.06 ms |
| Brigade | 0.333% | 30.45 ms |
| Location | 0.500% | 29.65 ms |
| Routing | 0.167% | 29.50 ms |
| Profile | 0% | 29.42 ms |
| Dispatch List | 100% | 366.98 ms |

Ошибки на верхней ступени были преимущественно `EOF` между Docker k6 и `kubectl port-forward`. Поэтому 225 RPS является надёжно подтверждённой границей данного стенда, а 300 RPS одновременно нагружает систему и транспорт генератора. Для отделения Gateway capacity от port-forward limit следующий прогон следует выполнять k6 Job внутри Kubernetes.

## Ресурсы на финальном снимке

- Нагруженная реплика Gateway: 144m CPU / 50Mi RAM.
- Её Istio sidecar: 196m CPU / 48Mi RAM.
- Вторая Gateway-реплика почти простаивала: port-forward закрепил основной поток соединений за одним backend.
- Ticket Service: 46m CPU / 24Mi, sidecar 38m CPU.
- Analytics Service: 31m CPU / 19Mi, sidecar 27m CPU.
- Dispatch: около 124–125m CPU на приложение и 130–131m на sidecar каждой реплики, хотя ответы были 503.

Кривая консервативна: сервисное железо не было исчерпано, но способ подачи нагрузки через port-forward стал ограничением раньше CPU Gateway.

## Запуск

```text
make -f load-tests/Makefile load-suite-readonly SCENARIO_FILTER=services-parallel RATES=3,5,10,15,20 MEASUREMENT=30s WARMUP=10s STABILIZATION=10s
```
