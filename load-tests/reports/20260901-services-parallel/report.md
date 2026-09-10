# Параллельный нагрузочный тест Go-сервисов

Дата: 2026-09-01. Артефакты suite: `load-tests/results/suite/20260901T090041Z`.

## Профиль

- 15 сервисных read-only потоков выполнялись одновременно через API Gateway.
- Ступени на каждый сервис: 3, 5 и 10 RPS.
- Совокупная верхняя нагрузка: 150 RPS.
- Каждая ступень: 5 секунд прогрева, 20 секунд измерения, 5 секунд стабилизации.
- API Gateway: две фиксированные реплики, HPA `min=max=2`.
- Rate limiter временно обходился только для маркированных load-test запросов и после suite восстановлен.

## Результаты

Значения p95 ниже агрегированы по трём ступеням; raw JSON сохранён для дальнейшей обработки.

| Сервис | Measurement requests | Ошибки | p95 |
|---|---:|---:|---:|
| Auth | 357 | 0% | 22.06 ms |
| Ticket | 358 | 0% | 35.00 ms |
| File | 357 | 0% | 20.72 ms |
| SLA | 358 | 0% | 21.17 ms |
| Notification | 357 | 0% | 20.53 ms |
| Audit | 359 | 0% | 23.94 ms |
| Analytics | 356 | 0% | 58.56 ms |
| Report | 358 | 0% | 21.16 ms |
| Asset | 358 | 0% | 21.33 ms |
| Department | 357 | 0% | 20.99 ms |
| Brigade | 359 | 0% | 21.01 ms |
| Location read | 357 | 0% | 19.96 ms |
| Routing | 357 | 0% | 20.62 ms |
| Profile | 358 | 0% | 20.79 ms |
| Dispatch List | 358 | 100% | 373.51 ms |

14 из 15 потоков прошли верхнюю одновременную ступень 10 RPS на сервис без HTTP-ошибок. Это подтверждает минимум 140 успешных RPS по read-only операциям остальных сервисов при общей подаче 150 RPS.

## Узкое место Dispatch

`POST /dispatch/list` стабильно возвращает HTTP 503 `SERVICE_UNAVAILABLE`, включая одиночный диагностический запрос вне нагрузки. Это не capacity saturation: Dispatch preview в предыдущем прогоне работал, а обе реплики Dispatch Service были Running. Необходимо отдельно проверить gRPC ListDispatches, доступность repository/database пути и mapping внутренней ошибки в Gateway.

## Ресурсы после параллельной ступени

- Нагруженная реплика Gateway: около 117m CPU / 40Mi; Istio sidecar около 82m CPU / 48Mi.
- Большинство Go-сервисов: 9–21m CPU и 16–25Mi RAM.
- Dispatch Service: 63–83m CPU на реплику, sidecar 56–65m, несмотря на 503 — это дополнительный признак повторяющейся внутренней работы/ошибки.

Снимок `kubectl top` сделан после сценария и служит ориентиром, а не точным пиком.

## Запуск

```text
make -f load-tests/Makefile load-services-parallel RATES=3,5,10
```

Для запуска через suite с автоматической подготовкой Gateway:

```text
make -f load-tests/Makefile load-suite-readonly SCENARIO_FILTER=services-parallel
```

После этого прогона сценарий дополнен отдельными thresholds для каждого сочетания `service + load_stage`, поэтому следующие JSON-отчёты будут сразу содержать кривую 3/5/10 RPS по каждому сервису.
