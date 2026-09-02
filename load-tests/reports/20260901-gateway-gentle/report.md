# Отчёт по щадящему нагрузочному тестированию Gateway

**Дата:** 1 сентября 2026 года  
**Стенд:** локальный Kubernetes `docker-desktop`, namespace `automatic-system`  
**Git revision:** `c825f9abe801ea1df299e31c56cc5aec3e0911a9`  
**Сценарий:** read-only `GET /.well-known/jwks.json` через API Gateway  
**Инструмент:** k6 0.49.0, `constant-arrival-rate`

## Итог

Для одного client IP подтверждена устойчивая пропускная способность **5 RPS** при **0% ошибок** и **p95 7.61 ms**. Первая нарушившая SLO ступень — **10 RPS**.

Это не предел железа. Тест упёрся в штатный общий Redis rate limiter Gateway: `300 запросов/мин`, то есть примерно `5 RPS`, с burst `100`. При превышении лимита запросы отклонялись до выполнения handler'а. CPU Gateway после теста составлял лишь `1–2m` на контейнер, память — `16–20 MiB`.

Следовательно:

- измеренная policy-limited capacity для одного IP: **5 RPS**;
- hardware/service capacity: **не достигнута и не измерена**;
- knee point по latency: **не обнаружен**;
- failure point по текущему SLO: **10 RPS**, причина — rate limiting, а не насыщение ресурсов;
- экстраполяция на сервер или большее число реплик: **невалидна**.

## Методика

Использованы два запуска нового load-testing framework. Запросы не изменяли данные. Stress, spike и soak профили не запускались.

| Запуск | Ступени | Measurement | Результат |
|---|---:|---:|---|
| Boundary control | 2, 5 RPS | 1 минута на ступень | SLO выполнен |
| Gentle ceiling probe | 10, 25, 50 RPS | 1 минута на ступень | SLO нарушен начиная с 10 RPS |

Warmup составлял 20 секунд, stabilization — 15 секунд. Между ступенями framework оставлял паузу для восстановления token bucket и стенда.

## Результаты

### Устойчивая зона: 2–5 RPS

| Метрика measurement-фазы | Значение |
|---|---:|
| Запросы | 421 |
| Ошибки | 0% |
| Успешные checks за весь запуск | 594 / 594 |
| Average latency | 5.79 ms |
| Median latency | 5.60 ms |
| p90 latency | 6.99 ms |
| p95 latency | 7.61 ms |
| Maximum latency | 13.29 ms |
| Interrupted iterations | 0 |

### Выше policy ceiling: 10–50 RPS

| Метрика measurement-фазы | Значение |
|---|---:|
| Запросы | 5 102 |
| Ошибки | 79.75% |
| Успешные checks за весь запуск | 1 908 / 7 106 |
| Average latency, включая быстрые отказы | 3.79 ms |
| Median latency | 3.34 ms |
| p90 latency | 5.66 ms |
| p95 latency | 6.27 ms |
| Maximum latency | 29.72 ms |
| Interrupted iterations | 0 |

Низкая latency во втором запуске не является хорошим результатом: отклонённые rate limiter'ом запросы завершаются быстрее нормальной обработки. Поэтому latency необходимо читать вместе с error rate.

## Ресурсы и состояние стенда

После теста:

| Компонент | CPU | Memory | Состояние |
|---|---:|---:|---|
| API Gateway pod 1 | 2m | 20 MiB | Ready |
| API Gateway pod 2 | 1m | 16 MiB | Ready |
| Istio sidecars | 3–4m | 42–44 MiB | Ready |
| Auth Service | 3m | 17 MiB | Ready |
| Redis Gateway | 12m | 4 MiB | Running |

Новых рестартов во время теста не обнаружено. Оба Gateway pod были Ready. Зафиксированные ранее restart count `1` у каждого pod относятся к их жизненному циклу до текущего прогона.

Нагрузка шла через `kubectl port-forward service/api-gateway`, который выбрал один backend pod. Поэтому этот запуск не измеряет балансировку между двумя репликами и не позволяет вычислить N+1 capacity. Rate limiter при этом хранит состояние в общем Redis и остаётся общим ограничением независимо от выбранной реплики.

## Bottleneck

**Высокая уверенность: Gateway global rate limiter.**

- Конфигурация: `Limit=300`, `Window=1m`, `Burst=100`.
- Ключ по умолчанию строится по client IP.
- Все запросы k6 поступали с одного IP.
- Успешна ступень 5 RPS; 10 RPS уже нарушает error-rate SLO.
- CPU и память имеют большой запас, latency не демонстрирует knee.

Это корректная защитная политика для обычного клиента, но она не позволяет данным сценарием измерить внутреннюю capacity Gateway/Auth Service.

## Что можно утверждать

1. Gateway стабильно обслуживает разрешённые политикой 5 RPS с одного IP с p95 менее 8 ms.
2. При превышении лимита система быстро и контролируемо отклоняет запросы, не перегружая pod'ы.
3. Две реплики не увеличивают per-IP throughput, потому что rate-limit state общий в Redis.
4. На протестированном уровне железо и сервисы не являются bottleneck.

## Что пока нельзя утверждать

- максимальную hardware capacity Gateway;
- per-replica throughput;
- N+1 capacity;
- scaling efficiency для HPA;
- capacity бизнес-сценариев Ticket/Dispatch/Analytics;
- поведение при длительном soak или spike.

## Рекомендации для следующего измерения

1. Добавить явный load-test профиль rate limiter только для непроизводственного окружения либо генерировать подтверждённые независимые client identities/IP.
2. Запускать k6 внутри кластера через обычный Service, а не port-forward, чтобы проверить балансировку двух реплик.
3. Собирать Prometheus snapshot на каждую measurement-ступень: Gateway CPU/RAM, Redis latency, Auth gRPC latency, restarts и Envoy response codes.
4. После снятия policy ceiling повторить ступени 25/50/100 RPS, останавливаясь при CPU около 60–70%, росте p95 либо error rate выше 0.1%.
5. Только после нескольких resource scaling points рассчитывать N+1 и экстраполяцию на серверное железо.

## Артефакты и проверка framework

- Raw successful boundary run: `load-tests/results/raw/20260901T052934Z-gateway-ratelimit-boundary/`
- Raw ceiling probe: `load-tests/results/raw/20260901T051702Z-gateway-gentle/`
- Проверки framework: `go test ./load-tests/...` и `go vet ./load-tests/...` — успешно.

Итоговая классификация: **capacity confirmed up to 5 RPS per client IP; higher internal capacity remains unmeasured due to policy bottleneck**.
