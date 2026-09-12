# Сеть Istio

`policies/` содержит правила для `local-ha` и `prod`:

- строгий mTLS для приложений пространства `automatic-system`;
- точечные исключения для входных портов, метрик и инфраструктуры без sidecar;
- ограничения пулов соединений;
- аудит неаутентифицированного доступа к внутренним сервисам.

Patroni, PgBouncer, Kafka, Redis, MinIO и часть наблюдаемости работают без
sidecar. Поэтому нельзя заменять автоматический выбор mTLS общим
`DestinationRule` с `ISTIO_MUTUAL` для всех адресов: инфраструктура не
сможет принять такой трафик.

## Проверка канареечного маршрута

`scenarios/api-gateway-canary.yaml` применяется только вручную и не
заменяет рабочие Canary Flagger. Перед применением нужно запустить основной и
канареечный Gateway за одной службой и разметить шаблоны подов:

```yaml
app.kubernetes.io/version: stable
```

```yaml
app.kubernetes.io/version: canary
```

После применения проверьте долю трафика 90/10, mTLS, ошибки и длительность в
Kiali. Повторные запросы настроены только для `/livez` и `/readyz`;
предметные операции не повторяются без гарантии идемпотентности.

Не включайте принудительный `AuthorizationPolicy`, пока приложения
используют общую учетную запись Kubernetes `default`: Istio не сможет
надежно отличить идентичность Gateway от внутренних сервисов.

## Входящий шлюз

Локальные адреса:

| Адрес | Назначение |
|---|---|
| `https://city.localhost` | Frontend. |
| `https://api.city.localhost` | API Gateway. |

Браузер подключается к шлюзу по TLS; до API Gateway шлюз использует h2c, а до
текущего сервера Frontend — HTTP/1.1. `install-mesh.ps1` устанавливает Istio,
Kiali и входной шлюз. Локальный самоподписанный сертификат выдается на два
года; его нужно принять или добавить в доверенные сертификаты.

Ротация:

```powershell
.\k8s\scripts\setup-ingress.ps1 -RotateCertificate
```

Состав манифестов и исключения mTLS описаны в
[`manifests.md`](../docs/manifests.md) и
[`security-observability.md`](../docs/security-observability.md).
