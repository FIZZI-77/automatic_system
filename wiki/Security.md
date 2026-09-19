# Безопасность

## Аутентификация

Auth Service хранит пароль как bcrypt hash. Refresh и one-time tokens не сохраняются в открытом виде; для них хранится hash. Access token — RSA-signed JWT.

API Gateway проверяет:

- Bearer token;
- алгоритм подписи;
- issuer/audience;
- expiry;
- затем помещает проверенный identity/roles в request context.

Доменный handler не должен доверять `user_id`, `actor_*` и ролям, присланным клиентом.

## Секреты

В Git не должны попадать:

- JWT private/public key material;
- database passwords;
- Firebase service account;
- учётные данные постоянного внешнего туннеля, если он используется;
- kubeconfig;
- production runtime secrets.

Для production документация рекомендует внешнее хранилище секретов вместо
локальной генерации. Tailscale Funnel, применяемый для разработки, не требует
покупки домена, но требует учётную запись Tailscale и доступную рабочую машину.

## Сетевые границы Kubernetes

В `local-ha` и `prod` приложения работают с Istio sidecar. Инфраструктурные StatefulSet/Deployments вроде PostgreSQL, Kafka, Redis, MinIO, ClickHouse и Valhalla исключаются из sidecar injection.

Используются два уровня:

1. `NetworkPolicy` — L3/L4 connectivity.
2. Istio mTLS / AuthorizationPolicy — service identity и application traffic.

## Ограничение AuthorizationPolicy

В текущей конфигурации enforcement для части service-to-service identity намеренно не включён: приложения используют общий ServiceAccount `default`. До строгого SPIFFE-based enforcement каждому workload нужен отдельный ServiceAccount.

## Ограничение частоты запросов

Gateway использует Redis-backed rate limits. Публичные auth routes имеют отдельные, более строгие лимиты; health checks исключаются из глобального лимита.

## Аудит

Audit Service делает записи append-only. Дедупликация обеспечивается `UNIQUE(topic, event_id)`, а PostgreSQL trigger запрещает UPDATE/DELETE существующей audit row.

### Источники
- [Auth README](https://github.com/FIZZI-77/automatic_system/blob/test/Auth_Service/README.md)
- [API Gateway README](https://github.com/FIZZI-77/automatic_system/blob/test/API_Gateway/README.md)
- [Security and observability](https://github.com/FIZZI-77/automatic_system/blob/test/k8s/docs/security-observability.md)
