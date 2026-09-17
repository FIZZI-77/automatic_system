# Руководство разработчика

## Добавление нового synchronous dependency

Перед добавлением service-to-service gRPC call:

1. Определить, действительно ли результат нужен **до завершения текущего request**.
2. Не переносить ownership чужой модели в orchestrating service.
3. Добавить timeout/cancellation propagation.
4. Передавать request/trace context.
5. Обработать partial failure и, если workflow многошаговый, compensation.
6. Обновить `docs/architecture/code-interactions.md` и эту Wiki.

Если реакция может быть независимой и eventual, предпочтительнее domain event.

## Добавление Kafka event

Для outbox-based service:

1. Изменить domain transaction.
2. В той же DB transaction сохранить outbox row.
3. Версионировать event schema/topic contract.
4. Сделать consumer idempotent.
5. Отделить retry от повторного business effect.
6. Добавить observability по failures/backlog.
7. Добавить consumer только после того, как publisher path реально существует.
8. Обновить таблицу [Event-Driven Architecture](Event-Driven-Architecture).

## Изменение DB schema

Deployment использует canary/rolling mechanics, а schema rollback Helm не выполняет. Поэтому migration должна позволять coexistence старой и новой application versions на период rollout.

Практический порядок:

- расширить схему;
- развернуть совместимый код;
- перенести данные и начать использовать новые поля;
- contract/remove old schema отдельным выпуском.

## Добавление сервиса

Минимальный checklist:

- отдельный Go module;
- запуск и корректное завершение;
- health checks, метрики и трассировка;
- границы домена, сервиса и репозитория;
- миграции;
- модель авторизации;
- Dockerfile;
- ресурсы Helm/Kubernetes;
- матрица CI и определение сборок;
- dashboards/alerts при наличии новых SLI;
- README и страница сервиса в Wiki.

## Источники of truth

Архитектурную стрелку следует добавлять только при наличии client creation/call, consumer startup или publisher worker в исполняемом коде.

### Источники
[Verified interaction map](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
