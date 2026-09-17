# Жизненный цикл заявки

## Состояния заявки

```mermaid
stateDiagram-v2
    [*] --> NEW
    NEW --> ASSIGNED
    ASSIGNED --> IN_PROGRESS
    IN_PROGRESS --> DONE
    NEW --> CANCELED
    ASSIGNED --> CANCELED
    IN_PROGRESS --> CANCELED
```

`DONE` и `CANCELED` — terminal states прикладной модели. В базе также предусмотрен `ARCHIVED` для хранения старых данных, но он не входит в публичный `TicketStatus`.

## Создание

1. Пользователь аутентифицируется через Auth.
2. Frontend отправляет HTTP request в Gateway.
3. Gateway проверяет JWT и вызывает Ticket по gRPC.
4. Ticket сохраняет заявку и outbox event.
5. `tickets.events.v1` может быть обработан SLA, Notification, Audit, Analytics и другими consumers.

## Назначение

```mermaid
sequenceDiagram
    participant D as Dispatch
    participant T as Ticket
    participant B as Brigade
    participant L as Location
    participant R as Routing

    D->>T: Get NEW ticket
    D->>B: List available brigades
    D->>L: Read fresh positions
    D->>R: Rank candidates
    loop candidates
        D->>B: Reserve candidate
    end
    D->>L: Read selected position
    D->>R: Create route
    D->>T: Assign brigade
```

При ошибке подтверждения Dispatch выполняет компенсацию достигнутых шагов — например, отменяет маршрут или освобождает бригаду.

## Выполнение

Worker может перевести назначенную своей бригаде заявку в `IN_PROGRESS`, затем в `DONE`, и добавить work report.

## Отчёт о завершении

```mermaid
sequenceDiagram
    participant GW as API Gateway
    participant T as Ticket
    participant K as Kafka
    participant R as Report
    participant F as File

    GW->>T: Create WorkReport
    T->>T: Save PENDING + outbox
    T-->>K: completion report request
    K-->>R: consume
    R->>F: store generated document
    R-->>K: generated / failed
    K-->>T: persist result
```

Источник истины о work report остаётся в Ticket; Report отвечает за формирование artifact.

### Источники
- [Ticket Service README](https://github.com/FIZZI-77/automatic_system/blob/test/Ticket_Service/README.md)
- [Dispatch Service README](https://github.com/FIZZI-77/automatic_system/blob/test/Dispatch_Service/README.md)
