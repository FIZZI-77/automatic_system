# Brigade Service gRPC in Postman

Brigade Service сейчас дергается как raw gRPC, не как HTTP через API Gateway. Поэтому HTTP `postman_collection.json` для него не нужен: в Postman надо создавать `gRPC` request и подключать proto.

## Files

- `postman/brigade-service.grpc-examples.json` - готовые method/message/metadata для всех ручек.
- `postman/brigade-service.postman_environment.json` - переменные окружения для Postman.
- Proto: `C:\Users\zapru\GolandProjects\automatic-system-contracts\brigade\v1\brigade.proto`.

## Setup

1. Start Brigade Service on `localhost:50054`.
2. In Postman choose `New` -> `gRPC`.
3. Server URL: `{{brigade_grpc_addr}}` or `localhost:50054`.
4. Import proto:
   `C:\Users\zapru\GolandProjects\automatic-system-contracts\brigade\v1\brigade.proto`
5. Select service:
   `brigade.v1.BrigadeService`
6. Select method from `postman/brigade-service.grpc-examples.json`.
7. Paste `message` into Postman request body.
8. Add metadata from the selected example or from `common_metadata`.

## Common Metadata

```text
x-actor-user-id: {{actor_user_id}}
x-actor-department-id: {{actor_department_id}}
x-actor-roles: {{actor_roles}}
x-request-id: {{request_id}}
x-idempotency-key: {{idempotency_key}}
```

For read-only methods, `x-request-id` and `x-idempotency-key` are optional.
