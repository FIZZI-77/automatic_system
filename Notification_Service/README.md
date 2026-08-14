# Notification Service

Consumes domain events and creates durable user notifications. PostgreSQL is the source of truth; Redis Pub/Sub provides live fan-out to Gateway WebSocket connections.

Channels are independent deliveries: in-app/WebSocket, FCM push, SMTP email and pluggable SMS. Failed delivery uses exponential backoff and becomes `DEAD` after eight attempts. Invalid FCM tokens are deactivated automatically.

FCM uses the HTTP v1 API. Set `FCM_SERVICE_ACCOUNT_FILE` to a mounted Google service-account JSON file. Push data contains only non-sensitive identifiers such as `ticket_id`; personal data is never included.

WebSocket endpoint: `ws://localhost:8081/notifications/ws?access_token=<JWT>`. Production must use `wss://` so the query token is encrypted in transit. After reconnect, clients should call `/notifications/list` to recover messages delivered while offline.
