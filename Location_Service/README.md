# Location Service

Сервис принимает GPS-телеметрию, хранит актуальную позицию в Redis, пакетно сохраняет историю в PostGIS, выполняет GEO-поиск и обнаруживает потерю сигнала.

## Запуск

Локальная инфраструктура:

```bash
docker compose up --build
```

Порты:

- `50056` — gRPC `location.v1.LocationService`;
- `8080` — HTTP ingestion и health check;
- `5436` — PostgreSQL/PostGIS;
- `6380` — Redis.

Все gRPC/HTTP-запросы получают `request_id` и пишутся структурированным JSON через `zap`. Уровень задаётся `LOG_LEVEL` (`debug`, `info`, `warn`, `error`). Для gRPC поддерживаются metadata `x-request-id` и `x-actor-roles`.

Graceful shutdown выполняется в фиксированном порядке: HTTP/gRPC прекращают принимать запросы, затем останавливаются и ожидаются фоновые worker-ы (history worker сбрасывает остаток буфера), после чего `closer` в обратном порядке закрывает Kafka writer, Redis и PostgreSQL.

Без Docker скопируйте `.env.example`, задайте `DATABASE_URL` и запустите:

```bash
go run ./src/cmd/server
```

## Телеметрия

Transponder Simulator отправляет envelope на:

```text
POST /v1/positions
```

При заданном `TRANSPONDER_API_KEY` обязателен заголовок `X-Transponder-Key`.

## События

В Kafka topic `locations.events.v1` публикуется только `BrigadeSignalLost`. Статус и запись Redis Stream создаются атомарно. Relay использует consumer group и удаляет запись только после подтверждённой публикации. Если `KAFKA_BROKERS` пуст, события остаются в Redis Stream.

## Контракты

Исходный protobuf находится в `C:\contracts\location\v1\location.proto`, сгенерированный Go-код — в `C:\contracts\gen\go\location\v1`.
