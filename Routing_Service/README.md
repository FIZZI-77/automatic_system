# Routing Service

Routing Service calculates road routes and ETA through Valhalla, ranks brigade candidates, persists assigned route calculations and publishes durable route events.

## gRPC

The service implements the contract from `routing/v1/routing.proto`:

- BuildRoute
- BuildMatrix
- RankCandidates
- CreateRoute
- GetRoute
- RecalculateRoute
- SetRouteStatus
- ListRoutes

## Valhalla

The adapter uses:

- `POST /route` for route geometry, distance and ETA
- `POST /sources_to_targets` for candidate ranking
- `truck` costing options for vehicle dimensions, weight, axle load and hazardous materials

## Storage

PostgreSQL stores routes and the transactional outbox. Route creation, recalculation and status transitions are published to `routing.events.v1`.

## Local checks

```bash
go test ./...
go vet ./...
```
