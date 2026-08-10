# Routing Service development

The domain service depends on two abstractions:

- `RoutingEngine` calculates routes and matrices.
- `RouteRepository` persists routes and route events.

Valhalla-specific JSON is isolated in `src/infrastructure/valhalla`. PostgreSQL code is isolated in `src/core/repository`.

A route status follows these transitions:

```text
PLANNED -> ACTIVE -> COMPLETED
    \          \-> CANCELLED
     \------------> CANCELLED
```

Routing Service does not assign brigades. Dispatch Service owns assignment and passes the selected ticket and brigade to Routing Service.
