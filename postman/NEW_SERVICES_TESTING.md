# Проверка Location, Routing и Dispatch

Коллекция: `new-services-gateway.postman_collection.json`.

## Подготовка

1. Запустить Docker Desktop и дождаться доступности Linux engine.
2. Скопировать корневой `.env.example` в `.env`, если локального `.env` ещё нет.
3. Запустить стек: `docker compose up --build`.
4. Убедиться, что `GET http://localhost:8081/health` возвращает `200`.
5. В Postman импортировать коллекцию и заполнить collection variables:
   - `email`, `password` — пользователь с ролью `dispatcher` или `admin`;
   - `actor_user_id` — ID этого пользователя;
   - `department_id`;
   - `brigade_id` и `cancel_brigade_id` — две активные доступные бригады департамента;
   - `vehicle_id`;
   - `ticket_id`, `auto_ticket_id`, `cancel_ticket_id` — три разные заявки в статусе `NEW`.

Бригады должны иметь нужные навыки и покрывать координаты заявки. Если `required_skill_ids` пуст, проверяются остальные ограничения бригады. Перед Dispatch необходимо выполнить `Record position`, чтобы Location Service знал актуальные координаты бригады.

## Порядок запуска

Запускать папки сверху вниз:

1. `00 Health and Auth` — получает JWT и сохраняет `access_token`.
2. `01 Location Service` — записывает позицию, проверяет current/batch/history/nearby и полный CRUD геозоны.
3. `02 Routing Service` — проверяет build, matrix, ranking и persisted route workflow.
4. `03 Dispatch Service` — проверяет preview, reserve/confirm, list, auto dispatch и reserve/cancel.

Коллекция автоматически сохраняет `geo_zone_id`, `route_id`, `dispatch_id` и `expected_version`. Не запускайте Confirm или Cancel повторно со старой версией: ожидаемый результат такого повтора — HTTP `409 Conflict`.

## Автоматические Go-тесты

Обычные тесты запускаются отдельно для каждого модуля, чтобы версии зависимостей сервисов не смешивались через workspace:

```powershell
$env:GOWORK='off'
cd API_Gateway; go test ./...
cd ../Dispatch_Service; go test ./...
cd ../Location_Service; go test ./...
cd ../Routing_Service; go test ./...
cd ../Ticket_Service; go test ./...
```

Integration-тесты Location и Routing используют testcontainers. При выключенном Docker они корректно пропускаются; для реальной проверки PostgreSQL Docker daemon должен быть запущен:

```powershell
cd Location_Service; go test -v ./src/integration
cd ../Routing_Service; go test -v ./src/integration
```

## Типовые причины ошибок Dispatch

- `403`: JWT не содержит роль `dispatcher` или `admin`.
- `409 ticket is not NEW`: заявка уже назначена либо закрыта.
- `409 brigade cannot handle ticket`: бригада занята, не покрывает точку или не имеет навыков.
- Location unavailable: сначала записать свежую позицию бригады.
- Routing unavailable: дождаться готовности Valhalla и загрузки карт.
- Version conflict: перечитать операцию через `/dispatch/get` и использовать актуальную `version` только для допустимого следующего перехода.
