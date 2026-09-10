# Location Service: контракт реализации

Сервис реализован как gRPC API с отдельным HTTP endpoint для автомобильных транспондеров. Текущие координаты хранятся в Redis, история пакетно записывается в PostgreSQL/PostGIS, а потеря сигнала атомарно добавляется в Redis Stream и публикуется в Kafka отдельным relay.

## Границы хранилищ

- `CurrentLocationRepo` — Redis: последняя позиция, sequence, время последнего сигнала, текущий signal status и быстрый geo-index.
- `PositionHistoryRepo` — PostgreSQL/PostGIS: пакетная запись неизменяемой истории через `pgx.CopyFrom` и временные/географические выборки.
- `GeoZoneRepo` — PostgreSQL/PostGIS: геометрия зон и `ST_Contains`/`ST_Covers`.
- Redis Stream `locations:events` хранит только события потери сигнала `BrigadeSignalLost`. Позиции и операции с геозонами в Kafka не публикуются.

## PositionService

### `RecordPosition`

1. Валидирует envelope и телеметрию.
2. Проверяет `event_id` на дедупликацию. Повтор того же события возвращает уже принятый результат с `Duplicate=true`, не создавая историю и события второй раз.
3. Сверяет `sequence` с последним sequence устройства. Меньшее или равное значение от нового события отклоняет как `ErrOutOfOrderPosition`; это не относится к точному дублю `event_id`.
4. При необходимости проверяет, что device/vehicle действительно закреплены за brigade. Эту внешнюю зависимость лучше вынести в отдельный checker-интерфейс при подключении реестра транспорта.
5. Сразу обновляет актуальную позицию в Redis, затем неблокирующе передаёт точку в `PositionHistorySink`. Ошибка/переполнение исторического буфера логируется, но не отменяет уже принятое обновление Redis.
6. Геозоны в обработке телеметрии не вычисляются: они используются только явными API `CheckPointInZones` и `FindNearbyBrigades`.
7. Если Redis временно недоступен, история не должна теряться: вернуть dependency error или запланировать восстановление hot state из последней SQL-точки — выбранную политику нужно закрепить тестом.

### `GetCurrentLocation`

Получает последнюю позицию по brigade, vehicle или device. Основной источник — Redis. Рассчитывает `ONLINE/STALE/OFFLINE` по возрасту точки. Для отсутствующего ключа допустим fallback на последнюю SQL-точку с восстановлением кэша; если данных нет вообще, возвращает `ErrNotFound`.

### `GetCurrentLocations`

Пакетный вариант для Routing/Dispatch. Читает Redis pipeline/MGET, сохраняет соответствие с входными brigade IDs, кладёт ненайденные IDs в `Missing`. При `AllowStale=false` stale/offline позиции не выдаёт как пригодные для маршрутизации.

### `ListPositionHistory`

Возвращает точки одной бригады за полуинтервал `[From, To)`, сортирует по `RecordedAt` и `Sequence`, применяет limit/offset и отдельно считает total. Запрос должен использовать пространственно-временной индекс без чтения Redis.

### `FindNearbyBrigades`

Ищет последние позиции в радиусе, считает расстояние в метрах и сортирует по возрастанию расстояния. Если задан `BrigadeIDs`, поиск ограничивается кандидатами Brigade Service. При `OnlyFresh=true` исключает точки старше `FreshnessWindow`. Для малого списка кандидатов подходит Redis GEO; для сложных исторических/точных запросов — PostGIS `ST_DWithin`.

### `DetectLostSignals`

Фоновая функция. Пакетно находит позиции, перешедшие из `ONLINE` в `STALE` и из `STALE` в `OFFLINE`. При переходе в `OFFLINE` один Lua-скрипт меняет статус и выполняет `XADD BrigadeSignalLost`. Повторный запуск не создаёт вторую запись. `OfflineBefore` должен быть старше `StaleBefore`.

## GeoZoneService

### `CreateGeoZone`

Проверяет роль администратора/диспетчера и принадлежность department, валидирует GeoJSON как Polygon/MultiPolygon, нормализует SRID 4326, исправность геометрии проверяет через `ST_IsValid`, затем сохраняет зону. События изменений зон не публикуются.

### `UpdateGeoZone`

Загружает существующую зону, проверяет доступ актора и обновляет только переданные поля. При смене геометрии повторяет полную PostGIS-валидацию.

### `DeleteGeoZone`

Выполняет soft delete (`active=false`), сохраняя геометрию для административного просмотра.

### `ListGeoZones`

Выдаёт зоны с фильтрами department/active и пагинацией. GeoJSON можно возвращать полностью для админского API; для внутренних проверок лучше не сериализовать геометрию без необходимости.

### `CheckPointInZones`

Выполняет point-in-polygon для координаты, опционально ограничивая department или явным списком zone IDs. Для граничной точки используйте `ST_Covers`, если граница должна считаться частью зоны; не смешивайте это поведение с `ST_Contains`.

## Repository-функции

- `SaveCurrentLocation` — атомарно обновляет Redis только если входной sequence новее сохранённого; обновляет TTL и geo-index.
- `GetCurrentLocation` — читает один current-state ключ по выбранному типу субъекта.
- `GetCurrentLocations` — пакетно читает current-state для brigade IDs без N отдельных round-trip.
- `FindNearbyBrigades` — возвращает кандидатов с расстоянием и уже загруженной текущей позицией.
- `DetectLostSignals` — переводит только ещё не обработанные статусы и атомарно добавляет потерю сигнала в Redis Stream.
- `AppendPositionsBatch` — преобразует однотипные точки в строки и напрямую вызывает `pgx.CopyFrom` для `position_history`; возвращает число записанных строк. При ошибке весь извлечённый батч считается потерянным и не блокирует следующие батчи.
- `ListPositionHistory` — временная выборка с детерминированной сортировкой и total.
- `CreateGeoZone`, `UpdateGeoZone`, `DeleteGeoZone`, `ListGeoZones` — CRUD зон с PostGIS geometry, а не с произвольной строкой в БД.
- `CheckPointInZones` — один пространственный SQL-запрос, не цикл запросов по зонам.

### Redis current-location layout

- `location:brigade:<uuid>` — Hash с последней полной позицией бригады.
- `location:device:<id>:brigade` и `location:vehicle:<uuid>:brigade` — ссылки для поиска позиции по device/vehicle.
- `locations:brigades:geo` — общий GEO-индекс активных бригад.
- `locations:signal:last_seen` — sorted set, где score равен `received_at` в Unix milliseconds; используется без `KEYS`/`SCAN` для поиска stale/offline сигналов.
- `locations:events` — Redis Stream событий `BrigadeSignalLost`; Kafka relay читает его через consumer group, после успешной публикации выполняет `XACK` и `XDEL`.
- `SaveCurrentLocation` выполняет проверку sequence, обновление Hash, mappings, GEO и signal-index одним Lua-скриптом. Это рассчитано на single-master/Sentinel. В Redis Cluster эти ключи попадут в разные slots и потребуют иной схемы hash tags либо неатомарного обновления.

## Position history worker

- `MemoryPositionBuffer.Add` — быстро добавляет точку в ограниченный FIFO; при заполнении возвращает `ErrPositionBufferFull`, не блокируя обработчик.
- `MemoryPositionBuffer.TakeBatch` — атомарно извлекает до указанного числа самых старых точек.
- `Worker.Add` — вход для service; будит worker при достижении `BatchSize`.
- `Worker.Run` — сбрасывает полные батчи сразу, остаток каждые `FlushInterval` (по умолчанию 5 секунд), а при shutdown пытается записать остаток в пределах `ShutdownTimeout`.
- Ошибка `CopyFrom` логируется как потерянный батч. Точки не возвращаются в память и не ретраятся, потому что актуальная координата уже находится в Redis, а SQL-история является best effort.

## Минимальные ограничения БД

- UTC для всех времён; координаты — WGS84/SRID 4326.
- `UNIQUE(event_id)` и `UNIQUE(device_id, sequence)` для истории.
- Индекс `(brigade_id, recorded_at DESC)` и GiST по географической точке.
- GiST по geometry зоны, check latitude/longitude/heading/speed/accuracy.
- Redis Stream relay публикует только `BrigadeSignalLost` в `locations.events.v1`; consumer должен быть идемпотентным по `event_id`.
