# Сервис объектов инфраструктуры (Asset Service)

## Ответственность

Реестр городской инфраструктуры: geometry, state history, incidents, repairs, inspections и maintenance plans.

## Ключевое поведение

- Spatial search выполняется через PostGIS.
- После incident/repair/inspection пересчитывается failure risk.
- Risk calculation — объяснимая rule/score formula, а не ML model.
- Domain changes публикуются через transactional outbox.
- При переходе риска в `CRITICAL` публикуется событие
  `asset.RISK_BECAME_CRITICAL`. Опциональный Kafka worker создаёт связанную
  заявку в Ticket Service, если настроены категория и системный заявитель.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL/PostGIS. |
| Синхронные взаимодействия | Опциональный gRPC-клиент Ticket Service для создания заявки по критическому риску. |
| Kafka | Publisher и внутренний consumer: `assets.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Полные сигнатуры и структуры параметров приведены в [справочнике функций Asset Service](https://automaticsystem.youtrack.cloud/articles/ACS-A-32/Kod-i-funkcii-Asset-Service).

### `NewService`

```go
func NewService(r repository.AssetRepository, l *zap.Logger) *Service
```

Создает оболочку `Service` и реализацию с репозиторием и журналом.

### `Create`

```go
func (s *AssetServiceStruct) Create(c context.Context, v models.CreateInput, p bool) (*models.Asset, error)
```

Требует право изменения, ненулевое подразделение, название, тип и геометрию.
Критичность должна быть от 0 до 1. После проверки вызывает репозиторий и
записывает созданный идентификатор и тип в журнал.

### `Get`

```go
func (s *AssetServiceStruct) Get(c context.Context, id uuid.UUID) (*models.Asset, error)
```

Возвращает объект по UUID напрямую из репозитория.

### `Update`

```go
func (s *AssetServiceStruct) Update(c context.Context, v models.UpdateInput, p bool) (*models.Asset, error)
```

Требует право изменения. Если критичность передана, проверяет диапазон 0–1,
после чего выполняет частичное обновление и журналирует успех.

### `List`

```go
func (s *AssetServiceStruct) List(c context.Context, f models.Filter) ([]*models.Asset, int64, error)
```

Нормализует `Limit`: неположительное значение заменяет на 20, значение больше
100 — на 100. Передает фильтр и смещение репозиторию.

### `ChangeStatus`

```go
func (s *AssetServiceStruct) ChangeStatus(c context.Context, id uuid.UUID, st models.Status, a uuid.UUID, reason string, p bool) (*models.Asset, error)
```

Требует право изменения и передает объект, новое состояние, автора и причину
репозиторию. Репозиторий изменяет карточку и пишет историю состояния.

### `Nearby`

```go
func (s *AssetServiceStruct) Nearby(c context.Context, lat, lon, r float64, t *string, l int32) ([]*models.Asset, error)
```

Проверяет широту от -90 до 90, долготу от -180 до 180 и положительный радиус.
Предел вне диапазона 1–100 заменяет на 20. Передает координаты, радиус,
необязательный тип и предел пространственному запросу репозитория.

### `Incident`

```go
func (s *AssetServiceStruct) Incident(c context.Context, v models.Incident, p bool) (*models.Incident, *models.Prediction, error)
```

Требует право изменения, записывает аварию через `RecordIncident`, затем
немедленно вызывает `calculate` для объекта. Возвращает и аварию, и новый
прогноз; ошибка расчета возникает уже после успешной записи аварии.

### `Repair`

```go
func (s *AssetServiceStruct) Repair(c context.Context, v models.Repair, p bool) (*models.Repair, *models.Prediction, error)
```

Требует право, завершает ремонт и затем пересчитывает риск. Как и для аварии,
ошибка расчета не отменяет уже сохраненный ремонт.

### `Inspection`

```go
func (s *AssetServiceStruct) Inspection(c context.Context, v models.Inspection, p bool) (*models.Inspection, *models.Prediction, error)
```

Требует право и оценку состояния от 0 до 1. Записывает осмотр и пересчитывает
риск объекта.

### `CreatePlan`

```go
func (s *AssetServiceStruct) CreatePlan(c context.Context, v models.Plan, p bool) (*models.Plan, error)
```

Требует право и положительный `IntervalDays`, затем создает план через
репозиторий.

### `Due`

```go
func (s *AssetServiceStruct) Due(c context.Context, d *uuid.UUID, t time.Time, l, o int32) ([]*models.Plan, int64, error)
```

Заменяет неположительный предел на 20. Возвращает планы, срок которых наступил
к моменту `t`, с необязательным ограничением по подразделению и смещением.
Верхняя граница предела в прикладном слое не задается.

### `Prediction`

```go
func (s *AssetServiceStruct) Prediction(c context.Context, id uuid.UUID) (*models.Prediction, error)
```

Пытается прочитать последний прогноз. Только если репозиторий сообщает «не
найдено», рассчитывает и сохраняет новый прогноз на текущее время UTC.
Остальные ошибки возвращает без пересчета.

### `Recalculate`

```go
func (s *AssetServiceStruct) Recalculate(c context.Context, d *uuid.UUID, p bool) (int64, error)
```

Требует право, получает идентификаторы объектов выбранного подразделения или
всех объектов и последовательно вызывает `calculate`. При первой ошибке
останавливается и возвращает число уже пересчитанных объектов.

### `calculate`

```go
func (s *AssetServiceStruct) calculate(c context.Context, id uuid.UUID, now time.Time) (*models.Prediction, error)
```

1. Загружает факты риска на момент `now`.
2. Начинает с `Criticality * 20`.
3. При известном положительном сроке службы добавляет не более 25 баллов:
   `age / serviceLife * 25`. При доле не меньше 0,8 добавляет причину об
   исчерпании срока.
4. За события 90 дней добавляет не более 25 баллов:
   `Incidents90 * 7 + Repeat90 * 5`. Повторы добавляют отдельную причину.
5. За просрочку осмотра добавляет не более 15 баллов:
   `DaysInspectionOverdue / 10`.
6. При известной последней оценке состояния добавляет
   `(1 - LastCondition) * 15`; значение ниже 0,5 отмечается как плохое.
7. Ограничивает сумму 100 и округляет до одной десятой.
8. Назначает уровень: `MEDIUM` от 35, `HIGH` от 60, `CRITICAL` от 75,
   иначе `LOW`; одновременно выбирает текст рекомендации.
9. Вычисляет вероятность:
   `round((1 - exp(-score / 55)) * 1000) / 10`.
10. Сохраняет прогноз и возвращает его.

При переходе сохраненного уровня риска в `CRITICAL` репозиторий дополнительно
формирует payload для `asset.RISK_BECAME_CRITICAL`: объект, подразделение,
адрес, координаты точки внутри геометрии и сам прогноз. Проверка старого уровня
выполняется под `FOR UPDATE`, поэтому повторный пересчет уже критичного объекта
не публикует новое событие для создания заявки.

### `criticalticket.Worker`

Читает `assets.events.v1` в группе `asset-critical-ticket-v1` и обрабатывает
только `asset.RISK_BECAME_CRITICAL`. Для события вызывает
`TicketService.CreateTicket` с системным requester, категорией из конфигурации,
приоритетом `HIGH`, адресом и координатами объекта, а также `asset_id`.

Повторная доставка Kafka-сообщения защищена metadata
`x-idempotency-key=asset-critical-risk:<event_id>`; offset коммитится только
после успешного ответа Ticket Service. Если обязательные настройки категории или
requester не заданы, worker не запускается.

### `logger`

```go
func (s *AssetServiceStruct) logger() *zap.Logger
```

Возвращает настроенный `zap.Logger`, а при его отсутствии — `zap.NewNop()`.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Asset_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Asset_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
