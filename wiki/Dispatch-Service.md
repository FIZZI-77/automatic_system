# Сервис диспетчеризации (Dispatch Service)

## Ответственность

Workflow-координатор ручного и автоматического назначения бригады.

## Ключевое поведение

- Не владеет ticket/brigade/location/route aggregates; хранит собственную operation.
- Автоматический процесс: доступные бригады → свежие позиции → ранжирование маршрутов → резервирование кандидата → создание маршрута → назначение заявки.
- Использует version field для optimistic transitions.
- При частичной ошибке выполняет compensation: освобождение brigade и/или отмена route.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL. |
| Синхронные взаимодействия | Ticket, Brigade, Location, Routing. |
| Kafka | Publisher: `dispatch.events.v1`; consumer: `tickets.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Полные сигнатуры и структуры параметров приведены в [справочнике функций Dispatch Service](https://automaticsystem.youtrack.cloud/articles/ACS-A-28/Kod-i-funkcii-Dispatch-Service).

### `New`

```go
func New(repo *repository.Repository, deps Dependencies, ttl time.Duration, logger *zap.Logger) (*Service, error)
```

Требует непустой репозиторий и все четыре клиента. Неположительный срок резерва
заменяет на 2 минуты, отсутствующий журнал — на `zap.NewNop()`. Возвращает
ошибку до создания сервиса, если зависимость отсутствует.

### `Cleanup`

```go
func (s *Service) Cleanup(ctx context.Context) error
```

Пакетами по 100 переводит просроченные операции через `repo.Expire`. Для
каждой операции с бригадой пытается вернуть ей `AVAILABLE`. Продолжает, пока
репозиторий возвращает полный пакет; ошибка чтения останавливает цикл.

### `Preview`

```go
func (s *Service) Preview(ctx context.Context, in *models.RecommendInput) ([]models.Candidate, error)
```

1. Проверяет вход и заявку; предел по умолчанию 10, максимум 100.
2. Читает заявку и требует состояние `NEW`.
3. Запрашивает доступные бригады того же подразделения с нужными навыками;
   внутренний предел равен максимуму из `Limit * 3` и 20.
4. Получает только свежие текущие позиции и пропускает записи без координат.
5. Передает кандидатов и координаты заявки в `Routing.RankCandidates` для
   автомобильного режима.
6. Пропускает результат с неверным UUID или без позиции и возвращает
   нормализованный список.

### `Reserve`

```go
func (s *Service) Reserve(ctx context.Context, in *models.ReserveInput) (*models.Operation, error)
```

Проверяет заявку, бригаду и автора. Срок по умолчанию берет из сервиса и требует
диапазон от 15 секунд до 15 минут. Загружает новую заявку, строит снимок
операции в ручном режиме, сохраняет ее и вызывает `reserveExisting`.

### `AutoDispatch`

```go
func (s *Service) AutoDispatch(ctx context.Context, in *models.AutoInput) (*models.Operation, error)
```

Проверяет вход и задает предел кандидатов 10. Если есть `TriggerEventID`,
пытается найти уже созданную операцию и продолжить ее вместо создания повтора.
Иначе читает новую заявку, создает операцию `AUTOMATIC` и передает ее в
`resumeAutomaticLocked`.

### `resumeAutomaticLocked`

```go
func (s *Service) resumeAutomaticLocked(ctx context.Context, op *models.Operation, in *models.AutoInput) (*models.Operation, error)
```

Пытается получить блокировку операции в базе. Если блокировка занята, возвращает
текущее состояние без ошибки. При успехе гарантированно вызывает функцию
освобождения блокировки и продолжает `resumeAutomatic`; ошибка освобождения
только журналируется.

### `resumeAutomatic`

```go
func (s *Service) resumeAutomatic(ctx context.Context, op *models.Operation, in *models.AutoInput) (*models.Operation, error)
```

Терминальное состояние возвращает без действий. `RESERVED` продолжает через
`Confirm`, `CONFIRMING` — через `finishConfirm`, `PENDING` запускает
поиск. Метод записывает количество всех и достижимых кандидатов. Ошибки
ранжирования и записи события переводят операцию в `FAILED`. Пустой список
дает `NO_REACHABLE_BRIGADE`. Достижимые кандидаты перебираются по порядку:
неудачный резерв не завершает цикл, первый успешный сразу подтверждается.

### `Confirm`

```go
func (s *Service) Confirm(ctx context.Context, in *models.ConfirmInput) (*models.Operation, error)
```

Требует идентификаторы и положительную ожидаемую версию, затем проверяет
`RESERVED`, совпадение версии и наличие бригады. Читает заявку и позицию
бригады, строит автомобильный маршрут, проверяет UUID маршрута, переводит
операцию в `CONFIRMING` и вызывает `finishConfirm`. При сбое отменяет уже
созданный маршрут и/или освобождает бригаду через `failAndRelease`.

### `finishConfirm`

```go
func (s *Service) finishConfirm(ctx context.Context, op *models.Operation, actor uuid.UUID) (*models.Operation, error)
```

Требует бригаду и маршрут. Вызывает `Ticket.AssignBrigade`. Если вызов
завершился ошибкой, повторно читает заявку: совпадающая уже назначенная бригада
считается успешным ранее выполненным действием. Иначе маршрут отменяется,
бригада освобождается, операция становится `FAILED`. В конце
`repo.FinishConfirm` переводит ее в `ASSIGNED`.

### `Get` и `List`

```go
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.Operation, error)
```

```go
func (s *Service) List(ctx context.Context, in *models.ListInput) ([]*models.Operation, int64, error)
```

`Get` читает операцию по UUID. `List` допускает пустой вход, задает предел
50, отклоняет предел больше 200 и отрицательное смещение, затем возвращает
страницу и общий счетчик.

### `Cancel`

```go
func (s *Service) Cancel(ctx context.Context, in *models.CancelInput) (*models.Operation, error)
```

Проверяет автора, версию и UUID. Отмена разрешена только для `PENDING` и
`RESERVED` при совпавшей версии. Пустая причина заменяется на
`cancelled by dispatcher`. После перехода в `CANCELLED` зарезервированная
бригада освобождается.

### `reserveExisting`

```go
func (s *Service) reserveExisting(ctx context.Context, op *models.Operation, brigadeID uuid.UUID, skills []uuid.UUID, actor uuid.UUID) (*models.Operation, error)
```

Повторно убеждается, что заявка еще `NEW`, затем просит Brigade Service
проверить подразделение, координаты и навыки. Недопустимая бригада дает
`ErrConflict` с причинами. Допустимая переводится в `BUSY`, после чего
репозиторий фиксирует `RESERVED`. Если запись операции не удалась, статус
бригады компенсируется обратно в `AVAILABLE`.

### `getNewTicket`

```go
func (s *Service) getNewTicket(ctx context.Context, id uuid.UUID) (*ticketv1.Ticket, error)
```

Читает заявку. gRPC `NotFound` и пустой ответ преобразует в
`models.ErrNotFound`; состояние, отличное от `NEW`, — в
`models.ErrConflict`.

### `failAndRelease`

```go
func (s *Service) failAndRelease(ctx context.Context, op *models.Operation, actor uuid.UUID, cause error) (*models.Operation, error)
```

Определяет этап и код ошибки, переводит операцию в `FAILED`. Если переход тоже
не удался, объединяет исходную и новую ошибки. После успешного перехода
освобождает бригаду и возвращает исходную причину.

### `dispatchFailureCode` и `dispatchFailureStage`

```go
func dispatchFailureCode(err error) string
```

```go
func dispatchFailureStage(operation *models.Operation) string
```

Коды: `DEPENDENCY_NOT_FOUND` для `ErrNotFound`, `STATE_CONFLICT` для
`ErrConflict`, `DEPENDENCY_UNAVAILABLE` для gRPC `Unavailable`, иначе
`DISPATCH_FAILED`. Этап равен `ROUTING` для `RESERVED`,
`TICKET_ASSIGNMENT` для `CONFIRMING`, иначе `DISPATCH`.

### `operationInput`

```go
func operationInput(ticket *ticketv1.Ticket, ticketID, requestedBy uuid.UUID, mode models.Mode, ttl time.Duration) (models.CreateOperationInput, error)
```

Разбирает UUID подразделения и категории из заявки, удаляет приставку
`TICKET_PRIORITY_` из приоритета и отклоняет пустое или `UNSPECIFIED`
значение. Возвращает полный снимок для создания операции.

### `release` и `cancelRoute`

```go
func (s *Service) release(ctx context.Context, id, actor uuid.UUID) error
```

```go
func (s *Service) cancelRoute(ctx context.Context, id string)
```

Первая функция возвращает бригаде `AVAILABLE`, вторая переводит маршрут в
`CANCELLED`. Они предназначены для компенсации и только журналируют ошибку,
не возвращая ее вызывающему коду.

### `forwardMetadata`

```go
func forwardMetadata(ctx context.Context) context.Context
```

Если исходящие метаданные уже есть, сохраняет контекст. Иначе копирует входящие
gRPC-метаданные в исходящие, чтобы межсервисные вызовы получили пользователя,
роли и идентификаторы трассировки.

### `uuidStrings`

```go
func uuidStrings(values []uuid.UUID) []string
```

Создает строковый список UUID в том же порядке и заранее выделяет нужную
емкость.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Dispatch_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Dispatch_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
