# Сервис уведомлений (Notification Service)

## Ответственность

Durable user notifications и channel deliveries.

## Ключевое поведение

- PostgreSQL — source of truth; live publisher используется поверх уже сохранённого notification.
- Ошибка live publish не отменяет DB record; после reconnect клиент может получить уведомление через List.
- Preferences управляют InApp/Push/Email/SMS delivery independently.
- FCM настраивается только при наличии соответствующего service account/key.
- `Consume` фильтрует события и создаёт уведомления только для разрешённого набора user-facing event types.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL + Redis + SMTP + optional FCM. |
| Синхронные взаимодействия | External providers; Gateway/Frontend читают notification API/live flow. |
| Kafka | Consumer многих `*.events.v1`; собственного Kafka publisher в текущем startup нет. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Полные сигнатуры и структуры параметров приведены в [справочнике функций Notification Service](https://automaticsystem.youtrack.cloud/articles/ACS-A-36/Kod-i-funkcii-Notification-Service).

### `New`

```go
func New(r *repository.Repository, p Publisher) *Service
```

Создает сервис с репозиторием и необязательным издателем живых уведомлений.

### `Consume`

```go
func (s *Service) Consume(c context.Context, e models.Event) error
```

1. Проверяет вид события через `isUserFacingEvent`; неизвестное событие
   считается успешно пропущенным.
2. Вызывает `ResolveRecipients`.
3. Передает событие и получателей в `Dispatch`, который сохраняет уведомления
   и доставки.
4. Для каждого созданного уведомления вызывает `live.Publish`, если издатель
   настроен.
5. Ошибка живого канала не возвращается и не отменяет сохраненные данные.

### `isUserFacingEvent`

```go
func isUserFacingEvent(eventType string) bool
```

Удаляет пробелы, приводит вид события к нижнему регистру и разрешает:
`ticket.created`, `ticket.assigned`, `ticket.status_changed`,
`ticket.completed`, `ticket.canceled`,
`ticket.completion_report.generated.v1` и
`ticket.completion_report.failed.v1`.

### `List`

```go
func (s *Service) List(c context.Context, u uuid.UUID, x *bool, l, o int32) ([]*models.Notification, int64, int64, error)
```

Передает пользователя, необязательный признак прочтения, предел и смещение
репозиторию. Возвращает страницу уведомлений, общее количество и число
непрочитанных.

### `MarkRead`

```go
func (s *Service) MarkRead(c context.Context, u, id uuid.UUID) (*models.Notification, error)
```

Помечает одно уведомление пользователя прочитанным. Ошибка отсутствующей строки
преобразуется функцией `mapErr` в `ErrNotFound`.

### `MarkAllRead`

```go
func (s *Service) MarkAllRead(c context.Context, u uuid.UUID) (int64, error)
```

Помечает прочитанными все уведомления пользователя и возвращает число
измененных строк.

### `GetPreferences` и `SavePreferences`

```go
func (s *Service) GetPreferences(c context.Context, u uuid.UUID) (*models.Preferences, error)
```

```go
func (s *Service) SavePreferences(c context.Context, v *models.Preferences) (*models.Preferences, error)
```

Первый метод читает настройки каналов пользователя. Второй передает всю
`Preferences` репозиторию для вставки либо обновления.

### `RegisterDevice`

```go
func (s *Service) RegisterDevice(c context.Context, v *models.Device) (*models.Device, error)
```

Приводит платформу к нижнему регистру, удаляет пробелы и требует непустой токен
и платформу `android`, `ios` или `web`. Затем регистрирует устройство
через репозиторий.

### `DeleteDevice`

```go
func (s *Service) DeleteDevice(c context.Context, u, id uuid.UUID) (*models.Device, error)
```

Удаляет либо деактивирует устройство конкретного пользователя. Отсутствие
строки преобразуется в `ErrNotFound`.

### `UpsertTemplate`

```go
func (s *Service) UpsertTemplate(c context.Context, v *models.Template) (*models.Template, error)
```

Требует непустые `EventType`, `Body` и `Channel`, после чего вставляет или
обновляет шаблон. Допустимость канала дополнительно защищена ограничением базы.

### `ListTemplates`

```go
func (s *Service) ListTemplates(c context.Context, e, ch *string, l, o int32) ([]*models.Template, int64, error)
```

Возвращает страницу шаблонов с необязательными ограничениями по событию и
каналу.

### `ListDeliveries`

```go
func (s *Service) ListDeliveries(c context.Context, st, ch *string, l, o int32) ([]*models.Delivery, int64, error)
```

Возвращает страницу попыток доставки с необязательными ограничениями по
состоянию и каналу.

### `mapErr`

```go
func mapErr(e error) error
```

Преобразует `pgx.ErrNoRows` в предметную `ErrNotFound`; остальные ошибки
возвращает без изменения.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Notification_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
