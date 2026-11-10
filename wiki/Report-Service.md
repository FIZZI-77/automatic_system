# Сервис отчётов (Report Service)

## Ответственность

Асинхронное формирование PDF/XLSX/CSV analytics reports и completion documents.

## Ключевое поведение

- Жизненный цикл задания: `PENDING → PROCESSING → COMPLETED`; ошибка → `FAILED`; отмена → `CANCELED`.
- `ProcessNext` использует `FOR UPDATE SKIP LOCKED`, что допускает несколько workers.
- Данные берутся из Analytics; готовый artifact сохраняется через File.
- Completion report имеет отдельный event-driven path от Ticket.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL; готовые binary artifacts идут в File/S3. |
| Синхронные взаимодействия | Analytics и File. |
| Kafka | Consumer: `tickets.events.v1`; publisher: `reports.events.v1`. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Полные сигнатуры и структуры параметров приведены в [справочнике функций Report Service](https://automaticsystem.youtrack.cloud/articles/ACS-A-38/Kod-i-funkcii-Report-Service).

### `Create`

```go
func (s *ReportServiceStruct) Create(c context.Context, v models.CreateInput) (*models.Report, error)
```

Проверяет `CreateInput`, создает через репозиторий задание `PENDING` и при
успехе записывает идентификатор, вид и формат в журнал. Возвращает созданный
`Report`.

### `Get`

```go
func (s *ReportServiceStruct) Get(c context.Context, id, actor uuid.UUID, privileged bool) (*models.Report, error)
```

Загружает отчет. Если вызывающий не является владельцем и не имеет
привилегированного признака, возвращает `ErrForbidden`. Ошибка репозитория
возвращается без преобразования.

### `List`

```go
func (s *ReportServiceStruct) List(c context.Context, actor uuid.UUID, privileged bool, status *models.Status, limit, offset int32) ([]*models.Report, int64, error)
```

Нормализует размер страницы: значение не больше нуля заменяет на 20, больше
100 — на 100. Для непривилегированного пользователя добавляет ограничение по
`RequestedBy`; привилегированный пользователь может видеть все задания.
Возвращает страницу, общий счетчик и ошибку.

### `Cancel`

```go
func (s *ReportServiceStruct) Cancel(c context.Context, id, actor uuid.UUID, p bool) (*models.Report, error)
```

Сначала вызывает `Get`, тем самым проверяя существование и права. Затем
репозиторий отменяет только допустимое состояние. Если условное обновление не
нашло строку, метод возвращает `ErrInvalidState`.

### `Retry`

```go
func (s *ReportServiceStruct) Retry(c context.Context, id, actor uuid.UUID, p bool) (*models.Report, error)
```

Проверяет доступ через `Get`, после чего просит репозиторий вернуть допустимое
ошибочное задание в очередь. Отсутствие строки для условного перехода
преобразуется в `ErrInvalidState`.

### `Download`

```go
func (s *ReportServiceStruct) Download(c context.Context, id, actor uuid.UUID, roles []string, p bool) (models.Download, error)
```

Проверяет права через `Get`, требует `StatusCompleted` и непустой `FileID`.
Передает идентификаторы файла и пользователя вместе с ролями в
`FileStorage.Download`. Возвращает отчет, ссылку и срок ее действия.

### `ProcessNext`

```go
func (s *ReportServiceStruct) ProcessNext(c context.Context) (bool, error)
```

1. Вызывает `repo.Claim`. Отсутствие ожидающего задания возвращает
   `(false, nil)`.
2. Получает строки отчета через `AnalyticsSource.Build`.
3. Передает строки, имя и формат в `Generator.Generate`.
4. Загружает полученный `Artifact` через `FileStorage.Upload`.
5. Помечает задание завершенным и сохраняет `file_id`.
6. При ошибке любого этапа пытается записать `FAILED` и текст ошибки. Ошибка
   этой дополнительной записи журналируется отдельно.
7. Возвращает `true`, если задание было захвачено, даже когда обработка
   завершилась ошибкой.

### `log`

```go
func (s *ReportServiceStruct) log() *zap.Logger
```

Возвращает настроенный журнал. Если он отсутствует, возвращает
`zap.NewNop()`, поэтому вызовы журналирования безопасны.

### `NewService`

```go
func NewService(repo repository.ReportRepository, source AnalyticsSource, files FileStorage, generator Generator, logger *zap.Logger) *Service
```

Принимает репозиторий, источник аналитики, файловое хранилище, генератор и
журнал. Создает одну `ReportServiceStruct` и встраивает ее одновременно как
`ReportService` и `JobProcessor`.

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/Report_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/Report_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
