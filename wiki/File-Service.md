# Файловый сервис (File Service)

## Ответственность

Метаданные файлов и безопасный доступ к S3-compatible object storage.

## Ключевое поведение

- Binary не проходит через gRPC: client загружает/скачивает его по presigned URL.
- Процесс: создание метаданных → PUT в S3 → подтверждение → связывание.
- Максимальный размер 25 MiB; README перечисляет JPEG/PNG/GIF/WebP/PDF/CSV/XLSX.
- Status включает `PENDING_UPLOAD`, `UPLOADED`, `LINKED`, `DELETED`, `QUARANTINED`.

## Зависимости

| Категория | Текущая реализация |
|---|---|
| Хранилища / внешние системы | PostgreSQL + S3-compatible storage/MinIO. |
| Синхронные взаимодействия | S3 API; Report использует File по gRPC. |
| Kafka | В текущем startup нет Kafka publisher и outbox. |

## Эксплуатационная интерпретация

Страница описывает реализованные границы сервиса в текущей ветке `test`. Конфигурационная переменная или подписка потребителя сама по себе не доказывает работоспособность полного сквозного сценария.

## Функции

Полные сигнатуры и структуры параметров приведены в [справочнике функций File Service](https://automaticsystem.youtrack.cloud/articles/ACS-A-41/Kod-i-funkcii-File-Service).

### `New`

```go
func New(repo *repository.Repository, store *storage.S3, ttl time.Duration, logger *zap.Logger) *Service
```

Сохраняет репозиторий, клиент S3, срок действия ссылок и журнал в `Service`.
Проверку доступности зависимостей не выполняет.

### `Create`

```go
func (s *Service) Create(ctx context.Context, in models.CreateInput) (*models.PresignedFile, error)
```

1. Оставляет от имени только базовую часть пути, удаляет пробелы.
2. Нормализует тип содержимого в нижний регистр.
3. Проверяет владельца, имя, положительный размер не более 25 МиБ и разрешенный
   тип.
4. Создает UUID и ключ вида `owner/id/name`.
5. Записывает метаданные со статусом `PENDING_UPLOAD`.
6. Получает подписанную ссылку загрузки с типом и контрольной суммой.
7. Возвращает файл, ссылку и вычисленный срок действия.

Если получение ссылки не удалось, созданная строка метаданных остается в базе.

### `Confirm`

```go
func (s *Service) Confirm(ctx context.Context, id, actor uuid.UUID, privileged bool) (*models.File, error)
```

Загружает файл и разрешает действие владельцу либо привилегированному
пользователю. Через `Stat` получает фактический размер и тип. При несовпадении
пытается перевести запись в `QUARANTINED`, записывает возможную ошибку этой
попытки и возвращает ошибку несоответствия. При совпадении переводит запись в
`UPLOADED`.

### `Link`

```go
func (s *Service) Link(ctx context.Context, id, actor uuid.UUID, privileged bool, in models.LinkInput) (*models.File, error)
```

Проверяет вид и UUID ресурса и права на файл. Нормализует вид ресурса для имени
каталога: оставляет латинские буквы, цифры, `-` и `_`, остальные символы
заменяет на `-`. Новый ключ имеет вид
`resource-type/resource-id/file-id-name`. Перемещает объект и обновляет
метаданные. Если обновление базы не удалось, пытается переместить объект
обратно. Если ключ уже совпадает, повторное перемещение не выполняется.

### `Download`

```go
func (s *Service) Download(ctx context.Context, id, actor uuid.UUID, privileged bool) (*models.PresignedFile, error)
```

Проверяет существование файла и права владельца, получает подписанную ссылку
скачивания и возвращает ее вместе с метаданными и сроком действия.

### `Delete`

```go
func (s *Service) Delete(ctx context.Context, id, actor uuid.UUID, privileged bool) error
```

Проверяет права, сначала удаляет объект из S3, затем переводит запись базы в
состояние удаления через репозиторий. Ошибка хранилища останавливает операцию.

### `List`

```go
func (s *Service) List(ctx context.Context, typ string, id, actor uuid.UUID, privileged bool) ([]*models.File, error)
```

Читает файлы, связанные с видом `typ` и идентификатором `id`.
Привилегированному пользователю возвращает список сразу. Для обычного
пользователя проверяет владельца каждого файла и отклоняет весь ответ, если
найден хотя бы один чужой файл.

### `IsNotFound`

```go
func IsNotFound(err error) bool
```

Возвращает результат `errors.Is(err, pgx.ErrNoRows)`, позволяя обработчику
преобразовать отсутствие строки в транспортную ошибку «не найдено».

## Источники

- [README сервиса](https://github.com/FIZZI-77/automatic_system/blob/test/File_Service/README.md)
- [Точка запуска и реализации](https://github.com/FIZZI-77/automatic_system/blob/test/File_Service/src/cmd/server/main.go)
- [Проверенная карта взаимодействий](https://github.com/FIZZI-77/automatic_system/blob/test/docs/architecture/code-interactions.md)
