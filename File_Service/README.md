# Файловый сервис (File Service)

## Общее описание и общий принцип работы

`File_Service` хранит метаданные файлов в PostgreSQL, а содержимое — в
S3-совместимом хранилище. Двоичные данные не проходят через gRPC: сервис выдает
временную подписанную ссылку, по которой клиент загружает или скачивает объект
напрямую.

Порядок загрузки: `Create` создает метаданные и ссылку, клиент выполняет
`PUT`, `Confirm` сверяет фактические размер и тип, затем `Link` связывает
файл с предметной сущностью. Максимальный размер равен 25 МиБ. Разрешены JPEG,
PNG, GIF, WebP, PDF, CSV и XLSX. Kafka и таблица исходящих событий не
используются.

## Модели

### `Status`

| Значение | Назначение |
|---|---|
| `PENDING_UPLOAD` | Метаданные созданы, загрузка еще не подтверждена. |
| `UPLOADED` | Объект проверен. |
| `LINKED` | Файл связан с предметной сущностью. |
| `DELETED` | Файл логически удален. |
| `QUARANTINED` | Размер или тип загруженного объекта не совпал с заявленными. |

### `File`

| Поле | Тип Go | Назначение |
|---|---|---|
| `ID` | `uuid.UUID` | Идентификатор файла. |
| `OwnerUserID` | `uuid.UUID` | Пользователь-владелец. |
| `ResourceType` | `*string` | Вид связанной сущности. |
| `ResourceID` | `*uuid.UUID` | Идентификатор связанной сущности. |
| `Name` | `string` | Безопасное базовое имя файла. |
| `ContentType` | `string` | Заявленный тип содержимого. |
| `Size` | `int64` | Размер в байтах. |
| `Checksum` | `string` | Контрольная сумма, передаваемая хранилищу. |
| `ObjectKey` | `string` | Внутренний ключ объекта; скрыт из JSON. |
| `Status` | `Status` | Текущее состояние. |
| `CreatedAt` | `time.Time` | Время создания. |
| `UpdatedAt` | `time.Time` | Время последнего изменения. |

### `CreateInput`

Входные данные для создания метаданных файла и получения ссылки на загрузку.

| Поле | Тип Go | Назначение |
|---|---|---|
| `OwnerUserID` | `uuid.UUID` | Владелец нового файла. |
| `Name` | `string` | Исходное имя. |
| `ContentType` | `string` | Ожидаемый тип содержимого. |
| `Size` | `int64` | Ожидаемый размер. |
| `Checksum` | `string` | Контрольная сумма. |

### `LinkInput`

Входные данные для привязки уже загруженного файла к предметной сущности.

| Поле | Тип Go | Назначение |
|---|---|---|
| `ResourceType` | `string` | Вид предметной сущности. |
| `ResourceID` | `uuid.UUID` | Идентификатор сущности. |

### `PresignedFile`

Результат операции, которая вместе с метаданными возвращает ограниченную по времени ссылку на объектное хранилище.

| Поле | Тип Go | Назначение |
|---|---|---|
| `File` | `*File` | Метаданные файла. |
| `URL` | `string` | Временная подписанная ссылка. |
| `ExpiresAt` | `time.Time` | Момент окончания действия ссылки. |

## Функции

Имя функции открывает её реализацию в ветке `test`; структуры параметров и результатов описаны в конце README.

### func [New](https://github.com/FIZZI-77/automatic_system/blob/test/File_Service/src/core/service/service.go#L31)

```go
func New(repo *repository.Repository, store *storage.S3, ttl time.Duration, logger *zap.Logger) *Service
```

Типы: [Repository](#type-repository), [S3](#type-s3), [Service](#type-service).

Структуры: [S3](#type-s3).

Сохраняет репозиторий, клиент S3, срок действия ссылок и журнал в `Service`.
Проверку доступности зависимостей не выполняет.

### func (*Service) [Create](https://github.com/FIZZI-77/automatic_system/blob/test/File_Service/src/core/service/service.go#L40)

```go
func (s *Service) Create(ctx context.Context, in models.CreateInput) (*models.PresignedFile, error)
```

Типы: [CreateInput](#type-createinput), [PresignedFile](#type-presignedfile), [Service](#type-service).

Структуры: [CreateInput](#type-createinput), [PresignedFile](#type-presignedfile).

1. Оставляет от имени только базовую часть пути, удаляет пробелы.
2. Нормализует тип содержимого в нижний регистр.
3. Проверяет владельца, имя, положительный размер не более 25 МиБ и разрешенный
   тип.
4. Создает UUID и ключ вида `owner/id/name`.
5. Записывает метаданные со статусом `PENDING_UPLOAD`.
6. Получает подписанную ссылку загрузки с типом и контрольной суммой.
7. Возвращает файл, ссылку и вычисленный срок действия.

Если получение ссылки не удалось, созданная строка метаданных остается в базе.

### func (*Service) [Confirm](https://github.com/FIZZI-77/automatic_system/blob/test/File_Service/src/core/service/service.go#L67)

```go
func (s *Service) Confirm(ctx context.Context, id, actor uuid.UUID, privileged bool) (*models.File, error)
```

Типы: [File](#type-file), [Service](#type-service).

Структуры: [File](#type-file).

Загружает файл и разрешает действие владельцу либо привилегированному
пользователю. Через `Stat` получает фактический размер и тип. При несовпадении
пытается перевести запись в `QUARANTINED`, записывает возможную ошибку этой
попытки и возвращает ошибку несоответствия. При совпадении переводит запись в
`UPLOADED`.

### func (*Service) [Link](https://github.com/FIZZI-77/automatic_system/blob/test/File_Service/src/core/service/service.go#L97)

```go
func (s *Service) Link(ctx context.Context, id, actor uuid.UUID, privileged bool, in models.LinkInput) (*models.File, error)
```

Типы: [File](#type-file), [LinkInput](#type-linkinput), [Service](#type-service).

Структуры: [LinkInput](#type-linkinput), [File](#type-file).

Проверяет вид и UUID ресурса и права на файл. Нормализует вид ресурса для имени
каталога: оставляет латинские буквы, цифры, `-` и `_`, остальные символы
заменяет на `-`. Новый ключ имеет вид
`resource-type/resource-id/file-id-name`. Перемещает объект и обновляет
метаданные. Если обновление базы не удалось, пытается переместить объект
обратно. Если ключ уже совпадает, повторное перемещение не выполняется.

### func (*Service) [Download](https://github.com/FIZZI-77/automatic_system/blob/test/File_Service/src/core/service/service.go#L110)

```go
func (s *Service) Download(ctx context.Context, id, actor uuid.UUID, privileged bool) (*models.PresignedFile, error)
```

Типы: [PresignedFile](#type-presignedfile), [Service](#type-service).

Структуры: [PresignedFile](#type-presignedfile).

Проверяет существование файла и права владельца, получает подписанную ссылку
скачивания и возвращает ее вместе с метаданными и сроком действия.

### func (*Service) [Delete](https://github.com/FIZZI-77/automatic_system/blob/test/File_Service/src/core/service/service.go#L135)

```go
func (s *Service) Delete(ctx context.Context, id, actor uuid.UUID, privileged bool) error
```

Типы: [Service](#type-service).

Проверяет права, сначала удаляет объект из S3, затем переводит запись базы в
состояние удаления через репозиторий. Ошибка хранилища останавливает операцию.

### func (*Service) [List](https://github.com/FIZZI-77/automatic_system/blob/test/File_Service/src/core/service/service.go#L148)

```go
func (s *Service) List(ctx context.Context, typ string, id, actor uuid.UUID, privileged bool) ([]*models.File, error)
```

Типы: [File](#type-file), [Service](#type-service).

Структуры: [File](#type-file).

Читает файлы, связанные с видом `typ` и идентификатором `id`.
Привилегированному пользователю возвращает список сразу. Для обычного
пользователя проверяет владельца каждого файла и отклоняет весь ответ, если
найден хотя бы один чужой файл.

### func [IsNotFound](https://github.com/FIZZI-77/automatic_system/blob/test/File_Service/src/core/service/service.go#L164)

```go
func IsNotFound(err error) bool
```

Возвращает результат `errors.Is(err, pgx.ErrNoRows)`, позволяя обработчику
преобразовать отсутствие строки в транспортную ошибку «не найдено».

## Структура БД

### `files` — метаданные файлов

| Поле | Тип PostgreSQL | Назначение и ограничения |
|---|---|---|
| `id` | `UUID` | Первичный ключ, создаваемый сервисом. |
| `owner_user_id` | `UUID` | Владелец; обязателен. |
| `resource_type` | `VARCHAR(64)` | Вид связанной сущности. |
| `resource_id` | `UUID` | Идентификатор связанной сущности. |
| `name` | `VARCHAR(255)` | Имя файла; обязательно. |
| `content_type` | `VARCHAR(127)` | Тип содержимого; обязателен. |
| `size` | `BIGINT` | Размер в байтах, строго больше нуля. |
| `checksum` | `VARCHAR(128)` | Контрольная сумма; обязательна. |
| `object_key` | `VARCHAR(512)` | Уникальный ключ в S3. |
| `status` | `VARCHAR(32)` | Одно из пяти значений `Status`; по умолчанию `PENDING_UPLOAD`. |
| `created_at` | `TIMESTAMPTZ` | Время создания. |
| `updated_at` | `TIMESTAMPTZ` | Время изменения. |
| `deleted_at` | `TIMESTAMPTZ` | Время логического удаления. |

Ограничение требует, чтобы `resource_type` и `resource_id` либо оба были
заданы, либо оба отсутствовали. Частичные индексы ускоряют список владельца для
неудаленных файлов и список связанных файлов со статусом `LINKED`.

## Структуры параметров и результатов

### type CreateInput

```go
type CreateInput struct {
	OwnerUserID uuid.UUID `json:"owner_user_id"`
	Name        string    `json:"name"`
	ContentType string    `json:"content_type"`
	Size        int64     `json:"size"`
	Checksum    string    `json:"checksum"`
}
```

### type File

```go
type File struct {
	ID           uuid.UUID  `json:"id"`
	OwnerUserID  uuid.UUID  `json:"owner_user_id"`
	ResourceType *string    `json:"resource_type,omitempty"`
	ResourceID   *uuid.UUID `json:"resource_id,omitempty"`
	Name         string     `json:"name"`
	ContentType  string     `json:"content_type"`
	Size         int64      `json:"size"`
	Checksum     string     `json:"checksum"`
	ObjectKey    string     `json:"-"`
	Status       Status     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}
```

### type LinkInput

```go
type LinkInput struct {
	ResourceType string    `json:"resource_type"`
	ResourceID   uuid.UUID `json:"resource_id"`
}
```

### type PresignedFile

```go
type PresignedFile struct {
	File      *File     `json:"file"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}
```

### type Repository

```go
type Repository struct {
	writeDB *pgxpool.Pool
	readDB  *pgxpool.Pool
}
```

### type S3

```go
type S3 struct {
	client  *s3.Client
	presign *s3.PresignClient
	bucket  string
}
```

### type Service

```go
type Service struct {
	repo   *repository.Repository
	store  *storage.S3
	ttl    time.Duration
	logger *zap.Logger
}
```
