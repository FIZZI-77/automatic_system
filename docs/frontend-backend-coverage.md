# Соответствие backend и frontend

Повторно проверено 16 августа 2026 года на поднятом Docker-стеке. В API Gateway зарегистрировано 178 HTTP-маршрутов. Frontend использует 127 явно вызываемых операций и автоматический `refresh`, то есть 128 операций в пользовательских сценариях. Все 168 клиентских адресов вынесены в `NEXT_PUBLIC_*`; остальные маршруты Gateway относятся к health/JWKS, чтению уже загруженной карточки или внутренним серверным связкам.

Добавлены полноценные экраны для реестра инфраструктуры, правил SLA и категорий заявок, навыков бригад и сотрудников, удостоверений, операционного журнала назначений/маршрутов, шаблонов и доставки уведомлений. Также реализованы изменение и отмена заявки с историей, детальная запись аудита, глобальные WebSocket-уведомления поверх любого раздела, безопасность профиля, архивирование бригад, удаление департаментов и редактирование зон.

| Контур | Реализованный сценарий во frontend | Прямые операции Gateway | Служебная часть сценария |
|---|---|---|---|
| Auth | вход, reset/verify, смена пароля, завершение одной или всех сессий, автоматический refresh | `login`, `refresh`, `logout`, `logout-all`, `verify-email`, `request/reset-password`, `change-password`, `me`, `register` | — |
| Ticket | создание, очередь, изменение, отмена, история статусов, начало и завершение работ | `create`, `list`, `update`, `cancel`, `status-history`, `change-status`, `complete`, `reports/list` | `get` не дублируется: карточка приходит из list и обновляется мутациями |
| Dispatch | подбор, ручное/автоматическое назначение, журнал и отмена | `preview`, `reserve`, `confirm`, `auto`, `list`, `cancel` | get дублирует выбранную запись списка |
| Routing | маршрут на карте, журнал маршрутов и управление статусом | `routing/build`, `routing/list`, `routing/set-status` | matrix/rank/create/get/recalculate используются серверной диспетчеризацией |
| File + MinIO | загрузка, confirm, привязка к отчёту, список, скачивание и удаление | uploads/create, uploads/confirm, list, download-url, delete | link выполняет Report Service; linked-файлы перемещаются в `resource_type/resource_id/` |
| Completion report | состав бригады, заявитель, адрес, описание работ, фото/GIF внутри PDF | `reports/completion/create` | Gateway собирает snapshot; Report Service генерирует PDF; File Service сохраняет в S3 |
| Report analytics | PDF/XLSX/CSV, очередь, повтор, отмена и скачивание | reports/create, list, retry, cancel, download-url | get — детальная операция той же очереди |
| SLA | реестр заявок, карточка и история SLA, полный CRUD правил | tickets/list/get, history/list, rules/create/update/delete/list, analytics/sla/summary | rules/get дублирует выбранную запись списка |
| Analytics | обзор, дневная динамика, разбивка, SLA и сводка активов | tickets/overview/daily/breakdown, sla/summary, assets/summary | — |
| Notification | список/read, предпочтения, WebSocket, push-устройства, шаблоны и журнал доставки | list/read/read-all, preferences, devices, templates, deliveries, ws | — |
| Audit | журнал с фильтром и полная карточка события | audit/list, audit/get | — |
| Department | создание, редактирование и безопасное удаление департаментов | create, list, update, delete | get дублирует выбранную запись списка |
| Brigade | единый список, статусы, деактивация и архивирование | create, list, update, set-status, deactivate, archive | get/history/capability/available — проверки Dispatch Service |
| Brigade members | состав, перевод, руководитель бригады | add, remove, change-role, list | availability/history — телеметрия смен и аудит |
| Schedule | график сотрудника через график его бригады | brigade-schedules/set, list | — |
| Brigade zones | создание, изменение и удаление персональной зоны каждой бригады | brigade-zones/create/update/delete/list | covers/find-by-point — серверный пространственный поиск |
| Location | фактические машины на карте и статистика онлайн | locations/current-batch | record/history/nearby — телеметрия и Dispatch Service |
| Profile | профиль, сотрудники, навыки, удостоверения, проверка/отзыв и файлы допусков | profile/work-profile CRUD; skills; brigade-skills; certification types; certifications; skill grants | batch/check используются Brigade/Dispatch Service |
| Infrastructure | OSM-слои и ведомственный реестр активов: паспорта, статусы, инциденты, ремонты, осмотры, ТО и риски | `/api/moscow-infrastructure`; assets create/update/list/status/nearby/incidents/repairs/inspections/prediction/maintenance/risks | assets/get дублирует выбранную запись списка |

## Проверенные инварианты

- Заявка `NEW` не имеет бригады и маршрута до подтверждённого назначения.
- Ручное назначение выполняется как `reserve → confirm`; прямой вызов Ticket Service интерфейсом исключён.
- На карте показываются только машины существующих операционных бригад; несколько машин одной бригады группируются и относятся к одной активной заявке.
- «Бригады на линии» рассчитываются по фактическому статусу Brigade Service, без константы.
- Зона хранится с `brigade_id` и не переносится между карточками бригад.
- Отчёт и исходные вложения привязаны к одному `work_report`; S3-путь организован по типу и ID ресурса.
- Маршрут авторизованного пользователя строится через Routing Service; прямой Valhalla-прокси используется только в демо без JWT.
