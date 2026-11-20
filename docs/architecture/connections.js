// Names and defaults are taken from service entry points, workers, and checked-in configuration.
const architectureMap = (() => {
  const source = (path, label) => ({path, label});
  const main = (service) => service + "_Service/src/cmd/server/main.go";
  const command = (service, file) => service + "_Service/src/cmd/server/" + file + ".go";
  const worker = (service, name) => service + "_Service/src/infrastructure/" + name + "/worker.go";
  const helm = (service) => "k8s/helm/applications/templates/services/" + service + ".yaml";
  const compose = source("docker-compose.yml", "Docker Compose");
  const gateway = "API_Gateway/src/cmd/server/main.go";
  const routingHandler = "Routing_Service/src/core/handler/";
  const reportFiles = "Report_Service/src/infrastructure/fileclient/client.go";
  const assetWorker = worker("Asset", "criticalticket");

  const components = {
    Browser: ["Frontend в браузере", "client", "Страницы, обращения к API, карта и загрузка файлов."],
    Frontend: ["Frontend · сервер", "client", "Страницы и серверные маршруты геокодирования, карты и маршрутизации."],
    Simulator: ["Transponder Simulator", "client", "Отправка телеметрии транспорта."],
    Gateway: ["API Gateway", "service", "Публичный HTTP API, WebSocket уведомлений и gRPC-клиенты сервисов."],
    Auth: ["Auth", "service", "Учётные записи, токены и отправка писем."],
    Profile: ["Profile", "service", "Пользовательские и рабочие профили."],
    Department: ["Department", "service", "Справочник подразделений."],
    Brigade: ["Brigade", "service", "Бригады, их состав, графики и резервы."],
    Ticket: ["Ticket", "service", "Заявки, статусы и записи об отчётах по работам."],
    Dispatch: ["Dispatch", "service", "Подбор и назначение бригад."],
    Location: ["Location", "service", "Приём координат, текущие позиции и геоистория."],
    Routing: ["Routing", "service", "Расчёт маршрутов и управление сохранёнными маршрутами."],
    Asset: ["Asset", "service", "Городские объекты, геоданные и риски."],
    File: ["File", "service", "Метаданные файлов и подписанные ссылки на объекты."],
    SLA: ["SLA", "service", "Правила и мониторинг сроков по заявкам."],
    Notification: ["Notification", "service", "Уведомления в приложении и доставка по внешним каналам."],
    Audit: ["Audit", "service", "Журнал событий для аудита."],
    Analytics: ["Analytics", "service", "Журнал событий и аналитические проекции в ClickHouse."],
    Report: ["Report", "service", "Формирование документов и выгрузок."],
    PostgreSQL: ["PostgreSQL", "system", "Тип хранилища. Сервисы подключаются к собственным БД по конфигурации."],
    PostGIS: ["PostgreSQL / PostGIS", "system", "Пространственные запросы Asset и Location."],
    RedisGateway: ["Redis · лимиты шлюза", "system", "Состояние ограничения частоты запросов."],
    RedisNotification: ["Redis · уведомления", "system", "Notification публикует в Redis Pub/Sub. Шлюз подписывается и передаёт данные в WebSocket."],
    RedisLocation: ["Redis · позиции", "system", "Оперативные позиции транспорта и поток locations:events."],
    ClickHouse: ["ClickHouse", "system", "События и аналитические проекции."],
    S3: ["S3 / MinIO", "system", "Бинарные объекты по S3 API и подписанным URL."],
    SMTP: ["SMTP", "system", "Почтовая доставка."],
    FCM: ["Firebase Cloud Messaging", "system", "Push-уведомления при наличии настроенных учётных данных."],
    Valhalla: ["Valhalla", "system", "Маршруты и матрицы времени проезда."],
    Nominatim: ["Nominatim", "system", "Геокодирование."],
    Overpass: ["Overpass API", "system", "Запросы геоданных OpenStreetMap."],
    MapTiles: ["Серверы тайлов", "system", "Настраиваемые слои OpenStreetMap, HOT и OpenTopoMap."],
  };

  const call = (from, to, label, refs, note) => ({from, to, label, refs, note});
  const grpc = (from, to, path, label, note) =>
    call(from, to, "gRPC", [source(path, label)], note);

  const gatewayTargets = [
    "Auth", "Profile", "Department", "Brigade", "Ticket", "Dispatch", "Location",
    "Routing", "Asset", "File", "SLA", "Notification", "Audit", "Analytics", "Report",
  ];
  const postgresServices = [
    "Auth", "Profile", "Department", "Brigade", "Ticket", "Dispatch", "Routing",
    "File", "SLA", "Notification", "Audit", "Report",
  ];

  const calls = [
    call("Browser", "Frontend", "HTTP · страницы и /api", [
      source("Frontend/worker/index.ts", "HTTP-обработчик Frontend"),
      source("Frontend/app/city-map.tsx", "Запросы к серверным маршрутам"),
    ]),
    call("Browser", "Gateway", "HTTP JSON / WebSocket", [
      source("Frontend/app/api.ts", "Адреса API и WebSocket"),
      source("Frontend/app/notifications-page.tsx", "Открытие WebSocket"),
      source("API_Gateway/src/core/handlers/notification.go", "Обработчик WebSocket"),
    ]),
    call("Browser", "S3", "HTTP · подписанный URL", [
      source("Frontend/app/ticket-workspace.tsx", "Загрузка и скачивание файлов"),
    ]),
    call("Browser", "MapTiles", "HTTP · тайлы карты", [
      source("Frontend/app/api.ts", "Адреса серверов тайлов"),
      source("Frontend/app/city-map.tsx", "Настройка слоёв Leaflet"),
    ]),
    call("Frontend", "Nominatim", "HTTP", [source("Frontend/app/api/geocode/route.ts", "Геокодирование")]),
    call("Frontend", "Overpass", "HTTP", [source("Frontend/app/api/moscow-infrastructure/route.ts", "Объекты на карте")]),
    call("Frontend", "Valhalla", "HTTP", [source("Frontend/app/api/valhalla-route/route.ts", "Расчёт маршрута")]),
    call("Simulator", "Location", "HTTP · POST /v1/positions", [
      source("Transponder_Simulator/internal/simulator/sender.go", "Отправка координат"),
      source("Location_Service/src/core/httptransport/handler.go", "Приём координат"),
    ]),
    ...gatewayTargets.map((to) => grpc("Gateway", to, gateway, "Создание клиента и передача в обработчик")),
    grpc("Auth", "Profile", "Auth_Service/src/infrastructure/profileclient/client.go", "Проверка и создание профиля"),
    grpc("Profile", "Auth", "Profile_Service/src/infrastructure/grpcdeps/checkers.go", "GetUserAuthInfo для проверки учётной записи"),
    grpc("Profile", "Department", "Profile_Service/src/infrastructure/grpcdeps/checkers.go", "GetDepartmentByID для проверки подразделения"),
    grpc("Brigade", "Profile", "Brigade_Service/src/core/service/member_service.go", "Проверка профиля и его компетенций"),
    grpc("Brigade", "Department", "Brigade_Service/src/core/service/brigade_service.go", "GetDepartmentByID при создании бригады"),
    ...["Ticket", "Brigade", "Location", "Routing"].map((to) =>
      call("Dispatch", to, "gRPC", [
        source(main("Dispatch"), "Инициализация клиента " + to),
        source("Dispatch_Service/src/core/service/workflow.go", "Вызовы при назначении бригады"),
      ])),
    grpc("Routing", "Ticket", routingHandler + "access.go", "GetTicket и ListTickets для проверок доступа"),
    grpc("Routing", "Brigade", routingHandler + "handler.go", "GetBrigadeByID в CreateRoute"),
    call("Asset", "Ticket", "gRPC · по условию", [
      source(assetWorker, "Создание заявки"),
      source(main("Asset"), "Условия запуска читателя"),
      source(helm("asset"), "Условия Helm"),
    ], "Требуются брокеры Kafka и оба идентификатора CRITICAL_RISK_TICKET_CATEGORY_ID и CRITICAL_RISK_TICKET_REQUESTER_ID."),
    grpc("Report", "Analytics", main("Report"), "Клиент аналитики"),
    call("Report", "File", "gRPC", [source(reportFiles, "Метаданные, ссылки и привязка файла")]),
    call("Report", "S3", "HTTP · GET/PUT", [source(reportFiles, "Чтение и запись бинарного объекта")]),
    ...postgresServices.map((from) =>
      call(from, "PostgreSQL", "SQL", [source(main(from), "Подключение к PostgreSQL")])),
    ...["Asset", "Location"].map((from) =>
      call(from, "PostGIS", "SQL · геоданные", [
        source(main(from), "Подключение к PostgreSQL"),
        source(from + "_Service/src/core/repository/" + (from === "Asset" ? "asset_repository.go" : "geo_zone_repo.go"), "Пространственные запросы"),
      ])),
    call("Gateway", "RedisGateway", "Redis · rate limit", [source(gateway, "Создание Redis rate limiter")]),
    call("Gateway", "RedisNotification", "Redis · SUBSCRIBE", [source("API_Gateway/src/core/handlers/notification.go", "Подписка в WebSocket-обработчике")]),
    call("Notification", "RedisNotification", "Redis · PUBLISH", [source("Notification_Service/src/infrastructure/live/redis.go", "Публикация уведомления")]),
    call("Location", "RedisLocation", "Redis · позиции и Stream", [source(main("Location"), "Подключение Redis и stream relay")]),
    call("Analytics", "ClickHouse", "ClickHouse", [source(main("Analytics"), "Подключение и проверка ClickHouse")]),
    call("File", "S3", "S3 API", [source(main("File"), "Настройка S3-хранилища"), source("File_Service/src/infrastructure/storage/s3.go", "Операции с объектами")]),
    call("Routing", "Valhalla", "HTTP", [source("Routing_Service/src/infrastructure/valhalla/client.go", "Клиент Valhalla")]),
    call("Auth", "SMTP", "SMTP", [source("Auth_Service/src/core/service/mail_service.go", "Отправка письма")]),
    call("Notification", "SMTP", "SMTP", [source("Notification_Service/src/infrastructure/sender/sender.go", "Отправка уведомления")]),
    call("Notification", "FCM", "HTTP · по условию", [source(main("Notification"), "Условная настройка FCM")], "FCM включается при наличии FCM_SERVICE_ACCOUNT_FILE."),
  ];

  const stages = {
    domain: "Предметные события",
    retry: "Повторная обработка",
    dlq: "Очередь ошибок (DLQ)",
  };
  const deadLetters = "При ошибках обработки, которые этот читатель направляет в DLQ.";
  const init = source("k8s/base/migrations/kafka-init.yaml", "Базовый kafka-init в Kubernetes");
  const topics = {};

  const publication = (service, label, refs, note) => ({service, label, refs, note});
  const outbox = (service, file = command(service, "outbox"), refs = []) =>
    publication(service, "Outbox", [source(file, "Запуск передатчика"), ...refs]);
  const subscription = (service, label, refs, note) => ({service, label, refs, note});
  const consumer = (service, group, entry, implementation, note) => subscription(service, group, [
    source(entry, "Топик и группа читателя"),
    source(worker(service, implementation), "Обработчик Kafka"),
  ], note);

  const publishers = [
    ["tickets", [outbox("Ticket")]],
    ["routing", [outbox("Routing")]],
    ["dispatch", [outbox("Dispatch")]],
    ["brigades", [outbox("Brigade")]],
    ["profiles", [outbox("Profile")]],
    ["departments", [outbox("Department")]],
    ["auth", [outbox("Auth")]],
    ["locations", [publication("Location", "Redis Stream", [
      source(main("Location"), "Запуск stream relay"),
      source(worker("Location", "streamrelay"), "Чтение Redis Stream и запись в Kafka"),
    ], "Поток Redis по умолчанию: locations:events.")]],
    ["assets", [outbox("Asset", main("Asset"))]],
    ["files", [outbox("File", command("File", "outbox"), [
      source("File_Service/scheme/20261116000100_create_event_outbox.sql", "Триггеры PostgreSQL"),
    ])]],
    ["sla", [outbox("SLA", main("SLA"))]],
    ["notifications", [outbox("Notification", command("Notification", "outbox"), [
      source("Notification_Service/scheme/20261116000100_create_event_outbox.sql", "Триггеры PostgreSQL"),
    ])]],
    ["reports", [publication("Report", "Outbox и completion worker", [
      source(main("Report"), "Запуск передатчика и completion worker"),
      source(worker("Report", "completionconsumer"), "Публикация результата обработки отчёта"),
    ], "Результаты формирования документа по заявке публикует сам completion worker.")]],
  ];

  const retryReaders = {
    profiles: [consumer("Brigade", "brigade-profile-projection-v1", command("Brigade", "profile_consumer"), "profileconsumer")],
    routing: [
      consumer("Brigade", "brigade-routing-projection-v1", command("Brigade", "routing_consumer"), "routingconsumer"),
      consumer("Ticket", "ticket-routing-projection-v1", command("Ticket", "routing_consumer"), "routingconsumer"),
    ],
    tickets: [
      consumer("Brigade", "brigade-ticket-lifecycle-v1", command("Brigade", "ticket_consumer"), "ticketconsumer"),
      consumer("Dispatch", "dispatch-emergency-v1", command("Dispatch", "ticket_consumer"), "ticketconsumer"),
      consumer("Routing", "routing-ticket-lifecycle-v1", command("Routing", "ticket_consumer"), "ticketconsumer"),
    ],
  };
  const otherReaders = {
    tickets: [
      consumer("SLA", "sla-service", main("SLA"), "ticketconsumer"),
      consumer("Report", "report-completion-v1", main("Report"), "completionconsumer", "Обрабатывает запросы на формирование документа и компенсацию."),
    ],
    reports: [consumer("Ticket", "ticket-report-result-v1", command("Ticket", "report_consumer"), "reportconsumer")],
    assets: [subscription("Asset", "asset-critical-ticket-v1 · по условию", [
      source(main("Asset"), "Запуск читателя и параметры"),
      source(assetWorker, "Обработка критического риска"),
      source(helm("asset"), "Настройки критического риска в Helm"),
    ], "Читатель включается при наличии брокеров и обоих идентификаторов настройки критического риска.")],
  };
  const notificationDefaults = new Set(["tickets", "sla", "dispatch", "departments", "brigades", "locations", "routing", "files"]);

  function notificationReader(key) {
    const scopes = {
      reports: [" · Helm / Compose", "Подписка добавлена в Helm и Docker Compose."],
      assets: [" · Compose", "Подписка добавлена в Docker Compose."],
    };
    const [suffix, note] = scopes[key] ?? ["", undefined];
    return subscription("Notification", "notification-service" + suffix, [
      source(main("Notification"), "Создание читателей из KAFKA_TOPICS"),
      source(worker("Notification", "eventconsumer"), "Обработка события и публикация в DLQ"),
      source(helm("notification"), "Список топиков Helm"),
      compose,
    ], note);
  }

  const readersOfEveryDomain = ["Audit", "Analytics"].map((service) =>
    subscription(service, service.toLowerCase() + "-service", [
      source(main(service), "Создание читателей из KAFKA_TOPICS"),
      source(service + "_Service/config.yaml", "Список топиков и группа"),
      source(worker(service, "eventconsumer"), "Обработка события и публикация в DLQ"),
    ]));

  for (const [key, writers] of publishers) {
    const topic = key + ".events.v1";
    const readers = [...(retryReaders[key] ?? []), ...(otherReaders[key] ?? [])];
    if (notificationDefaults.has(key) || key === "reports" || key === "assets") {
      readers.push(notificationReader(key));
    }
    readers.push(...readersOfEveryDomain);
    topics[topic] = {stage: "domain", writers, readers, refs: [init]};
  }

  for (const [key, readers] of Object.entries(retryReaders)) {
    const topic = key + ".events.v1.retry";
    topics[topic] = {
      stage: "retry",
      writers: readers.map(({service, refs}) =>
        publication(service, "При ошибке обработки", refs)),
      readers: readers.map(({service, label, refs}) => subscription(service, label + ".retry", refs)),
      note: key === "tickets"
        ? "Топик создают базовый Job kafka-init и Docker Compose."
        : "Топик явно создаёт Docker Compose. В списке базового Job kafka-init его нет.",
      refs: [init, compose],
    };
  }

  for (const [topic, entry] of Object.entries(topics)) {
    if (entry.stage !== "domain") continue;
    topics[topic + ".dlq"] = {
      stage: "dlq",
      writers: entry.readers.filter(({service}) => service !== "Asset")
        .map(({service, label, refs, note}) => publication(
          service,
          "При ошибке обработки" + (service === "Notification" ? label.slice("notification-service".length) : ""),
          refs,
          [deadLetters, note].filter(Boolean).join(" "),
        )),
      readers: [],
      note: "Схема показывает штатные сервисы. Инструменты ручного разбора и переигрывания событий находятся в документации эксплуатации.",
      refs: [init, compose],
    };
  }

  return {components, calls, topics, stages};
})();
