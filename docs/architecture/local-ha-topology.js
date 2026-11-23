// A fixed deployment view. The viewport can move without changing the layout.
const localHaTopology = (() => {
  const cards = [];
  const regions = [];
  const wires = [];
  const dots = [];
  const labels = [];

  function region(x, y, w, h, title, subtitle, style = "") {
    regions.push({ x, y, w, h, title, subtitle, style });
  }

  function card(id, x, y, w, h, title, endpoint, options = {}) {
    const entry = { id, x, y, w, h, title, endpoint, ...options };
    cards.push(entry);
    return entry;
  }

  function workload(id, x, y, w, h, title, endpoint, count, options = {}) {
    const { stateful, podDetail, ...rest } = options;
    const pods = Array.from({ length: count }, (_, index) => ({
      name: stateful ? `${id}-${index}` : `Pod ${index + 1}`,
      detail: podDetail,
    }));
    return card(id, x, y, w, h, title, endpoint, { pods, ...rest });
  }

  const top = (node, offset = 0) => [node.x + node.w / 2 + offset, node.y];
  const bottom = (node, offset = 0) => [node.x + node.w / 2 + offset, node.y + node.h];
  const left = (node, offset = 0) => [node.x, node.y + node.h / 2 + offset];
  const right = (node, offset = 0) => [node.x + node.w, node.y + node.h / 2 + offset];

  function wire(kind, title, points, options = {}) {
    wires.push({ kind, title, points, end: true, ...options });
  }

  function viaY(kind, title, from, to, y, options) {
    wire(kind, title, [from, [from[0], y], [to[0], y], to], options);
  }

  function viaX(kind, title, from, to, x, options) {
    wire(kind, title, [from, [x, from[1]], [x, to[1]], to], options);
  }

  function label(x, y, value, kind = "", align = "start") {
    labels.push({ x, y, value, kind, align });
  }

  function rail(kind, title, from, to, entries) {
    const net = title;
    wire(kind, title, [from, to], { end: false, net });
    for (const [index, entry] of entries.entries()) {
      wire(kind, entry.title || title, entry.points, { net, ...entry });
      if (index > 0 || entry.points[1][0] > from[0]) {
        const junction = entry.points.find(([x, y]) => y === from[1] && x >= from[0] && x <= to[0]);
        if (junction) dots.push({ kind, point: junction });
      }
    }
  }

  function branches(kind, title, from, targets, y) {
    const net = title;
    const xs = [from, ...targets].map(([x]) => x);
    rail(kind, title, [Math.min(...xs), y], [Math.max(...xs), y], [
      { points: [from, [from[0], y]], end: false },
      ...targets.map((point) => ({ points: [[point[0], y], point] })),
    ]);
    dots.push({ kind, point: [from[0], y] });
  }

  const canvas = { width: 3900, height: 2436 };

  region(38, 34, 3824, 326, "Вход и внешние системы",
    "Контур Kubernetes local-ha · приложения и данные в automatic-system");
  const browser = card("browser", 72, 126, 246, 76, "Браузер", "city.localhost · S3");
  const partner = card("partner", 72, 226, 246, 76, "Партнёрские клиенты", "api.city.localhost");
  const tunnel = card("tunnel", 396, 255, 264, 68, "ngrok / Tailscale Funnel", "внешний HTTPS", { optional: true, compact: true });
  const ingress = workload("istio-ingressgateway", 767, 138, 307, 146, "Istio Ingress Gateway",
    "istio-system · :80 / :443", 1, { optional: true, podDetail: "Envoy · HPA min 1", split: true });
  const frontend = workload("frontend", 1212, 119, 265, 143, "Frontend",
    "frontend:3000 · HTTP", 1, { split: true, podDetail: "приложение + Envoy", address: "Valhalla" });
  const gateway = workload("api-gateway", 1660, 151, 310, 143, "API Gateway",
    "api-gateway:8081 · HTTP / WS", 2, { split: true, podDetail: "Go + Envoy", address: "Redis G · Redis N" });
  const maps = card("maps", 1512, 54, 458, 69, "Геосервисы и тайлы", "Nominatim · Overpass · поставщики тайлов");
  const istiod = workload("istiod", 2090, 90, 258, 122, "istiod",
    "istio-system · xDS", 1, { optional: true, podDetail: "HPA min 1" });
  const kiali = workload("kiali", 2380, 90, 258, 122, "Kiali",
    "istio-system · /observe/kiali", 1, { optional: true });
  card("smtp", 2248, 244, 390, 73, "Внешний SMTP", "SMTP · smtp.gmail.com:587");
  const simulator = card("simulators", 2794, 120, 999, 161,
    "Симуляторы транспондеров", "необязательный overlay · automatic-system", {
      optional: true,
      pods: [
        { name: "transponder-simulator", detail: "1 pod", workload: "transponder-simulator" },
        { name: "transponder-simulator-auto", detail: "1 pod", workload: "transponder-simulator-auto" },
        { name: "transponder-simulator-cancel", detail: "1 pod", workload: "transponder-simulator-cancel" },
      ],
    });

  viaX("request", "Браузер → Istio по HTTP(S)", right(browser, -6), left(ingress, -47), 694);
  viaX("request", "Партнёрский API → Istio по HTTP(S)", right(partner, -12), left(ingress, 18), 721);
  viaX("optional", "Публичный туннель → ingress", right(tunnel), left(ingress, 58), 739);
  viaX("request", "Страницы → Frontend", right(ingress, -35), left(frontend, -37), 1135);
  viaX("request", "Предметные HTTP и WebSocket → API Gateway", right(ingress, 51), left(gateway, 39), 1585);
  viaX("request", "Сервер Frontend → Nominatim и Overpass", right(frontend, -60), left(maps, 42 - maps.h / 2), 1495);
  viaY("ops", "istiod настраивает ingress через xDS", bottom(istiod), bottom(ingress, 45), 330);
  label(1089, 139, "страницы", "request");
  label(1330, 281, "HTTP / WS", "request");
  label(1160, 322, "конфигурация Envoy", "ops");
  label(1430, 318, "API Gateway · Service LoadBalancer", "request");
  label(2788, 311, "Телеметрия · для Helm нужен location-service-http:8080");
  label(2788, 336, "В overlay симуляторов указан location-service:8080");

  region(38, 382, 3824, 811, "Прикладные сервисы",
    "Kubernetes Service распределяет вход между pod · короткие линии внутри карточки показывают этот выбор");

  // The order limits the number of spans shared by synchronous calls.
  const appDefinitions = [
    ["auth", "Auth", 50051, true, "pub", "SMTP"],
    ["profile", "Profile", 50055, true, "pub", ""],
    ["department", "Department", 50053, true, "pub", ""],
    ["brigade", "Brigade", 50054, true, "both", ""],
    ["routing", "Routing", 50057, true, "both", ""],
    ["dispatch", "Dispatch", 50058, true, "both", ""],
    ["ticket", "Ticket", 50052, false, "both", ""],
    ["location", "Location", 50056, true, "pub", "HTTP :8080"],
    ["asset", "Asset", 50065, true, "both", "HTTP :8085"],
    ["sla", "SLA", 50060, true, "both", ""],
    ["notification", "Notification", 50061, true, "both", "SMTP"],
    ["audit", "Audit", 50062, true, "sub", ""],
    ["analytics", "Analytics", 50063, false, "sub", ""],
    ["report", "Report", 50064, true, "both", "HTTP :8084"],
    ["file", "File", 50059, true, "pub", ""],
  ];

  const apps = Object.fromEntries(appDefinitions.map(([id, name, port, platform, event, address], index) => {
    const node = workload(`${id}-service`, 72 + index * 252, 698, 216, 151, name,
      `${id}-service:${port}`, 2, { split: true, podDetail: "Go + Envoy", address });
    return [id, { node, platform, event }];
  }));
  const app = (id) => apps[id].node;

  branches("request", "API Gateway → 15 gRPC Service", bottom(gateway),
    Object.values(apps).map(({ node }) => top(node)), 471);
  label(1100, 461, "gRPC из API Gateway", "request");
  label(204, 518, "Связи между сервисами", "request");

  viaY("optional", "Симуляторы → location-service-http:8080 после перенастройки URL", bottom(simulator, 95), top(app("location"), 92), 495);
  viaY("request", "Gateway → asset-history-internal:8085", bottom(gateway, 72), top(app("asset"), 91), 518);
  viaY("request", "Gateway → report-service-internal:8084", bottom(gateway, 115), top(app("report"), 91), 539);
  label(2306, 510, "Asset History · :8085", "request");
  label(2965, 531, "Report Internal · :8084", "request");

  const calls = [
    ["auth", "profile"], ["profile", "auth"], ["profile", "department"],
    ["brigade", "profile"], ["brigade", "department"],
    ["routing", "brigade"], ["routing", "ticket"], ["dispatch", "brigade"],
    ["dispatch", "routing"], ["dispatch", "ticket"], ["dispatch", "location"],
    ["report", "analytics"], ["report", "file"],
    ["asset", "ticket", "optional"],
  ];
  const freePorts = new Map(Object.keys(apps).map((id) => [id, [-75, -53, -31, 29, 51, 73]]));
  const tracks = [];
  for (const [from, to, kind = "request"] of calls) {
    const start = top(app(from), freePorts.get(from).shift());
    const end = top(app(to), freePorts.get(to).shift());
    const low = Math.min(start[0], end[0]);
    const high = Math.max(start[0], end[0]);
    let track = tracks.findIndex((intervals) => intervals.every(([a, b]) => high + 14 < a || low - 14 > b));
    if (track === -1) track = tracks.push([]) - 1;
    tracks[track].push([low, high]);
    viaY(kind, `${app(from).title} → ${app(to).title}${kind === "optional" ? " · обработчик критического риска" : " · gRPC"}`,
      start, end, 561 + track * 19);
  }

  region(38, 1221, 604, 545, "PostgreSQL Platform",
    "Patroni · отдельные базы сервисов");
  region(665, 1221, 742, 545, "PostgreSQL Ticket",
    "Patroni + Citus · распределение по department_id");
  region(1430, 1221, 575, 545, "Kafka", "Брокеры и контроллеры KRaft");
  region(2028, 1221, 747, 545, "Redis",
    "Gateway · Notification · Location");
  region(2798, 1221, 1064, 545, "Хранилища и движки",
    "S3 · OLAP · ГИС · почта");

  const pWrite = workload("pgbouncer-platform-primary", 59, 1336, 265, 111,
    "PgBouncer · запись", "pgbouncer-platform-primary:6432", 2, { compact: true, split: true });
  const pRead = workload("pgbouncer-platform-replicas", 352, 1336, 265, 111,
    "PgBouncer · чтение", "pgbouncer-platform-replicas:6432", 2, { compact: true, split: true });
  const pLeader = card("postgres-platform-primary", 59, 1501, 265, 69, "Service · primary",
    "postgres-platform-primary:5432", { compact: true });
  const pFollowers = card("postgres-platform-replicas", 352, 1501, 265, 69, "Service · replicas",
    "postgres-platform-replicas:5432", { compact: true });
  const platform = workload("postgres-platform", 59, 1621, 558, 111, "Patroni PostgreSQL",
    "primary выбирается Patroni · PostGIS для Location и Asset", 3,
    { stateful: true, compact: true, podDetail: "PostgreSQL + exporter" });
  const tWrite = workload("pgbouncer-ticket-primary", 691, 1336, 329, 111,
    "PgBouncer · запись", "pgbouncer-ticket-primary:6432", 2, { split: true, compact: true });
  const tRead = workload("pgbouncer-ticket-replicas", 1052, 1336, 329, 111,
    "PgBouncer · чтение", "pgbouncer-ticket-replicas:6432", 2, { split: true, compact: true });
  const tLeader = card("postgres-ticket-primary", 691, 1490, 329, 57, "Service · primary",
    "postgres-ticket-primary:5432", { compact: true });
  const tFollowers = card("postgres-ticket-replicas", 1052, 1490, 329, 57, "Service · replicas",
    "postgres-ticket-replicas:5432", { compact: true });
  const coordinator = workload("coordinator-ticket-citus", 691, 1571, 690, 69,
    "Координатор Citus", "", 3, { stateful: true, compact: true });
  const workerOne = workload("worker-1-ticket-citus", 691, 1678, 329, 69,
    "Группа worker 1", "", 2, { stateful: true, compact: true });
  const workerTwo = workload("worker-2-ticket-citus", 1052, 1678, 329, 69,
    "Группа worker 2", "", 2, { stateful: true, compact: true });

  for (const [pooler, endpoint, cluster] of [
    [pWrite, pLeader, platform], [pRead, pFollowers, platform],
    [tWrite, tLeader, coordinator], [tRead, tFollowers, coordinator],
  ]) {
    wire("data", `${pooler.title} → ${endpoint.endpoint}`, [bottom(pooler), top(endpoint)]);
    wire("data", `${endpoint.endpoint} → роль Patroni в ${cluster.title}`,
      [bottom(endpoint), [bottom(endpoint)[0], cluster.y]]);
  }
  branches("data", "Координатор Citus → группы worker", bottom(coordinator),
    [top(workerOne), top(workerTwo)], 1658);
  label(705, 1669, "распределённый SQL", "data");

  const brokers = card("kafka-bootstrap", 1454, 1336, 527, 73, "Kafka bootstrap",
    "kafka-1:9092, kafka-2:9092, kafka-3:9092");
  const kafkaNodes = [1, 2, 3].map((n) => workload(`kafka-${n}`, 1455 + (n - 1) * 181, 1490, 163, 111,
    `Kafka ${n}`, ":9092 / :9093", 1, { stateful: true, podDetail: "broker + controller", compact: true }));
  branches("event", "Kafka bootstrap → брокеры", bottom(brokers),
    kafkaNodes.map((node) => top(node)), 1450);
  const kafkaCenters = kafkaNodes.map((node) => bottom(node));
  rail("event", "Kafka: кворум и репликация между брокерами",
    [kafkaCenters[0][0], 1663], [kafkaCenters[2][0], 1663],
    kafkaCenters.map((point) => ({ points: [point, [point[0], 1663]], end: false })));
  label(1717, 1701, "KRaft / репликация Kafka", "event", "middle");

  workload("redis-gateway", 2052, 1336, 213, 121, "Redis Gateway",
    "redis-gateway:6379", 1, { stateful: true, address: "Redis G" });
  const redisN = workload("redis-notification", 2290, 1336, 223, 121, "Redis Notification",
    "redis-notification:6379", 1, { stateful: true, address: "Redis N" });
  const sentinel = workload("redis-location-sentinel", 2052, 1484, 699, 109,
    "Redis Sentinel · Location", "redis-location-sentinel:26379 · выбор текущего master", 3,
    { stateful: true, address: "Redis L", compact: true });
  const redisLocations = [
    ["redis-location-master", "Исходный master"],
    ["redis-location-replica-1", "Реплика 1"],
    ["redis-location-replica-2", "Реплика 2"],
  ].map(([id, title], index) => workload(id, 2052 + index * 237, 1647, 225, 99, title,
    ":6379 · Redis Location", 1, { stateful: true, compact: true, podFont: 12 }));
  branches("data", "Sentinel обнаруживает текущую роль Redis", bottom(sentinel),
    redisLocations.map((node) => top(node)), 1619);
  branches("data", "Репликация Redis в исходной топологии", bottom(redisLocations[0]),
    redisLocations.slice(1).map((node) => bottom(node)), 1757);

  const clickhouse = workload("clickhouse", 2820, 1336, 225, 121, "ClickHouse",
    ":8123 HTTP · :9000 native", 1, { stateful: true, address: "CH" });
  const minio = workload("minio", 3077, 1336, 224, 121, "MinIO",
    "S3 :9000 · консоль :9001", 1, { stateful: true, address: "S3" });
  const valhalla = workload("valhalla", 3333, 1336, 224, 121, "Valhalla",
    "valhalla:8002 · HTTP", 1, { stateful: true, address: "Valhalla" });
  workload("mailhog", 3589, 1336, 249, 121, "MailHog",
    ":1025 SMTP · :8025 UI", 1);
  label(2820, 1498, "S3 · File и Report · подписанные URL браузера · pgBackRest");
  label(2820, 1535, "Valhalla · Routing и серверный маршрут Frontend");
  label(2820, 1572, "SMTP Helm · Auth и Notification используют внешний SMTP");
  label(2820, 1609, "MailHog поднимается overlay support для локальной диагностики");
  label(2820, 1646, "Patroni хранит состояние выборов в Kubernetes Endpoints.");
  label(2820, 1683, "Локальные тома и размещение pod определяет кластер.");
  label(2820, 1720, "Номер Pod у Deployment обозначает слот реплики.");

  const sqlInputs = Object.values(apps).filter(({ platform }) => platform)
    .map(({ node }) => bottom(node, -57));
  const sqlSplit = 630;
  const sqlNet = "Платформенные подключения PostgreSQL";
  rail("data", sqlNet, [sqlInputs[0][0], 924], [sqlInputs.at(-1)[0], 924],
    sqlInputs.map((point) => ({ points: [point, [point[0], 924]], end: false })));
  dots.push({ kind: "data", point: [sqlSplit, 924] });
  branches("data", sqlNet, [sqlSplit, 924], [top(pWrite), top(pRead)], 1311);
  label(704, 912, "SQL Platform", "data");

  const citusFeed = 1371;
  viaY("data", "Ticket → PgBouncer Ticket", bottom(app("ticket"), -57), [citusFeed, 1287], 965,
    { end: false, net: "Ticket SQL" });
  branches("data", "Ticket SQL", [citusFeed, 1287], [top(tWrite), top(tRead)], 1307);
  label(1265, 951, "Ticket SQL", "data");

  const kafkaY = 1007;
  const eventInputs = Object.values(apps).map(({ node, event }) => {
    const point = bottom(node);
    const junction = [point[0], kafkaY];
    return {
      points: event === "pub" ? [point, junction] : [junction, point],
      title: `${node.title} · ${event === "pub" ? "публикует" : event === "sub" ? "читает" : "публикует и читает"} Kafka`,
      start: event === "both",
    };
  });
  const kafkaNet = "Kafka: публикация и подписки";
  rail("event", kafkaNet, [bottom(app("auth"))[0], kafkaY], [bottom(app("file"))[0], kafkaY], eventInputs);
  const brokerInput = top(brokers, 25);
  wire("event", "Шина событий → Kafka bootstrap", [[brokerInput[0], kafkaY], brokerInput],
    { start: true, net: kafkaNet });
  dots.push({ kind: "event", point: [brokerInput[0], kafkaY] });
  label(454, 994, "Kafka · pub / sub", "event");

  const serviceData = [
    ["notification", 55, top(redisN, 20), "Redis Notification · :6379"],
    ["location", 57, left(sentinel, -3), "Redis Sentinel · :26379"],
    ["routing", 56, top(valhalla, 46), "Valhalla · :8002"],
    ["analytics", 57, left(clickhouse, 9), "ClickHouse · :9000"],
    ["report", 59, top(minio, 6), "Report → MinIO · S3"],
    ["file", 57, top(minio, 45), "File → MinIO · S3"],
  ];
  for (const [index, [id, offset, target, title]] of serviceData.entries()) {
    const from = bottom(app(id), offset);
    const y = 1045 + index * 21;
    if (id === "location" || id === "analytics") {
      const corridor = id === "location" ? 2016 : 2809;
      wire("data", title, [from, [from[0], y], [corridor, y], [corridor, target[1]], target]);
    } else {
      viaY("data", title, from, target, y);
    }
  }
  label(671, 1075, "Одинаковые короткие метки обозначают один адрес.");
  label(671, 1109, "Location после выбора master использует Redis :6379.");
  label(671, 1143, "Asset → Ticket · при включённом обработчике критического риска.");

  region(38, 1800, 2800, 320, "Наблюдаемость",
    "automatic-system · вход /observe через Istio при настройке · 1 pod на узел для DaemonSet");
  workload("kube-state-metrics", 60, 1909, 212, 100, "kube-state-metrics", ":8080", 1, { compact: true });
  workload("kafka-exporter", 292, 1909, 186, 100, "Kafka exporter", ":9308", 1, { compact: true });
  workload("redis-exporter", 498, 1909, 190, 100, "Redis exporter", ":9121", 1, { compact: true });
  card("node-exporter", 708, 1909, 174, 100, "Node exporter", "DaemonSet", {
    compact: true, pods: [{ name: "по 1 на узел" }],
  });
  const prometheus = workload("prometheus", 924, 1909, 210, 100, "Prometheus", ":9090", 1);
  const otel = workload("otel-collector", 1182, 1909, 214, 100, "OTel Collector", ":4317 / :4318 / :8889", 1, { compact: true });
  const jaeger = workload("jaeger", 1445, 1909, 193, 100, "Jaeger", ":16686 · Badger", 1);
  const filebeat = card("filebeat", 1683, 1909, 179, 100, "Filebeat", "DaemonSet", {
    pods: [{ name: "по 1 на узел" }],
  });
  const elastic = workload("elasticsearch", 1905, 1909, 210, 100, "Elasticsearch", ":9200", 1, { stateful: true, compact: true });
  const kibana = workload("kibana", 2160, 1909, 167, 100, "Kibana", ":5601", 1);
  const grafana = workload("grafana", 2393, 1909, 213, 120, "Grafana", ":3000", 1, { address: "CH" });
  const pgadmin = workload("pgadmin-pgadmin4", 2638, 1909, 175, 100, "pgAdmin", "установка отдельно", 1,
    { optional: true, compact: true });

  branches("ops", "Prometheus опрашивает экспортёры", bottom(prometheus),
    ["kube-state-metrics", "kafka-exporter", "redis-exporter", "node-exporter"]
      .map((id) => bottom(cards.find((node) => node.id === id))), 2041);
  wire("ops", "OTel Collector → Jaeger · OTLP", [right(otel, -8), left(jaeger, -8)]);
  wire("ops", "Prometheus опрашивает OTel Collector :8889", [right(prometheus, -8), left(otel, -8)]);
  wire("ops", "Filebeat → Elasticsearch", [right(filebeat, -8), left(elastic, -8)]);
  wire("ops", "Kibana → Elasticsearch", [left(kibana, -8), right(elastic, -8)]);
  branches("ops", "Grafana читает Prometheus, Jaeger и Elasticsearch", bottom(grafana),
    [bottom(prometheus, 63), bottom(jaeger), bottom(elastic)], 2077);
  label(919, 1891, "метрики pod и узлов", "ops");
  label(1179, 1891, "OTLP от Go и Istio", "ops");
  label(1680, 1891, "stdout / kubelet", "ops");
  label(pgadmin.x - 2, 2044, "SQL RO · отдельно", "ops");

  region(2861, 1800, 1001, 320, "Доставка через Flux",
    "Опционально · фоновое согласование GitOps и Flagger", "optional");
  const repository = card("git", 2885, 1909, 174, 70, "GitHub", "deploy/local", { optional: true });
  const flux = card("flux", 3099, 1909, 423, 117, "Flux · flux-system",
    "отдельные Deployment контроллеров", {
      optional: true, podFont: 12,
      pods: [
        { name: "source", detail: "1 pod" },
        { name: "kustomize", detail: "1 pod" },
        { name: "helm", detail: "1 pod" },
        { name: "notification", detail: "1 pod" },
      ],
    });
  const flagger = workload("flagger", 3568, 1909, 260, 117, "Flagger",
    "flagger-system", 1, { optional: true });
  const loadtester = workload("flagger-loadtester", 3568, 2043, 260, 64, "Loadtester",
    "", 1, { optional: true, compact: true });
  wire("optional", "Flux читает ветку deploy/local", [left(flux, -23.5), right(repository)]);
  wire("optional", "HelmRelease управляет Flagger", [right(flux, -6), left(flagger, -6)]);
  wire("optional", "Flagger → проверки через нагрузочный генератор", [bottom(flagger), top(loadtester)]);
  label(2891, 2064, "HelmRelease applications · 17 Canary-ресурсов", "ops");
  label(2891, 2093, "Во время выпуска · primary, canary и временные pod", "ops");

  region(38, 2154, 3824, 246, "Фоновые задания",
    "Job и CronJob создают pod по запуску · эти pod не входят в постоянные реплики", "alt");
  card("migration-jobs", 60, 2250, 1261, 115, "Миграции Helm",
    "Auth · Profile · Department · Brigade · Ticket · Location · Routing", {
      lines: ["Dispatch · File · Notification · SLA · Audit · Report · Asset",
        "Подключение к primary PostgreSQL напрямую · без PgBouncer"],
    });
  card("bootstrap-jobs", 1349, 2250, 1274, 115, "Инициализация",
    "Kafka init → топики · ClickHouse init → схема · Citus bootstrap / distribute", {
      lines: ["Backup bucket init → MinIO · два backup init → stanza pgBackRest",
        "Инициализация выполняется при подготовке инфраструктуры и выпуске"],
    });
  card("scheduled-jobs", 2650, 2250, 1185, 115, "По расписанию",
    "postgres-platform-backup · postgres-ticket-citus-backup → MinIO", {
      lines: ["kibana-dashboards → обновление сохранённых объектов Kibana"],
    });

  return { canvas, regions, cards, wires, dots, labels };
})();
