import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const output = path.join(root, "docs", "architecture");
const require = createRequire(import.meta.url);

const c = {
  bg: "#f6f8fb",
  paper: "#ffffff",
  ink: "#172235",
  muted: "#566579",
  border: "#d8e0ea",
  row: "#f3f6fa",
  blue: "#2764a5",
  blueSoft: "#e8f1fb",
  teal: "#087e68",
  tealSoft: "#e4f5ee",
  violet: "#7050a0",
  violetSoft: "#f0eafa",
  amber: "#a56818",
  amberSoft: "#fff2d9",
};

const esc = (value) => String(value)
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;");

function rect(x, y, w, h, fill = c.paper, stroke = c.border, radius = 6) {
  return `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${radius}" fill="${fill}" stroke="${stroke}"/>`;
}

function line(x1, y1, x2, y2, stroke = c.border, width = 1) {
  return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${stroke}" stroke-width="${width}"/>`;
}

function text(x, y, value, size = 16, color = c.ink, weight = 400, anchor = "start") {
  return `<text x="${x}" y="${y}" fill="${color}" font-size="${size}" font-weight="${weight}" text-anchor="${anchor}">${esc(value)}</text>`;
}

function arrow(x1, y, x2, color = c.blue) {
  return `<path d="M ${x1} ${y} H ${x2 - 10}" fill="none" stroke="${color}" stroke-width="2.5"/><path d="M ${x2 - 11} ${y - 6} L ${x2} ${y} L ${x2 - 11} ${y + 6} Z" fill="${color}"/>`;
}

function startSvg(width, height, title) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="${esc(title)}">
<style>text{font-family:"Segoe UI",Arial,sans-serif;letter-spacing:0}</style>
<rect width="${width}" height="${height}" fill="${c.bg}"/>
`;
}

function heading(label, title, subtitle, width) {
  return [
    rect(0, 0, width, 132, c.paper, c.paper, 0),
    rect(40, 32, 6, 60, c.blue, c.blue, 3),
    text(62, 47, label, 13, c.blue, 700),
    text(62, 82, title, 29, c.ink, 700),
    text(62, 111, subtitle, 15, c.muted),
    line(40, 132, width - 40, 132),
  ].join("");
}

function sectionTitle(x, y, index, title, caption, color) {
  return [
    rect(x, y - 24, 28, 28, color, color, 4),
    text(x + 14, y - 4, index, 14, c.paper, 700, "middle"),
    text(x + 40, y - 3, title, 19, c.ink, 700),
    text(x + 40, y + 20, caption, 13, c.muted),
  ].join("");
}

function syncSvg() {
  const width = 1600;
  const height = 1050;
  const parts = [
    startSvg(width, height, "Прямые связи Automatic City Services"),
    heading("01 / СИНХРОННЫЕ ВЗАИМОДЕЙСТВИЯ", "Карта прямых вызовов", "Внешний вход, межсервисные зависимости и вызовы сторонних систем", width),
  ];

  parts.push(rect(40, 164, 250, 238));
  parts.push(text(62, 194, "КЛИЕНТ", 13, c.blue, 700));
  parts.push(text(62, 231, "Браузер", 22, c.ink, 700));
  parts.push(line(62, 249, 268, 249));
  parts.push(text(62, 278, "Frontend", 19, c.ink, 600));
  parts.push(text(62, 306, "страницы и запросы", 14, c.muted));
  parts.push(text(62, 345, "Серверные маршруты:", 13, c.muted));
  parts.push(text(62, 368, "карта · геокодирование", 14, c.ink));

  parts.push(rect(340, 164, 256, 238, c.blueSoft, "#aac8e8"));
  parts.push(text(362, 194, "ВНЕШНЯЯ ТОЧКА ВХОДА", 13, c.blue, 700));
  parts.push(text(362, 237, "API Gateway", 24, c.ink, 700));
  parts.push(line(362, 254, 574, 254, "#aac8e8"));
  parts.push(text(362, 290, "HTTP-запросы", 17, c.ink, 600));
  parts.push(text(362, 322, "15 gRPC-клиентов", 17, c.ink, 600));
  parts.push(text(362, 370, "проверка доступа · Redis", 14, c.muted));

  parts.push(rect(646, 164, 914, 238));
  parts.push(text(668, 194, "ПРЕДМЕТНЫЕ И ВСПОМОГАТЕЛЬНЫЕ СЕРВИСЫ", 13, c.teal, 700));
  const services = [
    "Auth", "Profile", "Department", "Brigade", "Ticket",
    "Dispatch", "Location", "Routing", "Asset", "File",
    "SLA", "Notification", "Audit", "Analytics", "Report",
  ];
  services.forEach((name, index) => {
    const col = index % 5;
    const row = Math.floor(index / 5);
    const x = 668 + col * 176;
    const y = 215 + row * 57;
    parts.push(rect(x, y, 160, 44, c.tealSoft, "#c5e6d9", 5));
    parts.push(text(x + 80, y + 28, name, 15, c.ink, 600, "middle"));
  });
  parts.push(arrow(290, 283, 340));
  parts.push(arrow(596, 283, 646, c.teal));

  parts.push(rect(40, 430, 916, 398));
  parts.push(sectionTitle(64, 474, "2", "Между компонентами", "Только реально созданные клиенты и вызовы", c.teal));
  parts.push(line(64, 510, 932, 510));
  const internal = [
    ["Auth", "Profile", "gRPC"],
    ["Profile", "Auth · Department", "gRPC"],
    ["Brigade", "Profile · Department", "gRPC"],
    ["Dispatch", "Ticket · Brigade · Location · Routing", "gRPC"],
    ["Report", "Analytics · File", "gRPC"],
    ["Transponder Simulator", "Location", "HTTP"],
  ];
  internal.forEach(([from, to, protocol], i) => {
    const y = 524 + i * 48;
    if (i % 2 === 0) parts.push(rect(64, y, 868, 44, c.row, c.row, 3));
    parts.push(text(82, y + 28, from, 16, c.ink, 600));
    parts.push(text(305, y + 28, "→", 18, c.teal, 700));
    parts.push(text(340, y + 28, to, 16, c.ink));
    parts.push(text(912, y + 28, protocol, 13, c.muted, 600, "end"));
  });

  parts.push(rect(980, 430, 580, 398));
  parts.push(sectionTitle(1004, 474, "3", "Внешние зависимости", "Запросы, которые выполняет код", c.amber));
  parts.push(line(1004, 510, 1536, 510));
  const external = [
    ["Frontend", "Nominatim · Overpass · Valhalla"],
    ["Браузер", "S3 по подписанной ссылке"],
    ["Routing", "Valhalla"],
    ["File · Report", "S3 / MinIO"],
    ["Auth", "SMTP"],
    ["Notification", "Redis · SMTP · FCM*"],
    ["Gateway · Location", "отдельные Redis"],
  ];
  external.forEach(([from, to], i) => {
    const y = 521 + i * 42;
    if (i % 2 === 0) parts.push(rect(1004, y, 532, 39, c.row, c.row, 3));
    parts.push(text(1018, y + 26, from, 14, c.ink, 600));
    parts.push(text(1190, y + 26, "→", 16, c.amber, 700));
    parts.push(text(1220, y + 26, to, 14, c.ink));
  });

  parts.push(rect(40, 854, 1520, 156, c.blueSoft, "#c9dcec"));
  parts.push(text(64, 890, "ГРАНИЦЫ СХЕМЫ", 14, c.blue, 700));
  parts.push(text(64, 922, "Kafka и фоновые обработчики показаны на отдельной событийной карте.", 18, c.ink, 600));
  parts.push(text(64, 952, "Хранилища PostgreSQL / ClickHouse и точные доказательства стрелок перечислены в текстовой карте.", 16, c.muted));
  parts.push(text(64, 982, "* FCM используется только при наличии настроенного ключа. Схема описывает код, а не состояние кластера.", 15, c.muted));
  parts.push("</svg>");
  return parts.join("\n");
}

function eventSvg() {
  const width = 1600;
  const height = 1050;
  const parts = [
    startSvg(width, height, "Событийные связи Automatic City Services"),
    heading("02 / СОБЫТИЙНЫЕ ВЗАИМОДЕЙСТВИЯ", "Потоки Kafka", "Публикация и чтение различаются: настроенная тема не гарантирует наличие издателя", width),
  ];
  parts.push(rect(40, 164, 582, 704));
  parts.push(sectionTitle(64, 206, "1", "Издатели", "Тема, в которую пишет запускаемый передатчик", c.teal));
  parts.push(line(64, 244, 598, 244));
  const publishers = [
    ["Auth", "auth.events.v1"],
    ["Profile", "profiles.events.v1"],
    ["Department", "departments.events.v1"],
    ["Brigade", "brigades.events.v1"],
    ["Ticket", "tickets.events.v1"],
    ["Dispatch", "dispatch.events.v1"],
    ["Routing", "routing.events.v1"],
    ["Location", "locations.events.v1"],
    ["Asset", "assets.events.v1"],
    ["SLA", "sla.events.v1"],
    ["Report", "reports.events.v1"],
  ];
  publishers.forEach(([service, topic], i) => {
    const y = 260 + i * 52;
    if (i % 2 === 0) parts.push(rect(64, y, 534, 46, c.row, c.row, 3));
    parts.push(text(82, y + 30, service, 16, c.ink, 600));
    parts.push(text(286, y + 30, topic, 15, c.teal, 600));
  });

  parts.push(rect(676, 340, 248, 310, c.violetSoft, "#c5b1e1"));
  parts.push(rect(778, 377, 44, 44, c.violet, c.violet, 6));
  parts.push(text(800, 407, "K", 22, c.paper, 700, "middle"));
  parts.push(text(800, 462, "Kafka", 27, c.ink, 700, "middle"));
  parts.push(line(714, 482, 886, 482, "#c5b1e1"));
  parts.push(text(800, 520, "11 издателей", 18, c.violet, 600, "middle"));
  parts.push(text(800, 552, "9 читателей", 18, c.violet, 600, "middle"));
  parts.push(text(800, 604, "темы предметных", 14, c.muted, 400, "middle"));
  parts.push(text(800, 626, "событий", 14, c.muted, 400, "middle"));
  parts.push(arrow(622, 495, 676, c.violet));
  parts.push(arrow(924, 495, 978, c.violet));

  parts.push(rect(978, 164, 582, 704));
  parts.push(sectionTitle(1002, 206, "2", "Читатели", "Подписки, созданные в точках запуска", c.blue));
  parts.push(line(1002, 244, 1536, 244));
  const readers = [
    ["Brigade", "profiles · routing · tickets"],
    ["Ticket", "routing · reports"],
    ["Dispatch", "tickets"],
    ["Routing", "tickets"],
    ["SLA", "tickets"],
    ["Report", "tickets"],
    ["Notification", "9 тем по настройке"],
    ["Audit", "12 тем по конфигурации"],
    ["Analytics", "12 тем по конфигурации"],
  ];
  readers.forEach(([service, topics], i) => {
    const y = 265 + i * 65;
    if (i % 2 === 0) parts.push(rect(1002, y, 534, 57, c.row, c.row, 3));
    parts.push(text(1018, y + 26, service, 17, c.ink, 600));
    parts.push(text(1018, y + 47, topics, 14, c.blue));
  });

  parts.push(rect(40, 892, 1520, 118, c.amberSoft, "#edcf9a"));
  parts.push(text(64, 927, "ТЕМЫ БЕЗ НАЙДЕННОГО ИЗДАТЕЛЯ", 14, c.amber, 700));
  parts.push(text(64, 960, "files.events.v1 у Notification  ·  notifications.events.v1 у Audit и Analytics", 19, c.ink, 600));
  parts.push(text(64, 989, "Это настроенные подписки, а не подтвержденные потоки публикации. Точный состав тем и ссылки на код есть в текстовой карте.", 14, c.muted));
  parts.push("</svg>");
  return parts.join("\n");
}

const diagrams = [
  ["sync-interactions", syncSvg()],
  ["event-interactions", eventSvg()],
];

let sharp;
try {
  sharp = require(path.join(root, "Frontend", "node_modules", "sharp"));
} catch {
  sharp = null;
}

for (const [name, svg] of diagrams) {
  const svgPath = path.join(output, `${name}.svg`);
  fs.writeFileSync(svgPath, svg, "utf8");
  if (sharp) {
    await sharp(Buffer.from(svg)).png().toFile(path.join(output, `${name}.png`));
  }
}

if (!sharp) {
  process.stderr.write("PNG not regenerated: install Frontend dependencies (sharp). SVG files are current.\n");
}
