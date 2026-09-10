import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "..");
const outputDir = path.join(repoRoot, "docs", "architecture");

fs.mkdirSync(outputDir, { recursive: true });

const palette = {
  ink: "#0f172a",
  muted: "#475569",
  line: "#cbd5e1",
  canvas: "#f8fafc",
  blue: "#2563eb",
  blueSoft: "#eff6ff",
  cyan: "#0891b2",
  cyanSoft: "#ecfeff",
  green: "#059669",
  greenSoft: "#ecfdf5",
  orange: "#ea580c",
  orangeSoft: "#fff7ed",
  purple: "#7c3aed",
  purpleSoft: "#f5f3ff",
  red: "#dc2626",
  redSoft: "#fef2f2",
  amber: "#d97706",
  amberSoft: "#fffbeb",
  graySoft: "#f1f5f9",
  white: "#ffffff",
};

const edgeStyles = {
  http: { color: "#111827", dashed: false, width: 2.5 },
  grpc: { color: "#334155", dashed: false, width: 2.5 },
  kafka: { color: palette.purple, dashed: true, width: 2.5 },
  data: { color: palette.purple, dashed: false, width: 2.5 },
  object: { color: palette.blue, dashed: false, width: 2.5 },
  analytics: { color: palette.green, dashed: false, width: 2.5 },
  cache: { color: "#d97706", dashed: false, width: 2.5 },
  route: { color: palette.red, dashed: false, width: 2.5 },
  telemetry: { color: palette.cyan, dashed: true, width: 2 },
  control: { color: palette.muted, dashed: true, width: 2 },
  backup: { color: palette.red, dashed: true, width: 2.5 },
};

function esc(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function iconSvg(symbol, color = palette.blue) {
  const stroke = `fill="none" stroke="${color}" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"`;
  const solid = `fill="${color}"`;
  let body;

  switch (symbol) {
    case "users":
      body = `<circle cx="32" cy="19" r="8" ${solid}/><circle cx="15" cy="24" r="6" ${solid} opacity=".78"/><circle cx="49" cy="24" r="6" ${solid} opacity=".78"/><path d="M16 52c0-11 7-18 16-18s16 7 16 18M3 51c0-8 5-14 12-14M61 51c0-8-5-14-12-14" ${stroke}/>`;
      break;
    case "browser":
      body = `<rect x="7" y="10" width="50" height="42" rx="5" ${stroke}/><path d="M7 20h50M14 15h1M21 15h1M28 15h1" ${stroke}/><path d="M18 31h28M18 39h18" ${stroke} opacity=".7"/>`;
      break;
    case "vehicle":
      body = `<path d="M11 39l5-16h32l6 16v10H10V39zM18 23l4-8h20l6 8" ${stroke}/><circle cx="20" cy="49" r="5" ${solid}/><circle cx="45" cy="49" r="5" ${solid}/><path d="M18 34h28" ${stroke}/>`;
      break;
    case "cloud":
      body = `<path d="M17 49h31a10 10 0 0 0 2-20 18 18 0 0 0-34-4A12 12 0 0 0 17 49z" ${stroke}/>`;
      break;
    case "ingress":
      body = `<path d="M8 32h42M38 20l12 12-12 12" ${stroke}/><path d="M19 16v32" ${stroke} opacity=".55"/><circle cx="19" cy="16" r="4" ${solid}/><circle cx="19" cy="48" r="4" ${solid}/>`;
      break;
    case "gateway":
      body = `<path d="M32 5l22 9v15c0 14-9 24-22 30C19 53 10 43 10 29V14z" ${solid} opacity=".16"/><path d="M32 5l22 9v15c0 14-9 24-22 30C19 53 10 43 10 29V14z" ${stroke}/><circle cx="32" cy="30" r="11" ${stroke}/><path d="M21 30h22M32 19c4 4 4 18 0 22M32 19c-4 4-4 18 0 22" ${stroke}/>`;
      break;
    case "lock":
      body = `<rect x="14" y="28" width="36" height="27" rx="5" ${solid} opacity=".15"/><rect x="14" y="28" width="36" height="27" rx="5" ${stroke}/><path d="M22 28v-8a10 10 0 0 1 20 0v8M32 39v7" ${stroke}/><circle cx="32" cy="38" r="3" ${solid}/>`;
      break;
    case "person":
      body = `<circle cx="32" cy="18" r="10" ${solid}/><path d="M13 55c0-14 8-23 19-23s19 9 19 23" ${solid} opacity=".78"/>`;
      break;
    case "org":
      body = `<rect x="23" y="7" width="18" height="13" rx="3" ${stroke}/><rect x="5" y="43" width="16" height="13" rx="3" ${stroke}/><rect x="24" y="43" width="16" height="13" rx="3" ${stroke}/><rect x="43" y="43" width="16" height="13" rx="3" ${stroke}/><path d="M32 20v12M13 32h38M13 32v11M32 32v11M51 32v11" ${stroke}/>`;
      break;
    case "team":
      body = `<circle cx="32" cy="17" r="7" ${solid}/><circle cx="14" cy="23" r="6" ${solid} opacity=".75"/><circle cx="50" cy="23" r="6" ${solid} opacity=".75"/><path d="M17 53c0-12 6-19 15-19s15 7 15 19M2 52c0-10 5-16 12-16M62 52c0-10-5-16-12-16" ${stroke}/>`;
      break;
    case "ticket":
      body = `<path d="M13 11h30l8 8v34H13zM43 11v10h8" ${stroke}/><path d="M21 30h21M21 39h14" ${stroke}/><path d="M39 46l4 4 8-10" ${stroke}/>`;
      break;
    case "pin":
      body = `<path d="M32 58s18-18 18-34a18 18 0 1 0-36 0c0 16 18 34 18 34z" ${solid} opacity=".18"/><path d="M32 58s18-18 18-34a18 18 0 1 0-36 0c0 16 18 34 18 34z" ${stroke}/><circle cx="32" cy="24" r="7" ${solid}/>`;
      break;
    case "route":
      body = `<circle cx="13" cy="13" r="6" ${stroke}/><circle cx="51" cy="51" r="6" ${stroke}/><path d="M13 19v11c0 6 5 10 11 10h16c6 0 11 4 11 10M25 24l8-8M25 24l8 8" ${stroke}/>`;
      break;
    case "dispatch":
      body = `<path d="M8 19h30v27H8zM38 29h10l8 9v8H38z" ${stroke}/><circle cx="19" cy="48" r="5" ${solid}/><circle cx="47" cy="48" r="5" ${solid}/><path d="M15 13h16" ${stroke}/>`;
      break;
    case "folder":
      body = `<path d="M7 17h20l6 7h24v29H7z" ${solid} opacity=".16"/><path d="M7 17h20l6 7h24v29H7zM7 29h50" ${stroke}/>`;
      break;
    case "clipboard":
      body = `<rect x="13" y="10" width="38" height="48" rx="5" ${stroke}/><rect x="23" y="5" width="18" height="10" rx="4" fill="${palette.canvas}" stroke="${color}" stroke-width="3"/><path d="M22 28l4 4 8-9M22 43l4 4 8-9M39 28h5M39 43h5" ${stroke}/>`;
      break;
    case "bell":
      body = `<path d="M12 46h40l-6-8V26c0-9-6-16-14-16s-14 7-14 16v12z" ${solid} opacity=".16"/><path d="M12 46h40l-6-8V26c0-9-6-16-14-16s-14 7-14 16v12zM25 51c1 5 4 7 7 7s6-2 7-7" ${stroke}/>`;
      break;
    case "audit":
      body = `<path d="M10 8h32l10 10v38H10zM42 8v12h10M19 29h21M19 38h14" ${stroke}/><path d="M42 39l10 4v7c0 6-4 10-10 13-6-3-10-7-10-13v-7z" ${solid} opacity=".85"/>`;
      break;
    case "cube":
      body = `<path d="M32 6l23 13v26L32 58 9 45V19zM9 19l23 13 23-13M32 32v26" ${stroke}/>`;
      break;
    case "bars":
      body = `<rect x="9" y="38" width="9" height="18" rx="2" ${solid}/><rect x="23" y="27" width="9" height="29" rx="2" ${solid} opacity=".85"/><rect x="37" y="16" width="9" height="40" rx="2" ${solid} opacity=".7"/><rect x="51" y="8" width="6" height="48" rx="2" ${solid} opacity=".55"/>`;
      break;
    case "trend":
      body = `<path d="M7 52h50M10 46l13-15 11 8 18-24" ${stroke}/><path d="M43 15h9v9" ${stroke}/><circle cx="23" cy="31" r="3" ${solid}/><circle cx="34" cy="39" r="3" ${solid}/>`;
      break;
    case "database":
      body = `<ellipse cx="32" cy="14" rx="23" ry="9" ${solid} opacity=".2"/><path d="M9 14v36c0 5 10 9 23 9s23-4 23-9V14M9 14c0 5 10 9 23 9s23-4 23-9-10-9-23-9S9 9 9 14zM9 32c0 5 10 9 23 9s23-4 23-9" ${stroke}/>`;
      break;
    case "cluster":
      body = `<circle cx="32" cy="12" r="7" ${solid}/><circle cx="13" cy="31" r="7" ${solid} opacity=".85"/><circle cx="51" cy="31" r="7" ${solid} opacity=".85"/><circle cx="22" cy="52" r="7" ${solid} opacity=".7"/><circle cx="42" cy="52" r="7" ${solid} opacity=".7"/><path d="M27 17L17 25M37 17l10 8M17 38l3 7M47 38l-3 7M29 52h6" ${stroke}/>`;
      break;
    case "redis":
      body = `<path d="M7 20l25-12 25 12-25 12zM7 31l25 12 25-12M7 42l25 12 25-12" ${stroke}/>`;
      break;
    case "minio":
      body = `<path d="M11 55l12-46 13 18 9-14 8 42M23 9l13 46M45 13L32 55" ${stroke}/>`;
      break;
    case "clickhouse":
      body = `<rect x="8" y="9" width="7" height="46" ${solid}/><rect x="20" y="9" width="7" height="46" ${solid}/><rect x="32" y="9" width="7" height="46" ${solid}/><rect x="44" y="21" width="7" height="34" ${solid}/><rect x="56" y="9" width="3" height="46" ${solid} opacity=".45"/>`;
      break;
    case "mountain":
      body = `<circle cx="32" cy="32" r="27" ${solid} opacity=".16"/><path d="M8 51l15-29 9 16 8-12 16 25M22 24l5 10M40 27l5 9" ${stroke}/>`;
      break;
    case "map":
      body = `<path d="M7 14l16-7 18 7 16-7v43l-16 7-18-7-16 7zM23 7v43M41 14v43" ${stroke}/>`;
      break;
    case "mail":
      body = `<rect x="7" y="13" width="50" height="38" rx="5" ${stroke}/><path d="M9 17l23 20 23-20M9 48l17-16M55 48L38 32" ${stroke}/>`;
      break;
    case "kafka":
      body = `<circle cx="32" cy="32" r="8" ${solid}/><circle cx="13" cy="12" r="6" ${stroke}/><circle cx="51" cy="12" r="6" ${stroke}/><circle cx="13" cy="52" r="6" ${stroke}/><circle cx="51" cy="52" r="6" ${stroke}/><path d="M26 26L17 17M38 26l9-9M26 38l-9 9M38 38l9 9" ${stroke}/>`;
      break;
    case "metrics":
      body = `<path d="M32 6c5 11 13 15 13 25a13 13 0 0 1-26 0c0-7 4-12 9-18 0 8 5 10 4-7z" ${solid}/><path d="M13 52h38M19 58h26" ${stroke}/>`;
      break;
    case "dashboard":
      body = `<circle cx="32" cy="32" r="24" ${stroke}/><path d="M32 8v8M49 15l-6 6M56 32h-8M15 15l6 6M8 32h8M22 43c5 5 15 5 20 0M32 32l11-10" ${stroke}/>`;
      break;
    case "trace":
      body = `<circle cx="12" cy="18" r="5" ${solid}/><circle cx="32" cy="32" r="5" ${solid}/><circle cx="52" cy="15" r="5" ${solid}/><circle cx="50" cy="50" r="5" ${solid}/><path d="M16 21l12 8M36 29l12-11M35 36l11 11" ${stroke}/>`;
      break;
    case "logs":
      body = `<path d="M9 10h46v44H9z" ${stroke}/><path d="M17 22h30M17 32h24M17 42h18" ${stroke}/><circle cx="50" cy="43" r="7" ${solid} opacity=".75"/>`;
      break;
    case "mesh":
      body = `<circle cx="12" cy="14" r="5" ${solid}/><circle cx="52" cy="14" r="5" ${solid}/><circle cx="32" cy="32" r="7" ${solid}/><circle cx="12" cy="52" r="5" ${solid}/><circle cx="52" cy="52" r="5" ${solid}/><path d="M16 17l11 11M48 17L37 28M16 49l11-12M48 49L37 37" ${stroke}/>`;
      break;
    case "shield":
      body = `<path d="M32 5l22 9v15c0 14-9 24-22 30C19 53 10 43 10 29V14z" ${stroke}/><path d="M22 31l7 7 14-16" ${stroke}/>`;
      break;
    case "code":
      body = `<path d="M24 15L8 32l16 17M40 15l16 17-16 17M37 8L27 56" ${stroke}/>`;
      break;
    case "warning":
      body = `<path d="M32 7L59 55H5z" ${stroke}/><path d="M32 23v16M32 48h.1" ${stroke}/>`;
      break;
    default:
      body = `<circle cx="32" cy="32" r="23" ${stroke}/><path d="M20 32h24M32 20v24" ${stroke}/>`;
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">${body}</svg>`;
}

function iconDataUri(symbol, color) {
  return `data:image/svg+xml;base64,${Buffer.from(iconSvg(symbol, color), "utf8").toString("base64")}`;
}

function htmlLabel(node) {
  const badgeColor = node.badgeColor ?? node.color ?? palette.blue;
  const icon = iconDataUri(node.symbol ?? "default", node.iconColor ?? badgeColor);
  const status = node.status
    ? `<span style="float:right;background:${node.status === "HA" ? palette.greenSoft : palette.amberSoft};color:${node.status === "HA" ? palette.green : palette.amber};border:1px solid ${node.status === "HA" ? "#86efac" : "#fcd34d"};border-radius:10px;padding:2px 7px;font-size:10px;font-weight:700;">${esc(node.status)}</span>`
    : "";

  if (node.visual === "service") {
    return `<div style="font-family:Inter,Segoe UI,Arial,sans-serif;text-align:center;padding:7px 8px;line-height:1.2;">` +
      `<div style="text-align:left;"><span style="display:inline-block;background:#18a7b5;color:#ffffff;clip-path:polygon(25% 0,75% 0,100% 50%,75% 100%,25% 100%,0 50%);padding:4px 7px;font-size:9px;font-weight:700;">GO</span>${status}</div>` +
      `<div style="margin-top:-18px;color:${palette.ink};font-size:13px;font-weight:700;">${esc(node.title)}</div>` +
      `<img src="${icon}" width="48" height="48" style="margin-top:8px;"/>` +
      (node.subtitle ? `<div style="margin-top:5px;color:${palette.muted};font-size:10px;">${esc(node.subtitle)}</div>` : "") +
      `</div>`;
  }

  if (node.visual === "actor" || node.visual === "access" || node.visual === "technology") {
    return `<div style="font-family:Inter,Segoe UI,Arial,sans-serif;text-align:center;padding:10px;line-height:1.25;">` +
      `${status}<img src="${icon}" width="58" height="58" style="margin-top:3px;"/>` +
      `<div style="margin-top:8px;color:${palette.ink};font-size:14px;font-weight:700;">${esc(node.title)}</div>` +
      (node.subtitle ? `<div style="margin-top:5px;color:${palette.muted};font-size:10px;">${esc(node.subtitle)}</div>` : "") +
      `</div>`;
  }

  if (node.visual === "observability") {
    return `<table style="font-family:Inter,Segoe UI,Arial,sans-serif;width:100%;height:100%;border-collapse:collapse;"><tr>` +
      `<td style="width:72px;text-align:center;"><img src="${icon}" width="50" height="50"/></td>` +
      `<td style="text-align:left;"><div style="color:${palette.ink};font-size:14px;font-weight:700;">${esc(node.title)}</div>` +
      (node.subtitle ? `<div style="margin-top:4px;color:${palette.muted};font-size:10px;">${esc(node.subtitle)}</div>` : "") +
      `</td></tr></table>`;
  }

  if (node.visual === "principle") {
    return `<table style="font-family:Inter,Segoe UI,Arial,sans-serif;width:100%;height:100%;border-collapse:collapse;"><tr>` +
      `<td style="width:52px;text-align:center;"><img src="${icon}" width="38" height="38"/></td>` +
      `<td style="text-align:left;color:${palette.ink};font-size:11px;font-weight:700;">${esc(node.title)}</td>` +
      `</tr></table>`;
  }

  if (node.visual === "legend") {
    const style = edgeStyles[node.edgeKind] ?? edgeStyles.control;
    const line = style.dashed ? "┄┄▶" : "━━▶";
    return `<div style="font-family:Inter,Segoe UI,Arial,sans-serif;text-align:left;padding:7px 5px;font-size:11px;color:${palette.ink};">` +
      `<span style="display:inline-block;width:58px;color:${style.color};font-size:16px;font-weight:700;">${line}</span>${esc(node.title)}` +
      `</div>`;
  }

  const details = (node.details ?? []).map((line) => `<div style="margin-top:4px;color:${palette.muted};font-size:11px;">${esc(line)}</div>`).join("");
  return `<div style="font-family:Inter,Segoe UI,Arial,sans-serif;text-align:left;padding:8px 10px;line-height:1.25;">` +
    `<div>${status}<span style="display:inline-block;background:${badgeColor};color:#ffffff;border-radius:6px;padding:3px 7px;font-size:10px;font-weight:700;letter-spacing:.4px;">${esc(node.icon ?? "APP")}</span></div>` +
    `<div style="margin-top:7px;color:${palette.ink};font-size:14px;font-weight:700;">${esc(node.title)}</div>` +
    (node.subtitle ? `<div style="margin-top:3px;color:${badgeColor};font-size:11px;font-weight:600;">${esc(node.subtitle)}</div>` : "") +
    details +
    `</div>`;
}

function nodeStyle(node) {
  const fill = node.fill ?? palette.white;
  const stroke = node.stroke ?? node.color ?? palette.line;
  const common = `html=1;whiteSpace=wrap;overflow=hidden;shadow=1;strokeWidth=1.5;fillColor=${fill};strokeColor=${stroke};fontColor=${palette.ink};`;
  if (node.visual === "legend") {
    return `html=1;whiteSpace=wrap;overflow=hidden;shadow=0;strokeColor=none;fillColor=none;fontColor=${palette.ink};`;
  }
  if (node.type === "database" || node.type === "storage" || node.type === "cache") {
    return `shape=cylinder3;boundedLbl=1;backgroundOutline=1;size=14;${common}`;
  }
  if (node.type === "bus") {
    return `shape=hexagon;perimeter=hexagonPerimeter2;arcSize=8;${common}`;
  }
  if (node.type === "cloud") {
    return `shape=cloud;${common}`;
  }
  if (node.type === "note") {
    return `shape=note;size=18;${common}`;
  }
  if (node.type === "control") {
    return `shape=mxgraph.basic.octagon;${common}`;
  }
  return `rounded=1;arcSize=16;${common}`;
}

function makeIllustratedOverview() {
  const serviceColor = "#5574c6";
  const serviceFill = "#ffffff";
  const observabilityColor = "#7e22ce";

  const service = (id, title, port, symbol, x, y) => ({
    id,
    x,
    y,
    w: 240,
    h: 145,
    title,
    subtitle: `gRPC :${port}`,
    symbol,
    color: serviceColor,
    iconColor: "#1f4eaa",
    fill: serviceFill,
    visual: "service",
  });

  const technology = (id, title, subtitle, details, symbol, color, x) => ({
    id,
    x,
    y: 1080,
    w: 240,
    h: 300,
    title,
    subtitle,
    details,
    symbol,
    color,
    iconColor: color,
    fill: "#ffffff",
    visual: "technology",
  });

  const observable = (id, title, subtitle, symbol, color, y, details = []) => ({
    id,
    x: 2060,
    y,
    w: 270,
    h: details.length > 0 ? 145 : 130,
    title,
    subtitle,
    details,
    symbol,
    color,
    iconColor: color,
    fill: "#ffffff",
    visual: "observability",
  });

  const principle = (id, title, symbol, x, color) => ({
    id,
    x,
    y: 1545,
    w: 250,
    h: 70,
    title,
    symbol,
    color,
    iconColor: color,
    fill: "#ffffff",
    visual: "principle",
  });

  const legend = (id, title, edgeKind, y) => ({
    id,
    x: 65,
    y,
    w: 250,
    h: 43,
    title,
    edgeKind,
    visual: "legend",
  });

  const groups = [
    { id: "logical-clients-zone", title: "1. Клиенты / edge", x: 40, y: 170, w: 300, h: 820, fill: "#f8fbff", stroke: "#a5b4fc", titleColor: "#1e40af", dashed: false },
    { id: "logical-access-zone", title: "2. Слой доступа", x: 360, y: 170, w: 270, h: 820, fill: "#f4fdf8", stroke: "#86efac", titleColor: "#047857", dashed: false },
    { id: "logical-services-zone", title: "3. Доменные микросервисы · Go / gRPC", x: 650, y: 170, w: 1360, h: 820, fill: "#fbfdff", stroke: "#93c5fd", titleColor: "#1d4ed8", dashed: false },
    { id: "logical-legend-zone", title: "Легенда", x: 40, y: 1010, w: 300, h: 450, fill: "#ffffff", stroke: "#d1d5db", titleColor: "#374151", dashed: false },
    { id: "logical-data-zone", title: "4. Данные и интеграции", x: 360, y: 1010, w: 1650, h: 450, fill: "#fffbeb", stroke: "#fde68a", titleColor: "#92400e", dashed: false },
    { id: "logical-observability-zone", title: "5. Наблюдаемость и поддержка", x: 2030, y: 170, w: 330, h: 1290, fill: "#fdf8ff", stroke: "#d8b4fe", titleColor: "#7e22ce", dashed: false },
    { id: "logical-principles-zone", title: "Ключевые принципы", x: 360, y: 1480, w: 2000, h: 160, fill: "#f8fafc", stroke: "#cbd5e1", titleColor: "#1e3a8a", dashed: false },
  ];

  const nodes = [
    {
      id: "logical-users",
      x: 70,
      y: 245,
      w: 240,
      h: 185,
      title: "Пользователи",
      subtitle: "Житель · диспетчер",
      details: ["Работник · администратор"],
      symbol: "users",
      color: "#2563eb",
      fill: "#ffffff",
      visual: "actor",
    },
    {
      id: "logical-frontend",
      x: 70,
      y: 480,
      w: 240,
      h: 210,
      title: "Web Frontend",
      subtitle: "UI · карты · WebSocket",
      details: ["HTTPS / HTTP2", "role-aware workspace"],
      symbol: "browser",
      color: "#2563eb",
      fill: "#ffffff",
      visual: "actor",
    },
    {
      id: "logical-trackers",
      x: 70,
      y: 740,
      w: 240,
      h: 185,
      title: "GPS / машины бригад",
      subtitle: "HTTP telemetry + API key",
      details: ["live coordinates"],
      symbol: "vehicle",
      color: "#2563eb",
      fill: "#ffffff",
      visual: "actor",
    },

    {
      id: "logical-ngrok",
      x: 390,
      y: 245,
      w: 210,
      h: 165,
      title: "ngrok Tunnel",
      subtitle: "опционально · dev",
      details: ["единый публичный HTTPS URL"],
      symbol: "cloud",
      color: "#059669",
      fill: "#ffffff",
      visual: "access",
    },
    {
      id: "logical-ingress",
      x: 390,
      y: 455,
      w: 210,
      h: 165,
      title: "Istio Ingress",
      subtitle: "TLS · VirtualService",
      details: ["HTTP/2 routing"],
      symbol: "ingress",
      color: "#059669",
      fill: "#ffffff",
      visual: "access",
    },
    {
      id: "logical-gateway",
      x: 390,
      y: 670,
      w: 210,
      h: 230,
      title: "API Gateway",
      subtitle: "REST/JSON → gRPC",
      details: ["JWT / RBAC", "rate limit · retries"],
      symbol: "gateway",
      color: "#047857",
      fill: "#ffffff",
      visual: "access",
    },

    {
      id: "logical-mesh",
      x: 680,
      y: 220,
      w: 1280,
      h: 55,
      title: "Istio service mesh · gRPC / HTTP2 · mTLS STRICT · trace context",
      symbol: "mesh",
      color: "#0891b2",
      fill: "#ecfeff",
      visual: "principle",
      type: "control",
    },

    service("logical-auth", "Auth", 50051, "lock", 680, 300),
    service("logical-profile", "Profile", 50055, "person", 940, 300),
    service("logical-department", "Department", 50053, "org", 1200, 300),
    service("logical-brigade", "Brigade", 50054, "team", 1460, 300),
    service("logical-ticket", "Ticket", 50052, "ticket", 1720, 300),

    service("logical-location", "Location", 50056, "pin", 680, 485),
    service("logical-routing", "Routing", 50057, "route", 940, 485),
    service("logical-dispatch", "Dispatch", 50058, "dispatch", 1200, 485),
    service("logical-file", "File", 50059, "folder", 1460, 485),
    service("logical-sla", "SLA", 50060, "clipboard", 1720, 485),

    service("logical-notification", "Notification", 50061, "bell", 680, 670),
    service("logical-audit", "Audit", 50062, "audit", 940, 670),
    service("logical-asset", "Asset", 50065, "cube", 1200, 670),
    service("logical-report", "Report", 50064, "bars", 1460, 670),
    service("logical-analytics", "Analytics", 50063, "trend", 1720, 670),

    {
      id: "logical-kafka",
      x: 750,
      y: 850,
      w: 1180,
      h: 110,
      title: "Apache Kafka · KRaft ×3",
      subtitle: "Доменные события · transactional outbox / inbox · consumer idempotency",
      details: ["RF=3 · min ISR=2 · retry topics · DLQ · completion Saga"],
      symbol: "kafka",
      color: palette.purple,
      iconColor: palette.purple,
      fill: "#faf5ff",
      visual: "event-bus",
      type: "bus",
      status: "HA",
    },

    technology("logical-platform-db", "PostgreSQL / Patroni", "platform · 13 service DBs", ["PgBouncer read/write ×2", "primary + 2 replicas"], "database", "#336791", 390),
    technology("logical-ticket-db", "Citus / Patroni", "ticket_db · department_id", ["coordinator ×3 · workers 2+2", "PgBouncer read/write ×2"], "cluster", "#7c3aed", 650),
    technology("logical-redis", "Redis", "Gateway · Location · Notify", ["Location: replicas + Sentinel ×3", "other two contours ×1"], "redis", "#dc2626", 910),
    technology("logical-minio", "MinIO", "S3 object storage", ["city-files · PDF", "pgBackRest backups"], "minio", "#dc2626", 1170),
    technology("logical-clickhouse", "ClickHouse", "analytics read model", ["domain events · reports", "FINAL queries"], "clickhouse", "#eab308", 1430),
    technology("logical-external", "External engines", "Valhalla · OSM/Nominatim", ["routing · tiles · geocode", "Mailhog / SMTP"], "mountain", "#16a34a", 1690),

    observable("logical-prometheus", "Prometheus", "метрики и exporters", "metrics", "#e8462b", 245),
    observable("logical-grafana", "Grafana", "дашборды · logs · traces", "dashboard", "#f97316", 405),
    observable("logical-otel", "OpenTelemetry", "OTLP traces · context", "trace", "#0891b2", 565),
    observable("logical-jaeger", "Jaeger", "distributed tracing", "route", "#0f766e", 725),
    observable("logical-elk", "ELK Stack", "Filebeat → Elasticsearch", "logs", "#7c3aed", 885, ["Kibana · log.level · trace_id"]),
    observable("logical-kiali", "Kiali + Istiod", "mesh topology / policy", "mesh", "#2563eb", 1075),
    observable("logical-exporters", "Infra exporters", "K8s · PG · Kafka · Redis", "bars", "#0891b2", 1235, ["PgBouncer · MinIO · ClickHouse"]),

    legend("logical-legend-sync", "Синхронные gRPC / REST", "grpc", 1075),
    legend("logical-legend-events", "Событийные потоки Kafka", "kafka", 1123),
    legend("logical-legend-object", "Доступ к объектам / S3", "object", 1171),
    legend("logical-legend-analytics", "Аналитика и отчёты", "analytics", 1219),
    legend("logical-legend-cache", "Кэш / временное состояние", "cache", 1267),
    legend("logical-legend-route", "Маршрутизация / geo", "route", 1315),
    legend("logical-legend-telemetry", "Telemetry / control plane", "telemetry", 1363),

    principle("logical-principle-entry", "Единая точка входа", "shield", 390, "#2563eb"),
    principle("logical-principle-go", "Go · gRPC · HTTP2", "code", 660, "#0891b2"),
    principle("logical-principle-events", "Outbox · Inbox · DLQ", "kafka", 930, "#7c3aed"),
    principle("logical-principle-db", "Service-owned databases", "database", 1200, "#64748b"),
    principle("logical-principle-shards", "Citus · department_id", "cluster", 1470, "#7c3aed"),
    principle("logical-principle-observe", "Metrics · logs · traces", "trace", 1740, "#0891b2"),
    principle("logical-principle-ha", "HA core · SPOF marked", "warning", 2010, "#d97706"),
  ];

  const edges = [
    ["logical-users", "logical-frontend", "UI", "http"],
    ["logical-frontend", "logical-ngrok", "HTTPS", "http"],
    ["logical-ngrok", "logical-ingress", "tunnel", "http"],
    ["logical-ingress", "logical-gateway", "REST / WS", "http"],
    ["logical-gateway", "logical-mesh", "gRPC / HTTP2", "grpc"],
    ["logical-mesh", "logical-auth", "public APIs", "grpc"],
    ["logical-trackers", "logical-location", "telemetry", "http"],

    ["logical-auth", "logical-profile", "atomic create / rollback", "grpc"],
    ["logical-profile", "logical-department", "working department", "grpc"],
    ["logical-brigade", "logical-profile", "worker profile", "grpc"],
    ["logical-dispatch", "logical-ticket", "reserve / assign", "grpc"],
    ["logical-dispatch", "logical-brigade", "availability", "grpc"],
    ["logical-report", "logical-file", "save PDF", "grpc"],
    ["logical-report", "logical-analytics", "aggregates", "grpc"],

    ["logical-ticket", "logical-kafka", "tickets + Saga", "kafka"],
    ["logical-location", "logical-kafka", "positions relay", "kafka"],
    ["logical-asset", "logical-kafka", "asset events", "kafka"],
    ["logical-report", "logical-kafka", "result / compensation", "kafka"],
    ["logical-kafka", "logical-notification", "user events", "kafka"],
    ["logical-kafka", "logical-audit", "all events", "kafka"],
    ["logical-kafka", "logical-analytics", "all events", "kafka"],
    ["logical-kafka", "logical-sla", "ticket lifecycle", "kafka"],
    ["logical-kafka", "logical-routing", "ticket events", "kafka"],
    ["logical-kafka", "logical-brigade", "projections", "kafka"],

    ["logical-auth", "logical-platform-db", "service DBs", "data"],
    ["logical-location", "logical-platform-db", "history", "data"],
    ["logical-notification", "logical-platform-db", "delivery state", "data"],
    ["logical-asset", "logical-platform-db", "PostGIS", "data"],
    ["logical-ticket", "logical-ticket-db", "sharded by department_id", "data"],
    ["logical-gateway", "logical-redis", "rate limits", "cache"],
    ["logical-location", "logical-redis", "live positions", "cache"],
    ["logical-notification", "logical-redis", "live channels", "cache"],
    ["logical-file", "logical-minio", "objects", "object"],
    ["logical-report", "logical-minio", "PDF", "object"],
    ["logical-analytics", "logical-clickhouse", "OLAP", "analytics"],
    ["logical-routing", "logical-external", "Valhalla", "route"],
    ["logical-frontend", "logical-external", "tiles / geocode", "route"],
    ["logical-auth", "logical-external", "SMTP", "http"],

    ["logical-mesh", "logical-otel", "OTLP", "telemetry"],
    ["logical-otel", "logical-jaeger", "traces", "telemetry"],
    ["logical-prometheus", "logical-grafana", "PromQL", "telemetry"],
    ["logical-elk", "logical-grafana", "logs", "telemetry"],
    ["logical-prometheus", "logical-kiali", "mesh metrics", "telemetry"],
    ["logical-exporters", "logical-prometheus", "scrape", "telemetry"],
  ].map(([source, target, label, kind]) => ({ source, target, label, kind }));

  return {
    id: "logical-illustrated",
    name: "01 Логическая архитектура",
    title: "Automatic City Services — логическая архитектура",
    subtitle: "Слои доступа, доменные Go/gRPC-сервисы, событийная шина, service-owned data и единая наблюдаемость",
    titleAlign: "center",
    showTopLegend: false,
    width: 2400,
    height: 1680,
    groups,
    nodes,
    edges,
  };
}

function makeOverview() {
  const groups = [
    { id: "edge-zone", title: "01 · Клиенты и edge", x: 40, y: 170, w: 500, h: 1040, fill: palette.greenSoft, stroke: "#6ee7b7" },
    { id: "mesh-zone", title: "02 · Прикладные сервисы · Istio mesh · gRPC/HTTP2", x: 580, y: 170, w: 1320, h: 1040, fill: palette.blueSoft, stroke: "#93c5fd" },
    { id: "data-zone", title: "03 · Данные и внешние движки", x: 1940, y: 170, w: 620, h: 1040, fill: palette.purpleSoft, stroke: "#c4b5fd" },
    { id: "event-zone", title: "04 · Асинхронная шина · transactional outbox / inbox / retry / DLQ", x: 580, y: 1250, w: 1980, h: 300, fill: palette.orangeSoft, stroke: "#fdba74" },
    { id: "obs-zone", title: "05 · Наблюдаемость и эксплуатация", x: 40, y: 1590, w: 2520, h: 260, fill: palette.cyanSoft, stroke: "#67e8f9" },
  ];

  const nodes = [
    { id: "users", x: 70, y: 250, w: 205, h: 145, icon: "USERS", title: "Пользователи", subtitle: "Житель · диспетчер", details: ["Работник · администратор", "Browser · role-aware UI"], color: palette.green, fill: palette.white },
    { id: "trackers", x: 305, y: 250, w: 205, h: 145, icon: "GPS", title: "GPS и машины", subtitle: "Location ingest", details: ["HTTP + API key", "Live coordinates"], color: palette.green, fill: palette.white },
    { id: "ngrok", x: 70, y: 445, w: 440, h: 105, icon: "EDGE", title: "ngrok Tunnel (опционально)", subtitle: "Единый публичный HTTPS URL", details: ["Dev-доступ без входящего NodePort"], color: palette.green, fill: palette.white, type: "cloud" },
    { id: "ingress", x: 70, y: 600, w: 440, h: 110, icon: "ISTIO", title: "Istio Ingress Gateway", subtitle: "TLS / VirtualService / routing", details: ["Frontend :3000 · API Gateway :8081"], color: palette.green, fill: palette.white, type: "control" },
    { id: "frontend", x: 70, y: 770, w: 205, h: 170, icon: "WEB", title: "Frontend", subtitle: "React/Vite", details: ["Карты и заявки", "HTTPS · HTTP/2", "WebSocket"], color: palette.green, fill: palette.white },
    { id: "gateway", x: 305, y: 770, w: 205, h: 170, icon: "API", title: "API Gateway", subtitle: "REST → gRPC", details: ["JWT/RBAC", "rate limits", "retries/timeouts"], color: palette.blue, fill: palette.white },

    { id: "auth", x: 630, y: 265, w: 270, h: 155, icon: "AUTH", title: "Auth Service", subtitle: "gRPC :50051", details: ["Пользователи, сессии, JWT, email", "Atomic registration → Profile · outbox"], color: palette.blue, fill: palette.white },
    { id: "profile", x: 950, y: 265, w: 270, h: 155, icon: "PROFILE", title: "Profile Service", subtitle: "gRPC :50055", details: ["Профили и рабочие роли", "Auth + Department lookups · outbox"], color: palette.blue, fill: palette.white },
    { id: "department", x: 1270, y: 265, w: 270, h: 155, icon: "DEPT", title: "Department Service", subtitle: "gRPC :50053", details: ["Департаменты и зоны ответственности", "Справочники · outbox"], color: palette.blue, fill: palette.white },
    { id: "brigade", x: 1590, y: 265, w: 270, h: 155, icon: "TEAM", title: "Brigade Service", subtitle: "gRPC :50054", details: ["Бригады, навыки, смены, занятость", "Profile projection · routing/ticket consumers"], color: palette.blue, fill: palette.white },

    { id: "ticket", x: 630, y: 490, w: 270, h: 165, icon: "TICKET", title: "Ticket Service", subtitle: "gRPC :50052 · центральный workflow", details: ["Заявки, статусы, назначения, отчёты", "Citus department_id · outbox · Saga"], color: palette.green, fill: palette.white },
    { id: "dispatch", x: 950, y: 490, w: 270, h: 165, icon: "DISPATCH", title: "Dispatch Service", subtitle: "gRPC :50058", details: ["Подбор департамента и бригады", "Reservations TTL · Ticket + Brigade"], color: palette.green, fill: palette.white },
    { id: "location", x: 1270, y: 490, w: 270, h: 165, icon: "GEO", title: "Location Service", subtitle: "gRPC :50056 · HTTP :8080", details: ["Live positions · history partitions", "Redis Stream → Kafka relay"], color: palette.green, fill: palette.white },
    { id: "routing", x: 1590, y: 490, w: 270, h: 165, icon: "ROUTE", title: "Routing Service", subtitle: "gRPC :50057", details: ["Маршруты и ETA", "Valhalla · ticket consumer · outbox"], color: palette.green, fill: palette.white },

    { id: "file", x: 630, y: 715, w: 270, h: 165, icon: "FILE", title: "File Service", subtitle: "gRPC :50059", details: ["Метаданные + presigned URL", "Синхронный MinIO/S3 lifecycle"], color: palette.purple, fill: palette.white },
    { id: "report", x: 950, y: 715, w: 270, h: 165, icon: "PDF", title: "Report Service", subtitle: "gRPC :50064 · HTTP :8084", details: ["PDF/аналитические отчёты", "Completion Saga · File + Analytics"], color: palette.purple, fill: palette.white },
    { id: "asset", x: 1270, y: 715, w: 270, h: 165, icon: "ASSET", title: "Asset Service", subtitle: "gRPC :50065", details: ["Паспорта городских объектов", "PostGIS geometry · lifecycle · outbox"], color: palette.purple, fill: palette.white },
    { id: "sla", x: 1590, y: 715, w: 270, h: 165, icon: "SLA", title: "SLA Service", subtitle: "gRPC :50060", details: ["Deadlines, warning, breach", "tickets consumer → sla events"], color: palette.purple, fill: palette.white },

    { id: "notification", x: 630, y: 940, w: 270, h: 165, icon: "NOTIFY", title: "Notification Service", subtitle: "gRPC :50061 · WebSocket", details: ["Общие пользовательские уведомления", "Kafka fan-in · Redis live channels · SMTP"], color: palette.orange, fill: palette.white },
    { id: "audit", x: 950, y: 940, w: 270, h: 165, icon: "AUDIT", title: "Audit Service", subtitle: "gRPC :50062", details: ["Неизменяемый журнал действий", "Все доменные Kafka events"], color: palette.orange, fill: palette.white },
    { id: "analytics", x: 1270, y: 940, w: 270, h: 165, icon: "OLAP", title: "Analytics Service", subtitle: "gRPC :50063", details: ["Read models и агрегаты", "Все события → ClickHouse"], color: palette.orange, fill: palette.white },
    { id: "grpc-fabric", x: 1590, y: 940, w: 270, h: 165, icon: "MESH", title: "Service mesh fabric", subtitle: "HTTP/2 gRPC · mTLS STRICT", details: ["Trace context · retries · connection pools", "NetworkPolicy + AuthorizationPolicy"], color: palette.cyan, fill: palette.white, type: "control" },

    { id: "platform-db", x: 1985, y: 265, w: 530, h: 185, icon: "PG", title: "Platform PostgreSQL / Patroni", subtitle: "13 service-owned databases", details: ["auth · department · brigade · profile · location", "routing · dispatch · file · sla · notification", "audit · report · asset (PostGIS)"], color: palette.purple, fill: palette.white, type: "database", status: "HA" },
    { id: "ticket-db", x: 1985, y: 490, w: 530, h: 175, icon: "CITUS", title: "Ticket PostgreSQL + Citus", subtitle: "ticket_db · shard key department_id", details: ["Coordinator + 2 worker groups", "Colocated ticket/history/report/outbox tables"], color: palette.purple, fill: palette.white, type: "database", status: "HA" },
    { id: "redis-gateway", x: 1985, y: 715, w: 160, h: 145, icon: "RDS", title: "Redis Gateway", subtitle: "rate limit", details: ["AOF"], color: palette.red, fill: palette.white, type: "cache" },
    { id: "redis-location", x: 2170, y: 715, w: 160, h: 145, icon: "RDS", title: "Redis Location", subtitle: "master + 2 replicas", details: ["Sentinel ×3"], color: palette.red, fill: palette.white, type: "cache", status: "HA" },
    { id: "redis-notification", x: 2355, y: 715, w: 160, h: 145, icon: "RDS", title: "Redis Notify", subtitle: "live channels", details: ["AOF"], color: palette.red, fill: palette.white, type: "cache" },
    { id: "minio", x: 1985, y: 900, w: 250, h: 135, icon: "S3", title: "MinIO", subtitle: "city-files · postgres-backups", details: ["Attachments · PDF · pgBackRest"], color: palette.purple, fill: palette.white, type: "storage" },
    { id: "clickhouse", x: 2265, y: 900, w: 250, h: 135, icon: "CH", title: "ClickHouse", subtitle: "analytics read model", details: ["domain_events FINAL"], color: palette.purple, fill: palette.white, type: "database" },
    { id: "valhalla", x: 1985, y: 1070, w: 160, h: 100, icon: "MAP", title: "Valhalla", subtitle: "routing :8002", details: [], color: palette.green, fill: palette.white, type: "cloud" },
    { id: "openstreetmap", x: 2170, y: 1070, w: 160, h: 100, icon: "OSM", title: "OSM / Nominatim", subtitle: "tiles · geocode", details: [], color: palette.green, fill: palette.white, type: "cloud" },
    { id: "mailhog", x: 2355, y: 1070, w: 160, h: 100, icon: "SMTP", title: "Mailhog / SMTP", subtitle: "local delivery", details: [], color: palette.green, fill: palette.white, type: "cloud" },

    { id: "kafka", x: 640, y: 1320, w: 1860, h: 165, icon: "KAFKA", title: "Kafka KRaft cluster ×3", subtitle: "RF=3 · min.insync.replicas=2 · producer outbox · consumer inbox/idempotency", details: ["auth · profiles · departments · brigades · tickets · locations · routing · dispatch", "sla · notifications · reports · assets · retry topics · *.dlq"], color: palette.orange, fill: palette.white, type: "bus", status: "HA" },

    { id: "otel", x: 90, y: 1660, w: 245, h: 125, icon: "OTEL", title: "OTel Collector", subtitle: "OTLP traces", details: ["SDK spans + infra receivers"], color: palette.cyan, fill: palette.white },
    { id: "jaeger", x: 370, y: 1660, w: 245, h: 125, icon: "TRACE", title: "Jaeger", subtitle: "distributed traces", details: ["Gateway → gRPC → DB/Kafka"], color: palette.cyan, fill: palette.white },
    { id: "prometheus", x: 650, y: 1660, w: 245, h: 125, icon: "PROM", title: "Prometheus", subtitle: "scrape + exporters", details: ["apps · K8s · PG · Kafka · Redis"], color: palette.cyan, fill: palette.white },
    { id: "grafana", x: 930, y: 1660, w: 245, h: 125, icon: "GRAF", title: "Grafana", subtitle: "metrics + logs + traces", details: ["Service & infrastructure dashboards"], color: palette.cyan, fill: palette.white },
    { id: "filebeat", x: 1210, y: 1660, w: 245, h: 125, icon: "BEAT", title: "Filebeat DaemonSet", subtitle: "container JSON logs", details: ["noise filters + ECS fields"], color: palette.cyan, fill: palette.white },
    { id: "elastic", x: 1490, y: 1660, w: 245, h: 125, icon: "ES", title: "Elasticsearch", subtitle: "central log storage", details: ["data streams + retention"], color: palette.cyan, fill: palette.white, type: "database" },
    { id: "kibana", x: 1770, y: 1660, w: 245, h: 125, icon: "KIB", title: "Kibana", subtitle: "Discover + dashboards", details: ["log.level · trace_id filters"], color: palette.cyan, fill: palette.white },
    { id: "kiali", x: 2050, y: 1660, w: 245, h: 125, icon: "KIALI", title: "Kiali", subtitle: "Istio topology", details: ["Prometheus + Jaeger links"], color: palette.cyan, fill: palette.white },
    { id: "ops", x: 2330, y: 1660, w: 180, h: 125, icon: "OPS", title: "Contracts + delivery", subtitle: "proto · CI · images", details: ["Kustomize · k6", "chaos · backup/PITR"], color: palette.cyan, fill: palette.white, type: "note" },
  ];

  const edges = [
    ["users", "ngrok", "HTTPS", "http"],
    ["ngrok", "ingress", "HTTP/2", "http"],
    ["ingress", "frontend", "web", "http"],
    ["ingress", "gateway", "api / ws", "http"],
    ["frontend", "gateway", "REST + WebSocket", "http"],
    ["trackers", "location", "telemetry", "http"],
    ["frontend", "openstreetmap", "tiles / geocode", "http"],
    ["frontend", "valhalla", "map route proxy", "http"],
    ["gateway", "grpc-fabric", "fan-out gRPC", "grpc"],
    ["grpc-fabric", "auth", "public APIs", "grpc"],
    ["grpc-fabric", "ticket", "public APIs", "grpc"],
    ["grpc-fabric", "file", "public APIs", "grpc"],
    ["auth", "profile", "create/rollback profile", "grpc"],
    ["profile", "department", "working department", "grpc"],
    ["brigade", "profile", "worker profile", "grpc"],
    ["dispatch", "ticket", "assign / reserve", "grpc"],
    ["dispatch", "brigade", "availability", "grpc"],
    ["report", "analytics", "aggregates", "grpc"],
    ["report", "file", "save PDF", "grpc"],
    ["routing", "valhalla", "route / ETA", "http"],
    ["ticket", "ticket-db", "read/write", "data"],
    ["grpc-fabric", "platform-db", "service DBs via PgBouncer", "data"],
    ["gateway", "redis-gateway", "rate limit", "data"],
    ["location", "redis-location", "positions / stream", "data"],
    ["notification", "redis-notification", "live channels", "data"],
    ["file", "minio", "objects", "data"],
    ["report", "minio", "PDF", "data"],
    ["analytics", "clickhouse", "OLAP", "data"],
    ["auth", "mailhog", "SMTP", "http"],
    ["ticket", "kafka", "outbox → tickets.events", "kafka"],
    ["location", "kafka", "Redis Stream relay", "kafka"],
    ["kafka", "sla", "tickets.events", "kafka"],
    ["kafka", "notification", "domain fan-in", "kafka"],
    ["kafka", "audit", "all events", "kafka"],
    ["kafka", "analytics", "all events", "kafka"],
    ["kafka", "routing", "tickets.events", "kafka"],
    ["kafka", "brigade", "ticket/routing/profile", "kafka"],
    ["kafka", "report", "completion request", "kafka"],
    ["report", "kafka", "result / compensation", "kafka"],
    ["grpc-fabric", "otel", "OTLP", "telemetry"],
    ["otel", "jaeger", "traces", "telemetry"],
    ["prometheus", "grafana", "PromQL", "telemetry"],
    ["filebeat", "elastic", "logs", "telemetry"],
    ["elastic", "kibana", "search", "telemetry"],
    ["elastic", "grafana", "logs", "telemetry"],
    ["prometheus", "kiali", "mesh metrics", "telemetry"],
  ].map(([source, target, label, kind]) => ({ source, target, label, kind }));

  return {
    id: "overview",
    name: "02 Детальная архитектура",
    title: "Automatic City Services · общая архитектура",
    subtitle: "Синхронный HTTP/2 + gRPC контур, событийная интеграция Kafka, service-owned data и единая наблюдаемость",
    width: 2600,
    height: 1900,
    groups,
    nodes,
    edges,
  };
}

function makeKubernetesHA() {
  const groups = [
    { id: "control-zone", title: "Kubernetes control plane", x: 40, y: 180, w: 600, h: 450, fill: palette.graySoft, stroke: "#94a3b8" },
    { id: "apps-zone", title: "automatic-system namespace · Istio mesh", x: 680, y: 180, w: 1240, h: 450, fill: palette.blueSoft, stroke: "#93c5fd" },
    { id: "postgres-zone", title: "PostgreSQL HA · sidecar.istio.io/inject=false", x: 40, y: 650, w: 1880, h: 720, fill: palette.purpleSoft, stroke: "#c4b5fd" },
    { id: "state-zone", title: "Messaging, cache and stateful engines", x: 1960, y: 650, w: 800, h: 720, fill: palette.orangeSoft, stroke: "#fdba74" },
    { id: "obs-ha-zone", title: "Observability / logging · текущее число реплик", x: 40, y: 1420, w: 2720, h: 380, fill: palette.cyanSoft, stroke: "#67e8f9" },
  ];

  const nodes = [
    { id: "public", x: 90, y: 245, w: 230, h: 105, icon: "PUBLIC", title: "Internet / local browser", subtitle: "city + api hosts", details: ["HTTPS / HTTP2"], color: palette.green, fill: palette.white, type: "cloud" },
    { id: "ngrok-dev", x: 360, y: 245, w: 230, h: 105, icon: "EDGE", title: "ngrok agent ×1", subtitle: "optional dev tunnel", details: ["No inbound node port"], color: palette.green, fill: palette.white, status: "DEV" },
    { id: "istio-ingress", x: 90, y: 390, w: 230, h: 120, icon: "INGRESS", title: "Istio IngressGateway", subtitle: "Gateway + VirtualService", details: ["replicas/HPA not pinned"], color: palette.green, fill: palette.white, type: "control", status: "RISK" },
    { id: "kube-api", x: 360, y: 390, w: 230, h: 120, icon: "K8S", title: "API Server + scheduler", subtitle: "Patroni Kubernetes DCS", details: ["role labels + Endpoints"], color: palette.muted, fill: palette.white, type: "control" },
    { id: "kube-etcd", x: 90, y: 535, w: 230, h: 75, icon: "ETCD", title: "Control-plane etcd", subtitle: "не Patroni etcd", details: [], color: palette.muted, fill: palette.white, type: "database" },
    { id: "worker-pool", x: 360, y: 535, w: 230, h: 75, icon: "NODE", title: "Worker pool ≥3", subtitle: "failure domains required", details: [], color: palette.muted, fill: palette.white, type: "control" },

    { id: "frontend-ha", x: 735, y: 245, w: 250, h: 120, icon: "WEB", title: "Frontend Deployment ×1", subtitle: "Service :3000", details: ["Current SPOF"], color: palette.blue, fill: palette.white, status: "SPOF" },
    { id: "gateway-ha", x: 1020, y: 245, w: 300, h: 120, icon: "API", title: "API Gateway ×2…6", subtitle: "HPA CPU 70% / memory 80%", details: ["PDB + topology spread"], color: palette.blue, fill: palette.white, status: "HA" },
    { id: "services-ha", x: 1355, y: 245, w: 510, h: 120, icon: "GRPC", title: "15 backend Deployments ×1", subtitle: "Auth · Ticket · Department · Brigade · Profile · Location · Routing", details: ["Dispatch · File · SLA · Notification · Audit · Analytics · Report · Asset"], color: palette.blue, fill: palette.white, status: "SPOF" },
    { id: "envoy", x: 735, y: 410, w: 360, h: 130, icon: "ENVOY", title: "Envoy sidecars", subtitle: "STRICT mTLS inside mesh", details: ["HTTP/2, trace propagation", "DestinationRule pools / retries"], color: palette.cyan, fill: palette.white, status: "HA" },
    { id: "mesh-policy", x: 1130, y: 410, w: 360, h: 130, icon: "POLICY", title: "NetworkPolicy + Istio policy", subtitle: "default deny + scoped allow", details: ["PeerAuthentication · AuthorizationPolicy"], color: palette.cyan, fill: palette.white },
    { id: "secrets", x: 1525, y: 410, w: 340, h: 130, icon: "SECRET", title: "ConfigMap / Secret / Jobs", subtitle: "runtime-secrets · JWT keys", details: ["Migration and init Jobs bypass PgBouncer"], color: palette.cyan, fill: palette.white },

    { id: "pgb-platform-write", x: 90, y: 740, w: 210, h: 130, icon: "POOL", title: "PgBouncer platform-primary ×2", subtitle: "transaction pool :6432", details: ["write route"], color: palette.purple, fill: palette.white, status: "HA" },
    { id: "pgb-platform-read", x: 330, y: 740, w: 210, h: 130, icon: "POOL", title: "PgBouncer platform-replicas ×2", subtitle: "transaction pool :6432", details: ["read route"], color: palette.purple, fill: palette.white, status: "HA" },
    { id: "pgb-ticket-write", x: 90, y: 915, w: 210, h: 130, icon: "POOL", title: "PgBouncer ticket-primary ×2", subtitle: "transaction pool :6432", details: ["coordinator leader"], color: palette.purple, fill: palette.white, status: "HA" },
    { id: "pgb-ticket-read", x: 330, y: 915, w: 210, h: 130, icon: "POOL", title: "PgBouncer ticket-replicas ×2", subtitle: "transaction pool :6432", details: ["coordinator replicas"], color: palette.purple, fill: palette.white, status: "HA" },
    { id: "migrations", x: 90, y: 1090, w: 450, h: 130, icon: "JOB", title: "Migrator / init / backup Jobs", subtitle: "Direct PostgreSQL :5432", details: ["DDL · Citus distribution · pgBackRest stanza", "Connectivity check before app rollout"], color: palette.purple, fill: palette.white },

    { id: "platform-pg", x: 600, y: 735, w: 540, h: 520, icon: "PATRONI", title: "postgres-platform StatefulSet ×3", subtitle: "1 primary + 2 streaming replicas", details: ["Required pod anti-affinity across nodes", "Separate DB/owner: auth, department, brigade, profile", "location, routing, dispatch, file, sla, notification", "audit, report, asset/PostGIS", "Patroni failover · PostgreSQL exporter", "PVC Retain · pgBackRest WAL archive"], color: palette.purple, fill: palette.white, type: "database", status: "HA" },
    { id: "ticket-citus", x: 1190, y: 735, w: 680, h: 520, icon: "CITUS", title: "postgres-ticket-citus logical cluster", subtitle: "Citus + Patroni · department_id sharding", details: ["Coordinator availability group ×3: primary + 2 replicas", "Worker group 1 ×2: primary + replica", "Worker group 2 ×2: primary + replica", "Distributed colocated tables: ticket/history/report/outbox", "Reference table: ticket categories", "Preferred anti-affinity · PostgreSQL/Citus exporter"], color: palette.purple, fill: palette.white, type: "database", status: "HA" },
    { id: "backup", x: 600, y: 1280, w: 1270, h: 55, icon: "BACKUP", title: "pgBackRest: WAL archive + differential backup → versioned MinIO postgres-backups", subtitle: "Реплика — не backup; restore/PITR drill обязателен", details: [], color: palette.red, fill: palette.redSoft, type: "note" },

    { id: "kafka-ha", x: 2010, y: 735, w: 700, h: 155, icon: "KAFKA", title: "Kafka KRaft ×3", subtitle: "3 combined broker/controller nodes", details: ["RF=3 · min ISR=2 · PVC per broker", "Leader election + consumer groups"], color: palette.orange, fill: palette.white, type: "bus", status: "HA" },
    { id: "redis-location-ha", x: 2010, y: 930, w: 330, h: 165, icon: "REDIS", title: "Redis Location", subtitle: "master + 2 replicas + Sentinel ×3", details: ["Live positions · Redis Stream", "Automatic master discovery"], color: palette.red, fill: palette.white, type: "cache", status: "HA" },
    { id: "redis-single", x: 2380, y: 930, w: 330, h: 165, icon: "REDIS", title: "Gateway + Notification Redis", subtitle: "два отдельных StatefulSet ×1", details: ["Rate limit / live notifications", "Оба контура — SPOF"], color: palette.red, fill: palette.white, type: "cache", status: "SPOF" },
    { id: "minio-ha", x: 2010, y: 1140, w: 210, h: 150, icon: "S3", title: "MinIO ×1", subtitle: "PVC Retain", details: ["files + backups"], color: palette.orange, fill: palette.white, type: "storage", status: "SPOF" },
    { id: "clickhouse-ha", x: 2255, y: 1140, w: 210, h: 150, icon: "CH", title: "ClickHouse ×1", subtitle: "analytics", details: ["PVC"], color: palette.orange, fill: palette.white, type: "database", status: "SPOF" },
    { id: "valhalla-ha", x: 2500, y: 1140, w: 210, h: 150, icon: "MAP", title: "Valhalla ×1", subtitle: "map routing", details: ["bootstrap data"], color: palette.orange, fill: palette.white, type: "cloud", status: "SPOF" },

    { id: "prom-ha", x: 90, y: 1500, w: 250, h: 130, icon: "PROM", title: "Prometheus ×1", subtitle: "scrape apps/infra", details: ["PVC / retention"], color: palette.cyan, fill: palette.white, status: "SPOF" },
    { id: "otel-ha", x: 375, y: 1500, w: 250, h: 130, icon: "OTEL", title: "OTel Collector ×1", subtitle: "OTLP traces", details: ["metrics receivers"], color: palette.cyan, fill: palette.white, status: "SPOF" },
    { id: "jaeger-ha", x: 660, y: 1500, w: 250, h: 130, icon: "TRACE", title: "Jaeger ×1", subtitle: "trace storage/UI", details: ["Current SPOF"], color: palette.cyan, fill: palette.white, status: "SPOF" },
    { id: "grafana-ha", x: 945, y: 1500, w: 250, h: 130, icon: "GRAF", title: "Grafana ×1", subtitle: "provisioned dashboards", details: ["Prometheus/ES/Jaeger"], color: palette.cyan, fill: palette.white, status: "SPOF" },
    { id: "elastic-ha", x: 1230, y: 1500, w: 250, h: 130, icon: "ES", title: "Elasticsearch ×1", subtitle: "logs data stream", details: ["Current SPOF"], color: palette.cyan, fill: palette.white, type: "database", status: "SPOF" },
    { id: "kibana-ha", x: 1515, y: 1500, w: 250, h: 130, icon: "KIB", title: "Kibana ×1", subtitle: "Discover/dashboards", details: ["Saved objects"], color: palette.cyan, fill: palette.white, status: "SPOF" },
    { id: "filebeat-ha", x: 1800, y: 1500, w: 250, h: 130, icon: "BEAT", title: "Filebeat DaemonSet", subtitle: "one pod per K8s node", details: ["Node-local log shipping"], color: palette.cyan, fill: palette.white, status: "HA" },
    { id: "kiali-ha", x: 2085, y: 1500, w: 250, h: 130, icon: "KIALI", title: "Kiali ×1 + Istiod", subtitle: "Istiod replicas unpinned", details: ["Prometheus + Jaeger links"], color: palette.cyan, fill: palette.white, status: "RISK" },
    { id: "exporters-ha", x: 2370, y: 1500, w: 340, h: 130, icon: "METRICS", title: "Exporters and agents", subtitle: "kube-state · node · etcd · PG · PgBouncer", details: ["Kafka · Redis · MinIO · ClickHouse"], color: palette.cyan, fill: palette.white, status: "MIXED" },
    { id: "ha-note", x: 90, y: 1670, w: 2620, h: 85, icon: "STATUS", title: "Фактический HA-статус", subtitle: "Database/messaging core имеет failover при наличии ≥3 failure domains; production app layer пока HA только для API Gateway. Остальные Deployments ×1, ingress без закреплённого replica policy и одиночные stateful engines требуют усиления.", details: [], color: palette.amber, fill: palette.amberSoft, type: "note" },
  ];

  const edges = [
    ["public", "ngrok-dev", "HTTPS", "http"],
    ["ngrok-dev", "istio-ingress", "tunnel", "http"],
    ["istio-ingress", "frontend-ha", "web", "http"],
    ["istio-ingress", "gateway-ha", "api", "http"],
    ["gateway-ha", "services-ha", "gRPC / HTTP2", "grpc"],
    ["envoy", "kube-api", "xDS / cert rotation", "control"],
    ["services-ha", "envoy", "sidecars", "control"],
    ["kube-api", "kube-etcd", "cluster state", "control"],
    ["kube-api", "worker-pool", "schedule", "control"],
    ["worker-pool", "envoy", "pods · CNI · CSI", "control"],
    ["kube-api", "platform-pg", "Patroni DCS", "control"],
    ["kube-api", "ticket-citus", "Patroni DCS", "control"],
    ["services-ha", "pgb-platform-write", "writes", "data"],
    ["services-ha", "pgb-platform-read", "eligible reads", "data"],
    ["services-ha", "pgb-ticket-write", "Ticket writes", "data"],
    ["services-ha", "pgb-ticket-read", "Ticket reads", "data"],
    ["pgb-platform-write", "platform-pg", "primary Service", "data"],
    ["pgb-platform-read", "platform-pg", "replica Service", "data"],
    ["pgb-ticket-write", "ticket-citus", "coordinator primary", "data"],
    ["pgb-ticket-read", "ticket-citus", "coordinator replicas", "data"],
    ["migrations", "platform-pg", "direct :5432", "data"],
    ["migrations", "ticket-citus", "DDL + distribute", "data"],
    ["platform-pg", "backup", "WAL / diff", "backup"],
    ["ticket-citus", "backup", "WAL / diff", "backup"],
    ["backup", "minio-ha", "S3", "backup"],
    ["services-ha", "kafka-ha", "outbox / consumers", "kafka"],
    ["services-ha", "redis-location-ha", "Location", "data"],
    ["services-ha", "redis-single", "Gateway / Notify", "data"],
    ["services-ha", "minio-ha", "File Service", "data"],
    ["services-ha", "clickhouse-ha", "Analytics", "data"],
    ["services-ha", "valhalla-ha", "Routing", "http"],
    ["services-ha", "otel-ha", "OTLP", "telemetry"],
    ["otel-ha", "jaeger-ha", "traces", "telemetry"],
    ["prom-ha", "grafana-ha", "metrics", "telemetry"],
    ["filebeat-ha", "elastic-ha", "logs", "telemetry"],
    ["elastic-ha", "kibana-ha", "search", "telemetry"],
    ["prom-ha", "kiali-ha", "mesh metrics", "telemetry"],
  ].map(([source, target, label, kind]) => ({ source, target, label, kind }));

  return {
    id: "kubernetes-ha",
    name: "03 Kubernetes HA",
    title: "Automatic City Services · Kubernetes HA topology",
    subtitle: "Текущая topology из prod/local-ha Kustomize: реальные replica counts, failover-контуры и отмеченные SPOF",
    width: 2800,
    height: 1850,
    groups,
    nodes,
    edges,
  };
}

function groupStyle(group) {
  const dashed = group.dashed === false ? "dashed=0;" : "dashed=1;dashPattern=8 5;";
  return `rounded=1;arcSize=12;html=1;whiteSpace=wrap;verticalAlign=top;align=left;spacingTop=12;spacingLeft=14;fontStyle=1;fontSize=16;fontColor=${group.titleColor ?? palette.ink};fillColor=${group.fill};strokeColor=${group.stroke};strokeWidth=1.5;${dashed}shadow=0;`;
}

function drawioPage(diagram) {
  const titleAlign = diagram.titleAlign ?? "left";
  const cells = [
    `<mxCell id="0"/>`,
    `<mxCell id="1" parent="0"/>`,
    `<mxCell id="title" value="&lt;div style=&quot;font-family:Inter,Segoe UI,Arial,sans-serif;text-align:${titleAlign};&quot;&gt;&lt;div style=&quot;font-size:26px;font-weight:700;color:${palette.ink};&quot;&gt;${esc(diagram.title)}&lt;/div&gt;&lt;div style=&quot;margin-top:7px;font-size:13px;color:${palette.muted};&quot;&gt;${esc(diagram.subtitle)}&lt;/div&gt;&lt;/div&gt;" style="html=1;whiteSpace=wrap;strokeColor=none;fillColor=none;align=${titleAlign};verticalAlign=middle;" vertex="1" parent="1"><mxGeometry x="40" y="35" width="${diagram.width - 80}" height="85" as="geometry"/></mxCell>`,
  ];

  if (diagram.showTopLegend !== false) {
    cells.push(`<mxCell id="legend" value="&lt;div style=&quot;font-family:Inter,Segoe UI,Arial,sans-serif;text-align:left;font-size:11px;color:${palette.muted};&quot;&gt;&lt;b style=&quot;color:${palette.green};&quot;&gt;━━ HTTPS/REST&lt;/b&gt;&amp;nbsp;&amp;nbsp;&amp;nbsp;&lt;b style=&quot;color:${palette.blue};&quot;&gt;━━ gRPC/HTTP2&lt;/b&gt;&amp;nbsp;&amp;nbsp;&amp;nbsp;&lt;b style=&quot;color:${palette.purple};&quot;&gt;┄┄ Kafka/events&lt;/b&gt;&amp;nbsp;&amp;nbsp;&amp;nbsp;&lt;b style=&quot;color:${palette.purple};&quot;&gt;━━ data&lt;/b&gt;&amp;nbsp;&amp;nbsp;&amp;nbsp;&lt;b style=&quot;color:${palette.cyan};&quot;&gt;┄┄ telemetry/control&lt;/b&gt;&amp;nbsp;&amp;nbsp;&amp;nbsp;&lt;b style=&quot;color:${palette.green};&quot;&gt;HA&lt;/b&gt; = failover contour&amp;nbsp;&amp;nbsp;&lt;b style=&quot;color:${palette.amber};&quot;&gt;SPOF&lt;/b&gt; = single instance&lt;/div&gt;" style="html=1;whiteSpace=wrap;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;" vertex="1" parent="1"><mxGeometry x="40" y="120" width="${diagram.width - 80}" height="35" as="geometry"/></mxCell>`);
  }

  for (const group of diagram.groups) {
    cells.push(`<mxCell id="${esc(group.id)}" value="${esc(group.title)}" style="${groupStyle(group)}" vertex="1" parent="1"><mxGeometry x="${group.x}" y="${group.y}" width="${group.w}" height="${group.h}" as="geometry"/></mxCell>`);
  }

  for (const edge of diagram.edges) {
    const style = edgeStyles[edge.kind] ?? edgeStyles.control;
    const dashed = style.dashed ? "dashed=1;dashPattern=7 5;" : "";
    cells.push(`<mxCell id="edge-${esc(edge.source)}-${esc(edge.target)}-${cells.length}" value="${esc(edge.label ?? "")}" style="edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=auto;html=1;strokeColor=${style.color};strokeWidth=${style.width};${dashed}endArrow=block;endFill=1;fontSize=10;fontColor=${palette.muted};labelBackgroundColor=${palette.canvas};" edge="1" parent="1" source="${esc(edge.source)}" target="${esc(edge.target)}"><mxGeometry relative="1" as="geometry"/></mxCell>`);
  }

  for (const node of diagram.nodes) {
    cells.push(`<mxCell id="${esc(node.id)}" value="${esc(htmlLabel(node))}" style="${nodeStyle(node)}" vertex="1" parent="1"><mxGeometry x="${node.x}" y="${node.y}" width="${node.w}" height="${node.h}" as="geometry"/></mxCell>`);
  }

  return `<diagram id="${esc(diagram.id)}" name="${esc(diagram.name)}"><mxGraphModel dx="1800" dy="1100" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="${diagram.width}" pageHeight="${diagram.height}" math="0" shadow="0"><root>${cells.join("")}</root></mxGraphModel></diagram>`;
}

function svgText(node) {
  const iconHref = iconDataUri(node.symbol ?? "default", node.iconColor ?? node.color ?? palette.blue);
  const iconImage = (x, y, size) => `<image href="${iconHref}" x="${x}" y="${y}" width="${size}" height="${size}"/>`;

  if (node.visual === "service") {
    const iconSize = Math.min(56, node.h * 0.38);
    const centerX = node.x + node.w / 2;
    return [
      `<polygon points="${node.x + 14},${node.y + 15} ${node.x + 29},${node.y + 15} ${node.x + 36},${node.y + 27} ${node.x + 29},${node.y + 39} ${node.x + 14},${node.y + 39} ${node.x + 7},${node.y + 27}" fill="#18a7b5"/>`,
      `<text x="${node.x + 21.5}" y="${node.y + 31}" text-anchor="middle" class="service-go">GO</text>`,
      `<text x="${centerX}" y="${node.y + 31}" text-anchor="middle" class="service-title">${esc(node.title)}</text>`,
      iconImage(centerX - iconSize / 2, node.y + 48, iconSize),
      node.subtitle
        ? `<text x="${centerX}" y="${node.y + node.h - 14}" text-anchor="middle" class="service-subtitle">${esc(node.subtitle)}</text>`
        : "",
    ].join("");
  }

  if (node.visual === "actor" || node.visual === "access" || node.visual === "technology") {
    const iconSize = node.visual === "technology" ? 62 : 68;
    const centerX = node.x + node.w / 2;
    const iconY = node.y + 22;
    const chunks = [
      iconImage(centerX - iconSize / 2, iconY, iconSize),
      `<text x="${centerX}" y="${iconY + iconSize + 27}" text-anchor="middle" class="tile-title">${esc(node.title)}</text>`,
    ];
    if (node.subtitle) {
      chunks.push(`<text x="${centerX}" y="${iconY + iconSize + 48}" text-anchor="middle" class="tile-subtitle">${esc(node.subtitle)}</text>`);
    }
    (node.details ?? []).forEach((line, index) => {
      chunks.push(`<text x="${centerX}" y="${iconY + iconSize + 68 + index * 18}" text-anchor="middle" class="tile-detail">${esc(line)}</text>`);
    });
    return chunks.join("");
  }

  if (node.visual === "observability") {
    const iconSize = 54;
    return [
      iconImage(node.x + 18, node.y + (node.h - iconSize) / 2, iconSize),
      `<text x="${node.x + 88}" y="${node.y + 42}" class="obs-title">${esc(node.title)}</text>`,
      node.subtitle ? `<text x="${node.x + 88}" y="${node.y + 65}" class="obs-subtitle">${esc(node.subtitle)}</text>` : "",
      ...(node.details ?? []).map((line, index) => `<text x="${node.x + 88}" y="${node.y + 84 + index * 17}" class="tile-detail">${esc(line)}</text>`),
    ].join("");
  }

  if (node.visual === "principle") {
    const iconSize = 42;
    return [
      iconImage(node.x + 14, node.y + (node.h - iconSize) / 2, iconSize),
      `<text x="${node.x + 68}" y="${node.y + node.h / 2 + 5}" class="principle-title">${esc(node.title)}</text>`,
    ].join("");
  }

  if (node.visual === "event-bus") {
    return [
      iconImage(node.x + 34, node.y + 24, 58),
      `<text x="${node.x + 112}" y="${node.y + 48}" class="bus-title">${esc(node.title)}</text>`,
      `<text x="${node.x + 112}" y="${node.y + 75}" class="bus-subtitle">${esc(node.subtitle ?? "")}</text>`,
      ...(node.details ?? []).map((line, index) => `<text x="${node.x + 112}" y="${node.y + 98 + index * 18}" class="tile-detail">${esc(line)}</text>`),
    ].join("");
  }

  if (node.visual === "legend") {
    const style = edgeStyles[node.edgeKind] ?? edgeStyles.control;
    const dash = style.dashed ? `stroke-dasharray="8 6"` : "";
    return [
      `<line x1="${node.x + 8}" y1="${node.y + node.h / 2}" x2="${node.x + 62}" y2="${node.y + node.h / 2}" stroke="${style.color}" stroke-width="${style.width}" ${dash} marker-end="url(#arrow-${node.edgeKind ?? "control"})"/>`,
      `<text x="${node.x + 78}" y="${node.y + node.h / 2 + 4}" class="legend-item">${esc(node.title)}</text>`,
    ].join("");
  }

  const lines = [node.title, node.subtitle, ...(node.details ?? [])].filter(Boolean);
  const x = node.x + 16;
  const startY = node.y + 54;
  const chunks = [];
  chunks.push(`<rect x="${node.x + 14}" y="${node.y + 14}" width="${Math.max(44, String(node.icon ?? "APP").length * 8 + 16)}" height="25" rx="7" fill="${node.badgeColor ?? node.color ?? palette.blue}"/>`);
  chunks.push(`<text x="${node.x + 24}" y="${node.y + 31}" class="badge">${esc(node.icon ?? "APP")}</text>`);
  if (node.status) {
    const statusColor = node.status === "HA" ? palette.green : palette.amber;
    const statusFill = node.status === "HA" ? palette.greenSoft : palette.amberSoft;
    const statusWidth = Math.max(55, String(node.status).length * 8 + 20);
    const statusX = node.x + node.w - statusWidth - 15;
    chunks.push(`<rect x="${statusX}" y="${node.y + 14}" width="${statusWidth}" height="24" rx="12" fill="${statusFill}" stroke="${statusColor}"/>`);
    chunks.push(`<text x="${statusX + statusWidth / 2}" y="${node.y + 30}" text-anchor="middle" class="status" fill="${statusColor}">${esc(node.status)}</text>`);
  }
  lines.forEach((line, index) => {
    const y = startY + index * (index === 0 ? 0 : 21);
    const className = index === 0 ? "node-title" : index === 1 ? "node-subtitle" : "node-detail";
    chunks.push(`<text x="${x}" y="${y}" class="${className}">${esc(line)}</text>`);
  });
  return chunks.join("");
}

function svgShape(node) {
  const fill = node.fill ?? palette.white;
  const stroke = node.stroke ?? node.color ?? palette.line;
  if (node.visual === "legend") {
    return `<rect x="${node.x}" y="${node.y}" width="${node.w}" height="${node.h}" fill="none" stroke="none"/>`;
  }
  if (node.type === "bus") {
    const points = `${node.x + 28},${node.y} ${node.x + node.w - 28},${node.y} ${node.x + node.w},${node.y + node.h / 2} ${node.x + node.w - 28},${node.y + node.h} ${node.x + 28},${node.y + node.h} ${node.x},${node.y + node.h / 2}`;
    return `<polygon points="${points}" fill="${fill}" stroke="${stroke}" stroke-width="2" filter="url(#shadow)"/>`;
  }
  if (node.type === "database" || node.type === "storage" || node.type === "cache") {
    return `<path d="M ${node.x} ${node.y + 14} Q ${node.x} ${node.y} ${node.x + node.w / 2} ${node.y} Q ${node.x + node.w} ${node.y} ${node.x + node.w} ${node.y + 14} L ${node.x + node.w} ${node.y + node.h - 14} Q ${node.x + node.w} ${node.y + node.h} ${node.x + node.w / 2} ${node.y + node.h} Q ${node.x} ${node.y + node.h} ${node.x} ${node.y + node.h - 14} Z" fill="${fill}" stroke="${stroke}" stroke-width="2" filter="url(#shadow)"/><ellipse cx="${node.x + node.w / 2}" cy="${node.y + 14}" rx="${node.w / 2}" ry="14" fill="none" stroke="${stroke}" stroke-width="2"/>`;
  }
  if (node.type === "note") {
    const fold = 24;
    const points = `${node.x},${node.y} ${node.x + node.w - fold},${node.y} ${node.x + node.w},${node.y + fold} ${node.x + node.w},${node.y + node.h} ${node.x},${node.y + node.h}`;
    return `<polygon points="${points}" fill="${fill}" stroke="${stroke}" stroke-width="2" filter="url(#shadow)"/><path d="M ${node.x + node.w - fold} ${node.y} L ${node.x + node.w - fold} ${node.y + fold} L ${node.x + node.w} ${node.y + fold}" fill="none" stroke="${stroke}" stroke-width="2"/>`;
  }
  if (node.type === "control") {
    const cut = Math.min(22, node.w / 8, node.h / 4);
    const points = `${node.x + cut},${node.y} ${node.x + node.w - cut},${node.y} ${node.x + node.w},${node.y + cut} ${node.x + node.w},${node.y + node.h - cut} ${node.x + node.w - cut},${node.y + node.h} ${node.x + cut},${node.y + node.h} ${node.x},${node.y + node.h - cut} ${node.x},${node.y + cut}`;
    return `<polygon points="${points}" fill="${fill}" stroke="${stroke}" stroke-width="2" filter="url(#shadow)"/>`;
  }
  return `<rect x="${node.x}" y="${node.y}" width="${node.w}" height="${node.h}" rx="18" fill="${fill}" stroke="${stroke}" stroke-width="2" filter="url(#shadow)"/>`;
}

function edgeEndpoints(source, target) {
  const sx = source.x + source.w / 2;
  const sy = source.y + source.h / 2;
  const tx = target.x + target.w / 2;
  const ty = target.y + target.h / 2;
  const horizontal = Math.abs(tx - sx) > Math.abs(ty - sy);
  if (horizontal) {
    return tx >= sx
      ? [source.x + source.w, sy, target.x, ty]
      : [source.x, sy, target.x + target.w, ty];
  }
  return ty >= sy
    ? [sx, source.y + source.h, tx, target.y]
    : [sx, source.y, tx, target.y + target.h];
}

function svgDiagram(diagram) {
  const centeredTitle = diagram.titleAlign === "center";
  const titleX = centeredTitle ? diagram.width / 2 : 40;
  const titleAnchor = centeredTitle ? "middle" : "start";
  const topLegend = diagram.showTopLegend === false
    ? ""
    : `<text x="40" y="138" class="legend" fill="${palette.green}">━━ HTTPS/REST</text>
  <text x="190" y="138" class="legend" fill="${palette.blue}">━━ gRPC/HTTP2</text>
  <text x="345" y="138" class="legend" fill="${palette.purple}">┄┄ Kafka/events</text>
  <text x="510" y="138" class="legend" fill="${palette.purple}">━━ data</text>
  <text x="605" y="138" class="legend" fill="${palette.cyan}">┄┄ telemetry/control</text>
  <text x="820" y="138" class="legend" fill="${palette.green}">HA = failover contour</text>
  <text x="1005" y="138" class="legend" fill="${palette.amber}">SPOF = single instance</text>`;
  const nodeByID = new Map(diagram.nodes.map((node) => [node.id, node]));
  const edgeSvg = diagram.edges.map((edge, index) => {
    const source = nodeByID.get(edge.source);
    const target = nodeByID.get(edge.target);
    if (!source || !target) return "";
    const [sx, sy, tx, ty] = edgeEndpoints(source, target);
    const style = edgeStyles[edge.kind] ?? edgeStyles.control;
    const midX = (sx + tx) / 2;
    const pathData = Math.abs(tx - sx) > Math.abs(ty - sy)
      ? `M ${sx} ${sy} L ${midX} ${sy} L ${midX} ${ty} L ${tx} ${ty}`
      : `M ${sx} ${sy} L ${sx} ${(sy + ty) / 2} L ${tx} ${(sy + ty) / 2} L ${tx} ${ty}`;
    const dash = style.dashed ? `stroke-dasharray="9 7"` : "";
    const labelX = Math.abs(tx - sx) > Math.abs(ty - sy) ? midX + 5 : sx + 8;
    const labelY = Math.abs(tx - sx) > Math.abs(ty - sy) ? (sy + ty) / 2 - 6 : (sy + ty) / 2 - 6;
    return `<g class="edge"><path d="${pathData}" fill="none" stroke="${style.color}" stroke-width="${style.width}" ${dash} marker-end="url(#arrow-${edge.kind})" opacity="0.78"/><text x="${labelX}" y="${labelY}" class="edge-label">${esc(edge.label ?? "")}</text></g>`;
  }).join("");

  const groups = diagram.groups.map((group) => {
    const dash = group.dashed === false ? "" : `stroke-dasharray="10 7"`;
    return `<g><rect x="${group.x}" y="${group.y}" width="${group.w}" height="${group.h}" rx="24" fill="${group.fill}" stroke="${group.stroke}" stroke-width="2" ${dash}/><text x="${group.x + 20}" y="${group.y + 34}" class="group-title" fill="${group.titleColor ?? palette.ink}">${esc(group.title)}</text></g>`;
  }).join("");
  const nodes = diagram.nodes.map((node) => `<g id="${esc(node.id)}">${svgShape(node)}${svgText(node)}</g>`).join("");
  const markers = Object.entries(edgeStyles).map(([name, style]) => `<marker id="arrow-${name}" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L9,3 z" fill="${style.color}"/></marker>`).join("");

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${diagram.width}" height="${diagram.height}" viewBox="0 0 ${diagram.width} ${diagram.height}" role="img" aria-labelledby="diagram-title diagram-desc">
  <title id="diagram-title">${esc(diagram.title)}</title>
  <desc id="diagram-desc">${esc(diagram.subtitle)}</desc>
  <defs>${markers}<filter id="shadow" x="-20%" y="-20%" width="140%" height="140%"><feDropShadow dx="0" dy="3" stdDeviation="5" flood-color="#0f172a" flood-opacity="0.09"/></filter></defs>
  <style>
    text{font-family:Inter,"Segoe UI",Arial,sans-serif;fill:${palette.ink}}
    .diagram-title{font-size:30px;font-weight:700}.diagram-subtitle{font-size:14px;fill:${palette.muted}}
    .legend{font-size:12px;fill:${palette.muted};font-weight:600}.group-title{font-size:17px;font-weight:700}
    .badge{font-size:10px;font-weight:700;fill:#fff;letter-spacing:.4px}.status{font-size:10px;font-weight:700}
    .node-title{font-size:14px;font-weight:700}.node-subtitle{font-size:11px;font-weight:600;fill:${palette.muted}}.node-detail{font-size:10.5px;fill:${palette.muted}}
    .service-go{font-size:9px;font-weight:700;fill:#fff}.service-title{font-size:14px;font-weight:700}.service-subtitle{font-size:10px;fill:${palette.muted}}
    .tile-title{font-size:15px;font-weight:700}.tile-subtitle{font-size:11px;fill:${palette.muted}}.tile-detail{font-size:10px;fill:${palette.muted}}
    .obs-title{font-size:15px;font-weight:700}.obs-subtitle{font-size:11px;fill:${palette.muted}}.principle-title{font-size:11px;font-weight:700}
    .bus-title{font-size:19px;font-weight:700}.bus-subtitle{font-size:12px;fill:${palette.muted}}
    .legend-item{font-size:11px;fill:${palette.ink}}
    .edge-label{font-size:9px;fill:${palette.muted};paint-order:stroke;stroke:${palette.canvas};stroke-width:4px;stroke-linejoin:round}.edge{pointer-events:none}
  </style>
  <rect width="100%" height="100%" fill="${palette.canvas}"/>
  <text x="${titleX}" y="64" text-anchor="${titleAnchor}" class="diagram-title">${esc(diagram.title)}</text>
  <text x="${titleX}" y="94" text-anchor="${titleAnchor}" class="diagram-subtitle">${esc(diagram.subtitle)}</text>
  ${topLegend}
  ${groups}${edgeSvg}${nodes}
</svg>`;
}

const diagrams = [makeIllustratedOverview(), makeOverview(), makeKubernetesHA()];
const mxfile = `<mxfile host="app.diagrams.net" agent="Automatic City Services architecture generator" version="24.7.17" type="device" compressed="false">${diagrams.map(drawioPage).join("")}</mxfile>`;

fs.writeFileSync(path.join(outputDir, "automatic-city-system-architecture.drawio"), mxfile, "utf8");
fs.writeFileSync(path.join(outputDir, "logical-architecture.svg"), svgDiagram(diagrams[0]), "utf8");
fs.writeFileSync(path.join(outputDir, "architecture-overview.svg"), svgDiagram(diagrams[1]), "utf8");
fs.writeFileSync(path.join(outputDir, "kubernetes-ha.svg"), svgDiagram(diagrams[2]), "utf8");

console.log(`Generated ${diagrams.length} draw.io pages and SVG previews in ${outputDir}`);
