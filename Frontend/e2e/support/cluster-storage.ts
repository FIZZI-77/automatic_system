import { execFileSync } from "node:child_process";

const namespace = process.env.E2E_NAMESPACE || "automatic-system";
const kubectl = process.platform === "win32" ? "kubectl.exe" : "kubectl";

function readyPrimaryPod(selector: string) {
  const raw = execFileSync(
    kubectl,
    ["get", "pods", "-n", namespace, "-l", selector, "-o", "json"],
    {
      encoding: "utf8",
    },
  );
  const pods = JSON.parse(raw) as {
    items: Array<{
      metadata: { name: string };
      status: {
        phase: string;
        containerStatuses?: Array<{ name: string; ready: boolean }>;
      };
    }>;
  };
  const pod = pods.items.find(
    (item) =>
      item.status.phase === "Running" &&
      item.status.containerStatuses?.some(
        (container) => container.name === "postgres" && container.ready,
      ),
  );
  if (!pod) throw new Error(`Не найден Ready primary pod: ${selector}`);
  return pod.metadata.name;
}

export function queryPlatformPostgres(database: string, sql: string) {
  const pod = readyPrimaryPod("cluster-name=postgres-platform,role=primary");
  return execFileSync(
    kubectl,
    [
      "exec",
      "-n",
      namespace,
      pod,
      "-c",
      "postgres",
      "--",
      "psql",
      "-v",
      "ON_ERROR_STOP=1",
      "-U",
      "postgres",
      "-d",
      database,
      "-At",
      "-c",
      sql,
    ],
    { encoding: "utf8" },
  ).trim();
}

export function queryTicketPostgres(sql: string) {
  const pod = readyPrimaryPod(
    "cluster-name=postgres-ticket-citus,citus-group=0,role=primary",
  );
  return execFileSync(
    kubectl,
    [
      "exec",
      "-n",
      namespace,
      pod,
      "-c",
      "postgres",
      "--",
      "psql",
      "-v",
      "ON_ERROR_STOP=1",
      "-U",
      "postgres",
      "-d",
      "ticket_db",
      "-At",
      "-c",
      sql,
    ],
    { encoding: "utf8" },
  ).trim();
}

export function queryClickHouse(sql: string) {
  return execFileSync(
    kubectl,
    [
      "exec",
      "-n",
      namespace,
      "clickhouse-0",
      "--",
      "clickhouse-client",
      "--query",
      sql,
    ],
    { encoding: "utf8" },
  ).trim();
}

export function publishNotification(userID: string, payload: string) {
  return execFileSync(
    kubectl,
    [
      "exec",
      "-n",
      namespace,
      "redis-notification-0",
      "--",
      "redis-cli",
      "PUBLISH",
      `notifications:user:${userID}`,
      payload,
    ],
    { encoding: "utf8" },
  ).trim();
}
