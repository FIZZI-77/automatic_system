import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import path from "node:path";
import { repositoryRoot } from "./support/environment";

type Evidence = "protocol" | "postgres" | "citus" | "redis" | "minio" | "clickhouse" | "snapshot";
type Suite = { file: string; evidence: Evidence[] };

const suites: Suite[] = [
  { file: "gateway-route-sweep.spec.ts", evidence: ["protocol"] },
  { file: "gateway-auth-storage.spec.ts", evidence: ["postgres"] },
  { file: "gateway-auth-lifecycle.spec.ts", evidence: ["postgres"] },
  { file: "gateway-auth-tokens.spec.ts", evidence: ["postgres"] },
  { file: "gateway-auth-smtp.spec.ts", evidence: ["postgres"] },
  { file: "gateway-read-surface.spec.ts", evidence: ["snapshot", "postgres", "citus", "clickhouse"] },
  { file: "gateway-assets-stateful.spec.ts", evidence: ["postgres"] },
  { file: "gateway-master-data-stateful.spec.ts", evidence: ["postgres"] },
  { file: "gateway-tickets-stateful.spec.ts", evidence: ["citus", "postgres"] },
  { file: "gateway-sla-stateful.spec.ts", evidence: ["postgres"] },
  { file: "gateway-brigades-stateful.spec.ts", evidence: ["postgres"] },
  { file: "gateway-profiles-stateful.spec.ts", evidence: ["postgres"] },
  { file: "gateway-location-routing-stateful.spec.ts", evidence: ["postgres", "redis"] },
  { file: "gateway-dispatch-stateful.spec.ts", evidence: ["postgres", "citus", "redis"] },
  { file: "gateway-files-stateful.spec.ts", evidence: ["postgres", "minio"] },
  { file: "gateway-reports-stateful.spec.ts", evidence: ["postgres", "citus", "minio", "clickhouse"] },
  { file: "gateway-notifications-stateful.spec.ts", evidence: ["postgres", "redis"] },
];

const methods = new Set(["get", "post", "put", "patch", "delete"]);
const openapi = JSON.parse(readFileSync(path.join(repositoryRoot, "API_Gateway", "src", "core", "handlers", "openapi.json"), "utf8")) as {
  paths: Record<string, Record<string, { security?: unknown[] }>>;
};
const operations = Object.entries(openapi.paths).flatMap(([route, item]) => Object.entries(item)
  .filter(([method]) => methods.has(method))
  .map(([method, operation]) => ({ method: method.toUpperCase(), path: route, secured: (operation.security?.length || 0) > 0 })));
const sources = suites.map((suite) => ({ ...suite, source: readFileSync(path.join(repositoryRoot, "Frontend", "e2e", suite.file), "utf8") }));

test("каждая OpenAPI операция имеет позитивный сценарий, негатив и storage evidence", () => {
  expect(operations).toHaveLength(202);
  const missingPositive: string[] = [];
  const missingEvidence: string[] = [];
  for (const operation of operations) {
    const matches = sources.filter((suite) => suite.source.includes(operation.path));
    if (matches.length === 0) missingPositive.push(`${operation.method} ${operation.path}`);
    if (matches.length > 0 && matches.every((suite) => suite.evidence.length === 0)) missingEvidence.push(`${operation.method} ${operation.path}`);
  }
  expect(missingPositive, `Нет позитивного сценария: ${missingPositive.join(", ")}`).toEqual([]);
  expect(missingEvidence, `Нет storage evidence: ${missingEvidence.join(", ")}`).toEqual([]);
  expect(operations.filter((operation) => operation.secured)).toHaveLength(191);
  expect(operations.filter((operation) => !operation.secured)).toHaveLength(11);
});
