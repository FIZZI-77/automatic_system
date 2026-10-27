import { expect, test, type APIRequestContext } from "@playwright/test";
import { readFileSync } from "node:fs";
import path from "node:path";
import { gatewayUrl, repositoryRoot } from "./support/environment";

type Operation = {
  method: string;
  path: string;
  security?: unknown[];
};

const methods = new Set(["get", "post", "put", "patch", "delete"]);
const openapiPath = path.join(repositoryRoot, "API_Gateway", "src", "core", "handlers", "openapi.json");
const document = JSON.parse(readFileSync(openapiPath, "utf8")) as {
  paths: Record<string, Record<string, { security?: unknown[] }>>;
};
const operations: Operation[] = Object.entries(document.paths).flatMap(([route, pathItem]) =>
  Object.entries(pathItem)
    .filter(([method]) => methods.has(method))
    .map(([method, operation]) => ({ method, path: route, security: operation.security })),
);
const securedOperations = operations.filter((operation) => (operation.security?.length || 0) > 0);

function requestFor(
  request: APIRequestContext,
  operation: Operation,
  authorization: string | undefined,
  sourceIndex: number,
) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Forwarded-For": `10.253.${Math.floor(sourceIndex / 250)}.${(sourceIndex % 250) + 1}`,
  };
  if (authorization) headers.Authorization = authorization;

  return request.fetch(`${gatewayUrl}${operation.path}`, {
    method: operation.method.toUpperCase(),
    headers,
    data: operation.method === "get" ? undefined : {},
  });
}

test.describe("Полный security sweep маршрутов API Gateway", () => {
  test("OpenAPI содержит ожидаемый полный набор операций", () => {
    expect(operations).toHaveLength(202);
    expect(securedOperations).toHaveLength(191);
  });

  test("каждая защищённая операция отклоняет запрос без JWT", async ({ request }) => {
    for (const [index, operation] of securedOperations.entries()) {
      const response = await requestFor(request, operation, undefined, index);
      expect(
        [401, 403],
        `${operation.method.toUpperCase()} ${operation.path}: ${response.status()} ${await response.text()}`,
      ).toContain(response.status());
    }
  });

  test("каждая защищённая операция отклоняет повреждённый JWT", async ({ request }) => {
    for (const [index, operation] of securedOperations.entries()) {
      const response = await requestFor(request, operation, "Bearer not-a-jwt", index + 500);
      expect(
        [401, 403],
        `${operation.method.toUpperCase()} ${operation.path}: ${response.status()} ${await response.text()}`,
      ).toContain(response.status());
    }
  });

  test("health, readiness и JWKS доступны и имеют ожидаемую форму", async ({ request }) => {
    for (const [route, status] of [["/health", "ok"], ["/livez", "alive"], ["/readyz", "ready"]]) {
      const response = await request.get(`${gatewayUrl}${route}`);
      expect(response.status(), route).toBe(200);
      await expect(response.json()).resolves.toMatchObject({ status });
    }

    const jwks = await request.get(`${gatewayUrl}/.well-known/jwks.json`);
    expect(jwks.status()).toBe(200);
    const payload = await jwks.json() as { keys?: Array<Record<string, unknown>> };
    expect(payload.keys?.length).toBeGreaterThan(0);
    expect(payload.keys?.[0]).toEqual(expect.objectContaining({ kty: expect.any(String), kid: expect.any(String) }));
  });

  test("публичные auth-операции отклоняют пустые или некорректные данные", async ({ request }) => {
    const cases = [
      ["/auth/register", {}],
      ["/auth/login", {}],
      ["/auth/refresh", {}],
      ["/auth/verify-email", {}],
      ["/auth/request-password-reset", { email: "not-an-email" }],
      ["/auth/reset-password", {}],
    ] as const;

    for (const [route, data] of cases) {
      const response = await request.post(`${gatewayUrl}${route}`, { data });
      expect([400, 401, 403, 422], `${route}: ${response.status()} ${await response.text()}`).toContain(response.status());
    }
  });
});
