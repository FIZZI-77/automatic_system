import { expect, test, type APIRequestContext } from "@playwright/test";
import { apiLogin, bearer } from "./support/auth";
import { gatewayUrl } from "./support/environment";

async function post(request: APIRequestContext, path: string, token: string, data: unknown = {}) {
  const response = await request.post(`${gatewayUrl}${path}`, { headers: bearer(token), data });
  const body = await response.json().catch(() => ({}));
  expect(response.status(), `${path}: ${response.status()} ${JSON.stringify(body)}`).toBeLessThan(500);
  return { response, body };
}

test.describe("Контракты API, используемые фронтендом", () => {
  test("health и профиль авторизованного пользователя", async ({ request }) => {
    const health = await request.get(`${gatewayUrl}/health`);
    await expect(health).toBeOK();
    expect(await health.json()).toMatchObject({ status: "ok" });
    const token = await apiLogin(request, "admin");
    const me = await request.get(`${gatewayUrl}/auth/me`, { headers: bearer(token) });
    await expect(me).toBeOK();
    expect(await me.json()).toMatchObject({ email: "demo.admin@city.local" });
  });

  test("административные списки отвечают и сохраняют ожидаемую форму", async ({ request }) => {
    const token = await apiLogin(request, "admin");
    const cases: Array<[string, unknown, string[]]> = [
      ["/tickets/list", { limit: 100, offset: 0 }, ["tickets"]],
      ["/departments/list", { limit: 100, offset: 0 }, ["departments"]],
      ["/brigades/list", { limit: 100, offset: 0 }, ["brigades"]],
      ["/work-profiles/list", { limit: 100, offset: 0 }, ["work_profiles", "profiles"]],
      ["/ticket-categories/list", { limit: 100, offset: 0 }, ["categories"]],
      ["/skills/list", { limit: 100, offset: 0 }, ["skills"]],
      ["/certification-types/list", { limit: 100, offset: 0 }, ["certification_types", "types"]],
      ["/sla/rules/list", { limit: 100, offset: 0 }, ["rules"]],
      ["/sla/tickets/list", { limit: 100, offset: 0 }, ["slas"]],
      ["/assets/list", { limit: 100, offset: 0 }, ["assets"]],
      ["/reports/list", { limit: 100, offset: 0 }, ["reports"]],
      ["/audit/list", { limit: 100, offset: 0 }, ["entries", "events"]],
      ["/dispatch/list", { limit: 100, offset: 0 }, ["operations", "items"]],
      ["/routing/list", { limit: 100, offset: 0 }, ["routes"]],
      ["/locations/current-batch", { brigade_ids: ["30000000-0000-4000-8000-000000000001"] }, ["positions", "locations"]],
    ];
    for (const [path, data, possibleKeys] of cases) {
      const { response, body } = await post(request, path, token, data);
      expect(response.ok(), `${path}: ${JSON.stringify(body)}`).toBeTruthy();
      expect(possibleKeys.some((key) => Object.hasOwn(body, key)), `${path}: missing ${possibleKeys.join("/")}`).toBeTruthy();
    }
  });

  test("аналитика возвращает все блоки для расширенного экрана", async ({ request }) => {
    const token = await apiLogin(request, "admin");
    const filter = {};
    for (const [path, data] of [
      ["/analytics/tickets/overview", { filter }],
      ["/analytics/sla/summary", { filter }],
      ["/analytics/tickets/daily", { filter }],
      ["/analytics/tickets/breakdown", { filter, dimension: "status", limit: 100 }],
      ["/analytics/assets/summary", { filter }],
    ] as const) {
      const { response } = await post(request, path, token, data);
      expect(response.ok(), path).toBeTruthy();
    }
  });

  test("RBAC блокирует административный аудит для жителя", async ({ request }) => {
    const token = await apiLogin(request, "user");
    const response = await request.post(`${gatewayUrl}/audit/list`, {
      headers: bearer(token), data: { limit: 10, offset: 0 },
    });
    expect([401, 403]).toContain(response.status());
    const body = await response.json();
    expect(body).toMatchObject({ code: expect.stringMatching(/UNAUTHENTICATED|PERMISSION_DENIED/) });
  });
});
