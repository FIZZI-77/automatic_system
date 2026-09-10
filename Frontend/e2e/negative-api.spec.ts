import { expect, test } from "@playwright/test";
import { apiLogin, bearer } from "./support/auth";
import { accounts, demoPassword, gatewayUrl } from "./support/environment";

test.describe("Негативные сценарии API", () => {
  test("закрытые маршруты отклоняют отсутствующий и повреждённый JWT", async ({ request }) => {
    const withoutToken = await request.post(`${gatewayUrl}/tickets/list`, {
      data: { limit: 10, offset: 0 },
    });
    expect([401, 403]).toContain(withoutToken.status());

    const malformedToken = await request.post(`${gatewayUrl}/tickets/list`, {
      headers: bearer("not-a-jwt"),
      data: { limit: 10, offset: 0 },
    });
    expect([401, 403]).toContain(malformedToken.status());
  });

  test("вход не раскрывает существование пользователя и отклоняет неверный пароль", async ({ request }) => {
    for (const email of [accounts.admin, "missing-user@city.local"]) {
      const response = await request.post(`${gatewayUrl}/auth/login`, {
        data: { email, password: `${demoPassword}-wrong`, client_id: "negative-e2e" },
      });
      expect([400, 401, 403]).toContain(response.status());
      const payload = await response.json().catch(() => ({}));
      expect(JSON.stringify(payload)).not.toMatch(/password_hash|stack|postgres|sqlstate/i);
    }
  });

  test("валидация отклоняет пустую и некорректную заявку", async ({ request }) => {
    const token = await apiLogin(request, "user");
    const empty = await request.post(`${gatewayUrl}/tickets/create`, {
      headers: bearer(token),
      data: {},
    });
    expect([400, 422]).toContain(empty.status());

    const invalidCoordinates = await request.post(`${gatewayUrl}/tickets/create`, {
      headers: bearer(token),
      data: {
        title: "Некорректные координаты",
        description: "Негативный E2E",
        address: "Москва",
        priority: "HIGH",
        latitude: 190,
        longitude: -500,
      },
    });
    expect([400, 422]).toContain(invalidCoordinates.status());
  });

  test("житель не может выполнять административные мутации", async ({ request }) => {
    const token = await apiLogin(request, "user");
    const response = await request.post(`${gatewayUrl}/departments/create`, {
      headers: bearer(token),
      data: { name: "Запрещённый E2E департамент", description: "RBAC" },
    });
    expect([401, 403]).toContain(response.status());
  });

  test("неизвестный маршрут возвращает 404 без внутренних деталей", async ({ request }) => {
    const response = await request.get(`${gatewayUrl}/definitely-missing-e2e-route`);
    expect(response.status()).toBe(404);
    const body = await response.text();
    expect(body).not.toMatch(/goroutine|stack trace|sqlstate|panic/i);
  });
});
