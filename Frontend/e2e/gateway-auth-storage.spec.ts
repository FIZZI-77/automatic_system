import { expect, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { gatewayUrl } from "./support/environment";
import { queryPlatformPostgres } from "./support/cluster-storage";

test.describe("Auth API и фактическая запись в PostgreSQL", () => {
  test.skip(
    process.env.E2E_STORAGE_ASSERTIONS !== "1",
    "Нужен доступ kubectl к тестовому кластеру",
  );

  test("регистрация создаёт пользователя, дубликат отклоняется, невалидный запрос ничего не пишет", async ({
    request,
  }) => {
    const runID = randomUUID().replaceAll("-", "");
    const email = `api-e2e-${runID}@city.local`;
    const invalidEmail = `invalid-api-e2e-${runID}`;
    const username = `api_e2e_${runID.slice(0, 20)}`;
    const password = `Api-E2E-${runID}!aA7`;

    try {
      const created = await request.post(`${gatewayUrl}/auth/register`, {
        data: { email, username, password },
      });
      expect(created.status(), await created.text()).toBe(201);
      const payload = (await created.json()) as { user_id?: string };
      expect(payload.user_id).toMatch(/^[0-9a-f-]{36}$/i);

      const stored = queryPlatformPostgres(
        "auth_db",
        `
        SELECT id::text || '|' || email || '|' || username || '|' || is_active::text
        FROM users WHERE email = '${email}'
      `,
      );
      expect(stored).toBe(`${payload.user_id}|${email}|${username}|true`);

      const duplicate = await request.post(`${gatewayUrl}/auth/register`, {
        data: { email, username: `${username}_duplicate`, password },
      });
      expect(duplicate.status()).toBe(409);
      expect(
        Number(
          queryPlatformPostgres(
            "auth_db",
            `SELECT count(*) FROM users WHERE email = '${email}'`,
          ),
        ),
      ).toBe(1);

      const invalid = await request.post(`${gatewayUrl}/auth/register`, {
        data: {
          email: invalidEmail,
          username: `${username}_invalid`,
          password,
        },
      });
      expect([400, 422]).toContain(invalid.status());
      expect(
        Number(
          queryPlatformPostgres(
            "auth_db",
            `SELECT count(*) FROM users WHERE email = '${invalidEmail}'`,
          ),
        ),
      ).toBe(0);
    } finally {
      queryPlatformPostgres(
        "auth_db",
        `DELETE FROM users WHERE email IN ('${email}', '${invalidEmail}')`,
      );
    }
  });
});
