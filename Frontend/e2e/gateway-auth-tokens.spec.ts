import { createHash, randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import { gatewayUrl } from "./support/environment";
import { createEphemeralAccount, deleteEphemeralAccount } from "./support/ephemeral-auth";
import { queryPlatformPostgres } from "./support/cluster-storage";

function tokenHash(token: string) {
  return createHash("sha256").update(token).digest("base64url");
}

function insertToken(userID: string, token: string, type: "email_verification" | "password_reset") {
  queryPlatformPostgres("auth_db", `
    INSERT INTO one_time_tokens(id, user_id, token_hash, type, expires_at)
    VALUES ('${randomUUID()}', '${userID}', '${tokenHash(token)}', '${type}', now() + interval '15 minutes')
  `);
}

test.describe("Одноразовые токены Auth API", () => {
  test.skip(process.env.E2E_STORAGE_ASSERTIONS !== "1", "Нужен доступ kubectl к тестовому кластеру");

  test("verify-email использует токен и подтверждает email", async ({ request }) => {
    const account = await createEphemeralAccount(request, "user");
    const token = `verify-${randomUUID()}`;
    try {
      queryPlatformPostgres("auth_db", `UPDATE users SET email_verified = FALSE WHERE id = '${account.userID}'`);
      insertToken(account.userID, token, "email_verification");

      const response = await request.post(`${gatewayUrl}/auth/verify-email`, { data: { token } });
      expect(response.status(), await response.text()).toBe(200);
      await expect(response.json()).resolves.toMatchObject({
        success: true,
        user_id: account.userID,
        email: account.email,
        email_verified: true,
      });
      expect(queryPlatformPostgres("auth_db", `SELECT email_verified::text FROM users WHERE id = '${account.userID}'`)).toBe("true");
      expect(Number(queryPlatformPostgres("auth_db", `SELECT count(*) FROM one_time_tokens WHERE user_id = '${account.userID}' AND type = 'email_verification' AND used_at IS NOT NULL`))).toBe(1);

      const reused = await request.post(`${gatewayUrl}/auth/verify-email`, { data: { token } });
      expect([400, 409]).toContain(reused.status());
    } finally {
      deleteEphemeralAccount(account);
    }
  });

  test("reset-password меняет пароль, отзывает сессии и использует токен", async ({ request }) => {
    const account = await createEphemeralAccount(request, "user");
    const token = `reset-${randomUUID()}`;
    const newPassword = `${account.password}-reset`;
    try {
      insertToken(account.userID, token, "password_reset");
      const response = await request.post(`${gatewayUrl}/auth/reset-password`, {
        data: { token, new_password: newPassword },
      });
      expect(response.status(), await response.text()).toBe(200);
      await expect(response.json()).resolves.toMatchObject({ success: true });
      expect(Number(queryPlatformPostgres("auth_db", `SELECT count(*) FROM one_time_tokens WHERE user_id = '${account.userID}' AND type = 'password_reset' AND used_at IS NOT NULL`))).toBe(1);
      expect(Number(queryPlatformPostgres("auth_db", `SELECT count(*) FROM sessions WHERE user_id = '${account.userID}' AND is_revoked = FALSE`))).toBe(0);

      const oldLogin = await request.post(`${gatewayUrl}/auth/login`, {
        data: { email: account.email, password: account.password, client_id: "reset-old-password" },
      });
      expect([401, 403]).toContain(oldLogin.status());
      const newLogin = await request.post(`${gatewayUrl}/auth/login`, {
        data: { email: account.email, password: newPassword, client_id: "reset-new-password" },
      });
      expect(newLogin.status(), await newLogin.text()).toBe(200);
    } finally {
      deleteEphemeralAccount(account);
    }
  });
});
