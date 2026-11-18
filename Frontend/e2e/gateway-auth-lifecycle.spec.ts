import { expect, test } from "@playwright/test";
import { gatewayUrl } from "./support/environment";
import {
  bearer,
  createEphemeralAccount,
  deleteEphemeralAccount,
} from "./support/ephemeral-auth";
import { queryPlatformPostgres } from "./support/cluster-storage";

test.describe("Полный жизненный цикл Auth API", () => {
  test.skip(
    process.env.E2E_STORAGE_ASSERTIONS !== "1",
    "Нужен доступ kubectl к тестовому кластеру",
  );

  test("login, me, refresh, password, logout и logout-all отражаются в БД", async ({
    request,
  }) => {
    const account = await createEphemeralAccount(request, "admin");
    let currentPassword = account.password;

    try {
      const me = await request.get(`${gatewayUrl}/auth/me`, {
        headers: bearer(account.token),
      });
      expect(me.status(), await me.text()).toBe(200);
      await expect(me.json()).resolves.toMatchObject({
        user_id: account.userID,
        email: account.email,
        roles: expect.arrayContaining(["admin"]),
        is_active: true,
        email_verified: true,
      });

      expect(
        Number(
          queryPlatformPostgres(
            "auth_db",
            `SELECT count(*) FROM sessions WHERE id = '${account.sessionID}' AND revoked_at IS NULL`,
          ),
        ),
      ).toBe(1);
      expect(
        Number(
          queryPlatformPostgres(
            "auth_db",
            `SELECT count(*) FROM refresh_tokens WHERE session_id = '${account.sessionID}' AND revoked_at IS NULL`,
          ),
        ),
      ).toBe(1);

      const refreshed = await request.post(`${gatewayUrl}/auth/refresh`, {
        data: {
          refresh_token: account.refreshToken,
          client_id: "gateway-cluster-e2e",
        },
      });
      expect(refreshed.status(), await refreshed.text()).toBe(200);
      const refreshedBody = (await refreshed.json()) as {
        access_token: string;
        refresh_token: string;
        session_id: string;
      };
      expect(refreshedBody.session_id).toBe(account.sessionID);
      expect(refreshedBody.refresh_token).not.toBe(account.refreshToken);
      expect(
        Number(
          queryPlatformPostgres(
            "auth_db",
            `SELECT count(*) FROM refresh_tokens WHERE session_id = '${account.sessionID}'`,
          ),
        ),
      ).toBe(2);

      const changedPassword = `${account.password}-changed`;
      const changed = await request.post(`${gatewayUrl}/auth/change-password`, {
        headers: bearer(refreshedBody.access_token),
        data: {
          old_password: currentPassword,
          new_password: changedPassword,
          revoke_other_sessions: false,
        },
      });
      expect(changed.status(), await changed.text()).toBe(200);
      currentPassword = changedPassword;

      const oldLogin = await request.post(`${gatewayUrl}/auth/login`, {
        data: {
          email: account.email,
          password: account.password,
          client_id: "old-password-check",
        },
      });
      expect([401, 403]).toContain(oldLogin.status());
      const newLogin = await request.post(`${gatewayUrl}/auth/login`, {
        data: {
          email: account.email,
          password: currentPassword,
          client_id: "second-session",
        },
      });
      expect(newLogin.status(), await newLogin.text()).toBe(200);
      const secondSession = (await newLogin.json()) as {
        access_token: string;
        session_id: string;
      };

      const logout = await request.post(`${gatewayUrl}/auth/logout`, {
        headers: bearer(secondSession.access_token),
      });
      expect(logout.status(), await logout.text()).toBe(200);
      expect(
        Number(
          queryPlatformPostgres(
            "auth_db",
            `SELECT count(*) FROM sessions WHERE id = '${secondSession.session_id}' AND revoked_at IS NOT NULL`,
          ),
        ),
      ).toBe(1);

      const finalLogin = await request.post(`${gatewayUrl}/auth/login`, {
        data: {
          email: account.email,
          password: currentPassword,
          client_id: "logout-all-session",
        },
      });
      expect(finalLogin.status(), await finalLogin.text()).toBe(200);
      const finalSession = (await finalLogin.json()) as {
        access_token: string;
      };
      const logoutAll = await request.post(`${gatewayUrl}/auth/logout-all`, {
        headers: bearer(finalSession.access_token),
      });
      expect(logoutAll.status(), await logoutAll.text()).toBe(200);
      expect(
        Number(
          queryPlatformPostgres(
            "auth_db",
            `SELECT count(*) FROM sessions WHERE user_id = '${account.userID}' AND revoked_at IS NULL`,
          ),
        ),
      ).toBe(0);
    } finally {
      deleteEphemeralAccount(account);
    }
  });
});
