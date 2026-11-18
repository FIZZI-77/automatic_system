import { expect, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { gatewayUrl } from "./support/environment";
import {
  bearer,
  createEphemeralAccount,
  deleteEphemeralAccount,
  type EphemeralAccount,
} from "./support/ephemeral-auth";
import { queryPlatformPostgres } from "./support/cluster-storage";

test.describe("Auth SMTP API", () => {
  test.skip(
    process.env.E2E_STORAGE_ASSERTIONS !== "1",
    "Нужен доступ kubectl к тестовому кластеру",
  );
  let user: EphemeralAccount;
  let profileID = "";
  test.beforeAll(async ({ request }) => {
    user = await createEphemeralAccount(request, "user");
    profileID = queryPlatformPostgres(
      "profile_db",
      `SELECT id FROM user_profiles WHERE user_id='${user.userID}'`,
    );
    queryPlatformPostgres(
      "auth_db",
      `UPDATE users SET email_verified=false WHERE id='${user.userID}'`,
    );
  });
  test.afterAll(() => {
    if (user)
      queryPlatformPostgres(
        "auth_db",
        `DELETE FROM one_time_tokens WHERE user_id='${user.userID}'`,
      );
    if (profileID)
      queryPlatformPostgres(
        "profile_db",
        `DELETE FROM outbox_events WHERE aggregate_id='${profileID}'; DELETE FROM user_profiles WHERE id='${profileID}'`,
      );
    if (user) deleteEphemeralAccount(user);
  });
  test("send-verification-email создаёт email verification token", async ({
    request,
  }) => {
    const verification = await request.post(
      `${gatewayUrl}/auth/send-verification-email`,
      { headers: bearer(user.token) },
    );
    expect(verification.status(), await verification.text()).toBe(200);
    expect(
      queryPlatformPostgres(
        "auth_db",
        `SELECT count(*) FROM one_time_tokens WHERE user_id='${user.userID}' AND type='email_verification' AND used_at IS NULL`,
      ),
    ).not.toBe("0");
  });

  test("request-password-reset создаёт password reset token", async ({
    request,
  }) => {
    const reset = await request.post(
      `${gatewayUrl}/auth/request-password-reset`,
      { data: { email: user.email } },
    );
    expect(reset.status(), await reset.text()).toBe(200);
    expect(
      queryPlatformPostgres(
        "auth_db",
        `SELECT count(*) FROM one_time_tokens WHERE user_id='${user.userID}' AND type='password_reset' AND used_at IS NULL`,
      ),
    ).not.toBe("0");
  });

  test("request-password-reset не раскрывает неизвестный email и ничего не пишет", async ({
    request,
  }) => {
    const unknown = `missing-${randomUUID()}@city.local`;
    const before = queryPlatformPostgres(
      "auth_db",
      `SELECT count(*) FROM one_time_tokens t JOIN users u ON u.id=t.user_id WHERE u.email='${unknown}'`,
    );
    const hidden = await request.post(
      `${gatewayUrl}/auth/request-password-reset`,
      { data: { email: unknown } },
    );
    expect(hidden.status()).toBe(200);
    expect(
      queryPlatformPostgres(
        "auth_db",
        `SELECT count(*) FROM one_time_tokens t JOIN users u ON u.id=t.user_id WHERE u.email='${unknown}'`,
      ),
    ).toBe(before);
  });
});
