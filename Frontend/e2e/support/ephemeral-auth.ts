import { expect, type APIRequestContext } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { gatewayUrl } from "./environment";
import { queryPlatformPostgres } from "./cluster-storage";

export type EphemeralAccount = {
  email: string;
  password: string;
  role: "admin" | "dispatcher" | "worker" | "user";
  token: string;
  refreshToken: string;
  sessionID: string;
  userID: string;
};

export async function createEphemeralAccount(request: APIRequestContext, role: EphemeralAccount["role"]) {
  const suffix = randomUUID().replaceAll("-", "");
  const email = `gateway-e2e-${role}-${suffix}@city.local`;
  const password = `Gateway-E2E-${suffix}!aA7`;
  const registration = await request.post(`${gatewayUrl}/auth/register`, {
    data: { email, password, username: `e2e_${role}_${suffix.slice(0, 18)}` },
  });
  expect(registration.status(), await registration.text()).toBe(201);
  const registered = await registration.json() as { user_id: string };

  queryPlatformPostgres("auth_db", `
    UPDATE users SET email_verified = TRUE, is_active = TRUE WHERE id = '${registered.user_id}';
    INSERT INTO user_roles(user_id, role_id)
    SELECT '${registered.user_id}', id FROM roles WHERE name = '${role}'
    ON CONFLICT (user_id, role_id) DO NOTHING;
  `);

  const login = await request.post(`${gatewayUrl}/auth/login`, {
    data: { email, password, client_id: "gateway-cluster-e2e" },
  });
  expect(login.status(), await login.text()).toBe(200);
  const session = await login.json() as {
    access_token: string;
    refresh_token: string;
    session_id: string;
  };
  return {
    email,
    password,
    role,
    token: session.access_token,
    refreshToken: session.refresh_token,
    sessionID: session.session_id,
    userID: registered.user_id,
  } satisfies EphemeralAccount;
}

export function deleteEphemeralAccount(account: EphemeralAccount) {
  queryPlatformPostgres("auth_db", `DELETE FROM users WHERE id = '${account.userID}'`);
}

export function bearer(token: string) {
  return { Authorization: `Bearer ${token}` };
}
