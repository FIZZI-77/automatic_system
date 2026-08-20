import { expect, type APIRequestContext, type Page } from "@playwright/test";
import { accounts, demoPassword, gatewayUrl } from "./environment";

export type AccountRole = keyof typeof accounts;

export async function loginThroughUi(page: Page, role: AccountRole) {
  await page.goto("/");
  await page.getByRole("button", { name: "Войти", exact: true }).click();
  await page.getByLabel("Электронная почта").fill(accounts[role]);
  await page.getByLabel("Пароль", { exact: true }).fill(demoPassword);
  await page.getByRole("button", { name: "Войти", exact: true }).click();
  await expect(page.locator(".app-shell")).toBeVisible();
}

export async function apiLogin(request: APIRequestContext, role: AccountRole) {
  const response = await request.post(`${gatewayUrl}/auth/login`, {
    data: { email: accounts[role], password: demoPassword, client_id: "playwright-e2e" },
  });
  const payload = await response.json() as { access_token?: string; error?: string };
  expect(response.ok(), `login ${role}: ${response.status()} ${payload.error || ""}`).toBeTruthy();
  expect(payload.access_token).toBeTruthy();
  return payload.access_token!;
}

export function bearer(token: string) {
  return { Authorization: `Bearer ${token}` };
}
