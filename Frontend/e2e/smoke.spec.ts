import { expect, test } from "@playwright/test";

// Обязательные браузерные проверки без seed, SMTP и рабочего кластера.
// Межсервисные сценарии остаются в основном Playwright-наборе.
test.beforeEach(async ({ page }) => {
  // Демо не должно зависеть от доступности внешних картографических API.
  await page.route("**/api/moscow-infrastructure**", (route) =>
    route.fulfill({ json: { features: [] } }),
  );
  await page.route("**/api/valhalla-route**", (route) =>
    route.fulfill({ json: { routes: [] } }),
  );
});

test("landing hydrates and preserves theme after reload", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: /Город слышит/ }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Включить тёмную тему" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  expect(errors).toEqual([]);
});

test("registration rejects a mismatched confirmation locally", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Регистрация", exact: true }).click();
  await page.getByLabel("Имя пользователя").fill("smoke-user");
  await page.getByLabel("Почта").fill("smoke@example.local");
  await page.getByLabel("Новый пароль", { exact: true }).fill("Correct123!");
  await page.getByLabel("Повторите пароль").fill("Different123!");
  await page
    .getByRole("button", { name: "Зарегистрироваться", exact: true })
    .click();
  await expect(page.getByText("Пароли не совпадают")).toBeVisible();
});

test("demo role navigation survives module boundaries", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Открыть демо" }).click();
  await expect(
    page.getByRole("heading", { name: "Ситуационный центр" }),
  ).toBeVisible();
  await page
    .locator(".demo-bar")
    .getByRole("button", { name: "Житель" })
    .click();
  await expect(page.locator("aside nav").getByText("Мои заявки")).toBeVisible();
  await expect(
    page.locator("aside nav").getByText("Сообщить", { exact: true }),
  ).toBeVisible();
  await page
    .locator(".demo-bar")
    .getByRole("button", { name: "Администратор" })
    .click();
  await page
    .locator("aside nav")
    .getByText("Аналитика", { exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Аналитика", exact: true }),
  ).toBeVisible();
});

test("password-reset deep link keeps its token", async ({ page }) => {
  await page.goto("/reset-password?token=smoke-reset-token");
  await expect(
    page.getByRole("heading", { name: "Новый пароль", exact: true }),
  ).toBeVisible();
  await expect(page.getByLabel("Токен")).toHaveValue("smoke-reset-token");
});
