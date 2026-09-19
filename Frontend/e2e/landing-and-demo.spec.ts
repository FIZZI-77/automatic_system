import { expect, test } from "@playwright/test";
import { expectNoHorizontalOverflow, watchPageErrors } from "./support/expectations";

test.describe("Лендинг и демонстрационный режим", () => {
  test("лендинг содержит все точки входа", async ({ page }) => {
    const assertNoPageErrors = watchPageErrors(page);
    await page.goto("/");
    await expect(page.getByRole("heading", { name: /Город слышит/ })).toBeVisible();
    await expect(page.getByRole("button", { name: "Войти", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Регистрация", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Открыть демо" })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    assertNoPageErrors();
  });

  test("регистрация проверяет повтор пароля", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Регистрация", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Создание аккаунта" })).toBeVisible();
    await page.getByLabel("Имя пользователя").fill("playwright-user");
    await page.getByLabel("Электронная почта").fill("playwright@example.local");
    await page.getByLabel("Новый пароль", { exact: true }).fill("Correct123!");
    await page.getByLabel("Повторите пароль").fill("Different123!");
    await page.getByRole("button", { name: "Зарегистрироваться", exact: true }).click();
    await expect(page.getByText("Пароли не совпадают")).toBeVisible();
  });

  test("ссылки из писем открывают формы с токеном", async ({ page }) => {
    await page.goto("/verify-email?token=verify-token-123");
    await expect(page.getByRole("heading", { name: "Подтверждение email" })).toBeVisible();
    await expect(page.getByLabel("Токен")).toHaveValue("verify-token-123");
    await expect(page).toHaveURL(/\/$/);

    await page.goto("/reset-password?token=reset-token-456");
    await expect(page.getByRole("heading", { name: "Новый пароль" })).toBeVisible();
    await expect(page.getByLabel("Токен")).toHaveValue("reset-token-456");
    await expect(page).toHaveURL(/\/$/);
  });

  test("невалидная ссылка подтверждения не считается истёкшей сессией", async ({ page }) => {
    await page.route("**/auth/verify-email", route => route.fulfill({
      status: 401,
      contentType: "application/json",
      body: JSON.stringify({ code: "UNAUTHENTICATED" }),
    }));
    await page.goto("/verify-email?token=invalid-email-token");
    await page.waitForLoadState("networkidle");
    await page.getByRole("button", { name: "Подтвердить" }).click();

    await expect(page.getByText("Токен подтверждения недействителен или истёк")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Подтверждение email" })).toBeVisible();
    await expect(page).toHaveURL(/\/$/);
  });

  test("переключение ролей меняет меню и рабочее пространство", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Открыть демо" }).click();
    await expect(page.getByText("Демонстрационный режим")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Ситуационный центр" })).toBeVisible();

    await page.locator(".demo-bar").getByRole("button", { name: "Житель" }).click();
    await expect(page.locator("aside nav").getByText("Мои заявки")).toBeVisible();
    await expect(page.locator("aside nav").getByText("Сообщить")).toBeVisible();

    await page.locator(".demo-bar").getByRole("button", { name: "Работник" }).click();
    await expect(page.locator("aside nav").getByText("Задания")).toBeVisible();
    await expect(page.locator("aside nav").getByText("Маршрут")).toBeVisible();

    await page.locator(".demo-bar").getByRole("button", { name: "Администратор" }).click();
    for (const item of ["Аналитика", "Инфраструктура", "Регламенты", "Квалификации", "Удостоверения", "Аудит", "Управление"]) {
      await expect(page.locator("aside nav").getByText(item, { exact: true })).toBeVisible();
    }
  });

  test("глобальный поиск находит заявку и раздел", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Открыть демо" }).click();
    await expect(page.getByText("Повреждён дорожный знак", { exact: true }).first()).toBeVisible();
    await page.getByRole("button", { name: "Открыть поиск" }).click();
    const dialog = page.getByRole("dialog", { name: "Поиск по системе" });
    await dialog.getByRole("searchbox").fill("дорожный знак");
    await expect(dialog.getByText("Повреждён дорожный знак")).toBeVisible();
    await dialog.getByRole("searchbox").fill("отчёты");
    await expect(dialog.getByText("Отчёты", { exact: true })).toBeVisible();
    await dialog.getByRole("button", { name: "Закрыть поиск" }).click();
    await expect(dialog).toBeHidden();
  });
});
