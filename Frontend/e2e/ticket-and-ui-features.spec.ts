import { expect, test } from "@playwright/test";
import { loginThroughUi } from "./support/auth";

test.describe("Заявки и пользовательские функции", () => {
  test("житель создаёт заявку и находит её фильтром", async ({ page }) => {
    await loginThroughUi(page, "user");
    await page.locator("aside nav").getByText("Сообщить", { exact: true }).click();
    await expect(page.getByRole("heading", { name: "Сообщить о проблеме" })).toBeVisible();
    const title = `E2E: повреждение покрытия ${Date.now()}`;
    await page.getByLabel("Заголовок").fill(title);
    await page.getByLabel("Описание").fill("Проверка полного сценария создания обращения через браузер.");
    await page.getByLabel("Адрес").fill("Москва, Тверская улица, 1");
    await page.getByLabel("Приоритет").selectOption("HIGH");
    await page.getByRole("button", { name: "Создать заявку" }).click();
    await expect(page.getByText(/Заявка создана/)).toBeVisible();
    await page.locator("aside nav").getByText("Мои заявки", { exact: true }).click();
    await page.getByLabel("Поиск").fill(title);
    await expect(page.getByText(title, { exact: true })).toBeVisible();
  });

  test("фильтры заявок и карточка работают в демо", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Открыть демо" }).click();
    await page.locator("aside nav").getByText("Инциденты", { exact: true }).click();
    await page.getByLabel("Статус").selectOption("NEW");
    await expect(page.getByText("Повреждён дорожный знак", { exact: true })).toBeVisible();
    await page.getByText("Повреждён дорожный знак", { exact: true }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByText(/Заявка inc-1031/i)).toBeVisible();
    await expect(dialog.getByText("Ожидает назначения")).toBeVisible();
    await page.keyboard.press("Escape");
  });

  test("профиль открывает отдельное окно смены пароля с подтверждением", async ({ page }) => {
    await loginThroughUi(page, "worker");
    await page.getByRole("button", { name: "Открыть профиль" }).click();
    await page.getByRole("button", { name: "Изменить пароль" }).click();
    const dialog = page.getByRole("dialog", { name: "Изменить пароль" });
    await expect(dialog.getByLabel("Текущий пароль")).toBeVisible();
    await expect(dialog.getByLabel("Новый пароль", { exact: true })).toBeVisible();
    await expect(dialog.getByLabel("Повторите новый пароль")).toBeVisible();
    await dialog.getByRole("button", { name: "Отмена" }).click();
    await expect(dialog).toBeHidden();
  });
});
