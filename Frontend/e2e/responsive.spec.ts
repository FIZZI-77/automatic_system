import { expect, test } from "@playwright/test";
import { expectNoHorizontalOverflow } from "./support/expectations";

test.describe("Адаптивность", () => {
  test("лендинг и регистрация не выходят за мобильный экран", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: /Город слышит/ })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await page.getByRole("button", { name: "Регистрация", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Создание аккаунта" })).toBeVisible();
    await expectNoHorizontalOverflow(page);
  });

  test("рабочее пространство демо остаётся доступным на телефоне", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Открыть демо" }).click();
    await expect(page.getByText("Демонстрационный режим")).toBeVisible();
    await expect(page.getByRole("button", { name: "Открыть поиск" })).toBeVisible();
    await page.locator("aside nav").getByText("Инциденты", { exact: true }).click();
    await expect(page.getByRole("heading", { name: "Заявки и инциденты", level: 1 })).toBeVisible();

    await page.locator(".demo-bar").getByRole("button", { name: "Администратор" }).click();
    await expect(page.getByRole("heading", { name: "Показатели", level: 1 })).toBeVisible();
    await page.locator("aside nav").getByText("Управление", { exact: true }).click();
    await expect(page.getByRole("heading", { name: "Управление", level: 1 })).toBeVisible();
    await expectNoHorizontalOverflow(page);
  });

  test("карта и выбор объекта помещаются на мобильном экране", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.getByRole("button", { name: "Открыть демо" }).click();
    await page.getByRole("button", { name: /Не работает освещение/ }).click();

    await expect(page.locator(".layers-window")).toHaveCount(0);
    await expect(page.locator(".assigned-route")).toBeVisible();
    await expectNoHorizontalOverflow(page);

    await page.getByRole("button", { name: "Работник", exact: true }).click();
    await page.locator("aside nav").getByText("Задания", { exact: true }).click();
    await page.getByRole("button", { name: /Повреждение водопровода/ }).click();

    const dialog = page.getByRole("dialog", { name: /Заявка/ });
    await expect(dialog.getByRole("heading", { name: "Объект работ" })).toBeVisible();
    await expectNoHorizontalOverflow(page);
  });
});
