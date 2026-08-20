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
    await expectNoHorizontalOverflow(page);
  });
});
