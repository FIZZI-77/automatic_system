import { expect, test } from "@playwright/test";
import { loginThroughUi } from "./support/auth";

test.describe("Роли и серверная авторизация", () => {
  test("житель видит только пользовательские разделы", async ({ page }) => {
    await loginThroughUi(page, "user");
    await expect(page.getByText("Житель · Москва")).toBeVisible();
    await expect(page.locator("aside nav").getByText("Мои заявки")).toBeVisible();
    await expect(page.locator("aside nav").getByText("Управление", { exact: true })).toHaveCount(0);
  });

  test("рабочий видит задания, маршрут и свой профиль", async ({ page }) => {
    await loginThroughUi(page, "worker");
    await expect(page.getByText("Работник · Москва")).toBeVisible();
    await page.locator("aside nav").getByText("Задания").click();
    await expect(page.getByRole("heading", { name: "Работа с заявками" })).toBeVisible();
    await page.getByRole("button", { name: "Открыть профиль" }).click();
    await expect(page.getByRole("heading", { name: "Профиль" })).toBeVisible();
    await expect(page.getByText("Департамент", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Изменить пароль" })).toBeVisible();
  });

  test("диспетчер не получает административные справочники", async ({ page }) => {
    await loginThroughUi(page, "dispatcher");
    await expect(page.getByText("Диспетчер · Москва")).toBeVisible();
    for (const item of ["Инциденты", "Бригады", "SLA", "Операции", "Отчёты"]) {
      await expect(page.locator("aside nav").getByText(item, { exact: true })).toBeVisible();
    }
    await expect(page.locator("aside nav").getByText("Регламенты", { exact: true })).toHaveCount(0);
    await expect(page.locator("aside nav").getByText("Аудит", { exact: true })).toHaveCount(0);
  });

  test("администратор открывает основные модули", async ({ page }) => {
    await loginThroughUi(page, "admin");
    const modules: Array<[string, RegExp]> = [
      ["Аналитика", /Динамика обращений/],
      ["Инфраструктура", /Реестр городской инфраструктуры|Городская инфраструктура/],
      ["Регламенты", /Регламенты и категории/],
      ["Квалификации", /Навыки и допуски сотрудников/],
      ["Удостоверения", /Удостоверения и допуски/],
      ["Операции", /Маршруты, назначения и доставка/],
      ["Отчёты", /^Отчёты$/],
      ["Аудит", /Журнал аудита/],
      ["Управление", /Управление системой/],
    ];
    for (const [nav, heading] of modules) {
      await page.locator("aside nav").getByText(nav, { exact: true }).click();
      await expect(page.getByRole("heading", { name: heading }).first()).toBeVisible();
    }
  });
});
