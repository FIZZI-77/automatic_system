import { expect, test } from "@playwright/test";
import { loginThroughUi } from "./support/auth";
import { expectNoHorizontalOverflow, watchPageErrors } from "./support/expectations";

const roleNavigation = {
  user: ["Обзор", "Мои заявки", "Сообщить", "Уведомления", "Профиль"],
  worker: ["Смена", "Задания", "Маршрут", "Отчёты", "Профиль"],
  dispatcher: ["Ситуационный центр", "Живая карта", "Инциденты", "Бригады", "SLA", "Операции", "Отчёты", "Уведомления", "Управление"],
  admin: ["Показатели", "Заявки", "Структура", "Аналитика", "SLA", "Инфраструктура", "Регламенты", "Квалификации", "Удостоверения", "Операции", "Отчёты", "Аудит", "Управление"],
} as const;

test.describe("Роли и серверная авторизация", () => {
  test("окончательно истёкшая сессия возвращает форму входа", async ({ page }) => {
    await page.addInitScript(() => {
      sessionStorage.setItem("city-services-session", JSON.stringify({
        accessToken: "expired-access-token",
        refreshToken: "expired-refresh-token",
        expiresAt: 0,
        user: {
          user_id: "expired-user",
          email: "expired@example.local",
          roles: ["admin"],
          permissions: [],
          is_active: true,
          email_verified: true,
        },
      }));
    });
    await page.route(/\/(tickets|brigades|analytics|auth)\//, route => {
      void route.fulfill({ status: 401, contentType: "application/json", body: '{"code":"UNAUTHENTICATED"}' });
    });

    await page.goto("/");

    await expect(page.getByRole("heading", { name: "Вход в систему" })).toBeVisible();
    await expect(page.locator(".app-shell")).toHaveCount(0);
  });

  test("открытые роли не подменяют друг другу список бригад", async ({ page, context }) => {
    const brigadesResponse = page.waitForResponse(response => response.url().endsWith("/brigades/list") && response.request().method() === "POST");
    await loginThroughUi(page, "dispatcher");
    const payload = await (await brigadesResponse).json() as { brigades?: Array<{ status: string }> };
    const operationalStatuses = new Set(["ACTIVE", "AVAILABLE", "BUSY", "ON_ROUTE", "ON_SITE"]);
    const dispatcherCount = String((payload.brigades || []).filter(brigade => operationalStatuses.has(brigade.status)).length);
    const brigadeKpi = page.locator(".kpis article").nth(1).locator("b");
    await expect(brigadeKpi).toHaveText(dispatcherCount);

    const adminPage = await context.newPage();
    await loginThroughUi(adminPage, "admin");
    await adminPage.locator("aside nav").getByText("Структура", { exact: true }).click();

    await page.locator("aside nav").getByText("Живая карта", { exact: true }).click();
    await page.locator("aside nav").getByText("Ситуационный центр", { exact: true }).click();
    await expect(brigadeKpi).toHaveText(dispatcherCount);
  });

  test("демонстрационная роль обновляет профиль, а выход остаётся доступен", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.getByRole("button", { name: "Открыть демо" }).click();
    await page.getByRole("button", { name: "Работник", exact: true }).click();
    await expect(page.getByRole("button", { name: "Открыть профиль" })).toContainText("Демо: Работник");
    await page.getByRole("button", { name: "Диспетчер", exact: true }).click();
    await expect(page.locator("aside").getByRole("button", { name: /Выйти/ })).toBeVisible();
  });

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
    await expect(page.getByRole("heading", { name: "Профиль", level: 2 })).toBeVisible();
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

  for (const [role, sections] of Object.entries(roleNavigation)) {
    test(`${role}: все доступные разделы открываются без ошибок`, async ({ page }) => {
      const assertNoPageErrors = watchPageErrors(page);
      const failedResponses: string[] = [];
      page.on("response", response => {
        if (response.status() >= 500 && response.url().startsWith(page.url().split("/api/")[0])) {
          failedResponses.push(`${response.status()} ${response.request().method()} ${response.url()}`);
        }
      });

      await loginThroughUi(page, role as keyof typeof roleNavigation);
      for (const section of sections) {
        await page.locator("aside nav").getByText(section, { exact: true }).click();
        await expect(page.locator("main")).toBeVisible();
        await expectNoHorizontalOverflow(page);
      }

      assertNoPageErrors();
      expect(failedResponses, `Ответы сервера с ошибкой:\n${failedResponses.join("\n")}`).toEqual([]);
    });
  }
});
