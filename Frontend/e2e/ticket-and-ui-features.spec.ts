import { expect, test } from "@playwright/test";
import { loginThroughUi } from "./support/auth";

async function selectTestAddress(page: import("@playwright/test").Page) {
  await page.route("**/api/geocode**", async route => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        suggestions: [{
          id: "e2e-address",
          address: "Москва, Тверская улица, 1",
          latitude: 55.757393,
          longitude: 37.613218,
        }],
      }),
    });
  });

  await page.getByLabel("Адрес").fill("Москва, Тверская улица, 1");
  await page.getByRole("button", { name: "Москва, Тверская улица, 1" }).click();
}

test.describe("Заявки и пользовательские функции", () => {
  test("житель создаёт заявку и находит её фильтром", async ({ page }) => {
    await loginThroughUi(page, "user");
    await page.locator("aside nav").getByText("Сообщить", { exact: true }).click();
    await expect(page.getByRole("heading", { name: "Сообщить о проблеме" })).toBeVisible();
    const title = `E2E: повреждение покрытия ${Date.now()}`;
    await page.getByLabel("Заголовок").fill(title);
    await page.getByLabel("Описание").fill("Проверка полного сценария создания обращения через браузер.");
    await selectTestAddress(page);
    await page.getByLabel("Приоритет").selectOption("HIGH");
    const createResponse = page.waitForResponse(response =>
      response.url().endsWith("/tickets/create") && response.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Создать заявку" }).click();
    expect((await createResponse).status()).toBe(201);
    await page.locator("aside nav").getByText("Мои заявки", { exact: true }).click();
    await page.getByRole("searchbox", { name: "Поиск", exact: true }).fill(title);
    await expect(page.getByText(title, { exact: true })).toBeVisible();
  });

  test("форма сохраняет данные и показывает понятную ошибку при недоступном Ticket Service", async ({ page }) => {
    await page.route("**/tickets/create", async route => {
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        headers: { "access-control-allow-origin": "*" },
        body: JSON.stringify({
          code: "SERVICE_UNAVAILABLE",
          error: "Сервис временно недоступен",
        }),
      });
    });
    await loginThroughUi(page, "user");
    await page.locator("aside nav").getByText("Сообщить", { exact: true }).click();

    const title = `E2E: недоступный Ticket Service ${Date.now()}`;
    await page.getByLabel("Заголовок").fill(title);
    await page.getByLabel("Описание").fill("Проверка отображения отказа без потери формы.");
    await selectTestAddress(page);
    await page.getByRole("button", { name: "Создать заявку" }).click();

    await expect(page.getByRole("status")).toContainText("Сервис временно недоступен");
    await expect(page.getByLabel("Заголовок")).toHaveValue(title);
    await expect(page.getByRole("button", { name: "Создать заявку" })).toBeEnabled();
  });

  test("фильтры заявок и карточка работают в демо", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: "Открыть демо" }).click();
    await page.locator("aside nav").getByText("Инциденты", { exact: true }).click();
    await page.locator(".ticket-filters label").filter({ hasText: /^Статус/ }).locator("select").selectOption("NEW");
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

  test("профиль жителя не запрашивает отсутствующий рабочий профиль", async ({ page }) => {
    const workProfileRequests: string[] = [];
    page.on("request", request => {
      if (request.url().includes("/work-profiles/get-by-user")) {
        workProfileRequests.push(request.url());
      }
    });

    await loginThroughUi(page, "user");
    await page.getByRole("button", { name: "Открыть профиль" }).click();
    await expect(page.getByRole("heading", { name: "Профиль", exact: true, level: 2 })).toBeVisible();
    await expect(page.getByLabel("ФИО")).toBeVisible();
    expect(workProfileRequests).toEqual([]);
  });

  test("карточка инфраструктуры закрывается по карте, а отсутствие паспорта не считается ошибкой", async ({ page }) => {
    await page.route("**/api/moscow-infrastructure", async route => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          features: [{
            id: "test-infrastructure-1",
            latitude: 55.764833,
            longitude: 37.609087,
            category: "roads",
            name: "Тестовый объект инфраструктуры",
            kind: "station",
          }],
        }),
      });
    });
    await page.route("http://localhost:8081/**", async route => {
      if (route.request().url().endsWith("/assets/nearby")) {
        await route.fulfill({
          status: 404,
          contentType: "application/json",
          headers: { "access-control-allow-origin": "*" },
          body: JSON.stringify({ code: "NOT_FOUND" }),
        });
        return;
      }

      const response = await route.fetch();
      await route.fulfill({
        response,
        headers: {
          ...response.headers(),
          "access-control-allow-origin": "*",
        },
      });
    });
    await loginThroughUi(page, "admin");

    const marker = page.locator(".infra-marker").first();
    await expect(marker).toBeVisible();
    await marker.click();

    const card = page.getByLabel("Карточка объекта инфраструктуры");
    await expect(card).toBeVisible();
    await expect(card.getByText("Паспорт для этого объекта ещё не создан.")).toBeVisible();
    await expect(card.getByText("Запрошенные данные не найдены")).toHaveCount(0);

    await page.locator(".map-root").click({ position: { x: 500, y: 350 } });
    await expect(card).toBeHidden();
  });
});
