import { expect, test, type Page, type Route } from "@playwright/test";

const departmentID = "10000000-0000-4000-8000-000000000001";
const categoryID = "20000000-0000-4000-8000-000000000001";
const userID = "40000000-0000-4000-8000-000000000001";
const assetID = "50000000-0000-4000-8000-000000000001";

async function fixtureSession(page: Page, role: "user" | "admin") {
  await page.addInitScript(({ role, userID }) => {
    sessionStorage.setItem("city-services-session", JSON.stringify({
      accessToken: "browser-regression-session",
      refreshToken: "",
      expiresAt: 0,
      user: { user_id: userID, roles: [role], email: "qa@city.local" },
    }));
  }, { role, userID });
  await page.route("**/api/moscow-infrastructure", (route) => route.fulfill({ json: { features: [] } }));
}

async function respond(route: Route, json: unknown, status = 200) {
  const headers = {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "authorization, content-type, x-idempotency-key",
  };
  if (route.request().method() === "OPTIONS") {
    await route.fulfill({ status: 204, headers });
    return;
  }
  await route.fulfill({ status, headers, json });
}

function ticket(index: number) {
  return {
    id: `60000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
    department_id: departmentID,
    category_id: categoryID,
    user_id: userID,
    title: `Тестовая заявка ${index}`,
    description: "Проверка реестра",
    status: "NEW",
    priority: "HIGH",
    address: "Москва",
    latitude: 55.755,
    longitude: 37.617,
    created_at: 1795250000 - index,
    updated_at: 1795250000 - index,
  };
}

test("поиск находит заявку со второй страницы, карточка скрывает занятые бригады и закрывается по Escape", async ({ page }) => {
  const rows = Array.from({ length: 101 }, (_, index) => ticket(index + 1));
  const brigades = [
    { id: "30000000-0000-4000-8000-000000000001", department_id: departmentID, name: "Свободная бригада", status: "AVAILABLE" },
    { id: "30000000-0000-4000-8000-000000000002", department_id: departmentID, name: "Занятая бригада", status: "BUSY" },
  ];
  await fixtureSession(page, "admin");
  await page.route("**/brigades/list", (route) => respond(route, { brigades, total: brigades.length }));
  await page.route("**/locations/current-batch", (route) => respond(route, { locations: {} }));
  await page.route("**/locations/history", (route) => respond(route, { positions: [] }));
  await page.route("**/brigade-zones/list", (route) => respond(route, { zones: [] }));
  await page.route("**/analytics/tickets/overview", (route) => respond(route, { avg_response_seconds: 0 }));
  await page.route("**/analytics/sla/summary", (route) =>
    respond(route, { breach_rate: 0, response_warnings: 0, resolution_warnings: 0 }),
  );
  await page.route("**/dispatch/preview", (route) => respond(route, { candidates: [] }));
  await page.route("**/tickets/list", (route) => {
    const offset = route.request().method() === "POST" ? route.request().postDataJSON().offset : 0;
    return respond(route, { tickets: rows.slice(offset, offset + 100), total: rows.length });
  });
  await page.route("**/tickets/get", (route) => respond(route, { ticket: rows[100] }));
  await page.goto("/");
  await page.locator("aside nav").getByText("Заявки", { exact: true }).click();
  await page.getByRole("searchbox", { name: "Поиск" }).fill(rows[100].id);
  await page.getByText(rows[100].title, { exact: true }).click();
  const card = page.getByRole("dialog");
  await expect(card.getByRole("heading", { name: rows[100].title })).toBeVisible();
  await expect(card.getByRole("option", { name: "Свободная бригада" })).toHaveCount(1);
  await expect(card.getByRole("option", { name: "Занятая бригада" })).toHaveCount(0);
  await page.keyboard.press("Escape");
  await expect(card).toHaveCount(0);
});

test("карта показывает недоступность слоёв и позволяет загрузить их повторно", async ({ page }) => {
  await fixtureSession(page, "admin");
  let calls = 0;
  await page.route("**/api/moscow-infrastructure", (route) => {
    calls += 1;
    return route.fulfill({ status: calls === 1 ? 503 : 200, json: { features: [] } });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Слои" }).click();
  const notice = page.getByText("Слои инфраструктуры временно недоступны");
  await expect(notice).toBeVisible();
  await page.getByRole("button", { name: "Обновить слои" }).click();
  await expect.poll(() => calls).toBe(2);
  await expect(notice).toHaveCount(0);
});

test("форма повторяет обращение с тем же ключом и показывает объединение", async ({ page }) => {
  await fixtureSession(page, "user");
  await page.route("**/tickets/list", (route) => respond(route, { tickets: [], total: 0 }));
  await page.route("**/departments/list", (route) => respond(route, {
    departments: [{ id: departmentID, name: "Дорожное хозяйство" }],
  }));
  await page.route("**/ticket-categories/list", (route) => respond(route, {
    categories: [{ id: categoryID, name: "Дорожное покрытие", is_active: true }],
  }));
  await page.route("**/api/geocode**", (route) => route.fulfill({
    json: { suggestions: [{ id: "address", address: "Москва, Тверская улица, 1", latitude: 55.755, longitude: 37.617 }] },
  }));
  const keys: (string | undefined)[] = [];
  const title = "Проверка объединения";
  await page.route("**/tickets/requests/create", (route) => {
    if (route.request().method() === "OPTIONS") return respond(route, {});
    keys.push(route.request().headers()["x-idempotency-key"]);
    if (keys.length === 1) return respond(route, { code: "UPSTREAM_TIMEOUT" }, 504);
    return respond(route, { request: { ...ticket(1), title, ticket_type: "REQUEST" }, duplicate_matched: true }, 201);
  });

  await page.goto("/");
  await page.locator("aside nav").getByText("Сообщить", { exact: true }).click();
  await page.getByLabel("Заголовок").fill(title);
  await page.getByLabel("Описание").fill("Один дефект уже зарегистрирован.");
  await page.getByLabel("Адрес").fill("Москва, Тверская улица");
  await page.getByRole("button", { name: "Москва, Тверская улица, 1" }).click();
  const submit = page.getByRole("button", { name: "Создать заявку" });
  await submit.click();
  await expect(page.getByRole("status")).toContainText("Сохранение заявки ещё не подтверждено");
  await expect(page.getByLabel("Заголовок")).toHaveValue(title);
  await submit.click();
  await expect(page.getByRole("status")).toContainText("добавлена к существующему инциденту");
  expect(keys[0]).toBeTruthy();
  expect(keys).toEqual([keys[0], keys[0]]);
});

test("в паспорте повреждённого объекта есть запись истории со связанной заявкой", async ({ page }) => {
  await fixtureSession(page, "admin");
  await page.route("**/assets/list", (route) => respond(route, {
    assets: [{ id: assetID, department_id: departmentID, name: "Проверочная опора", type: "STREET_LIGHT", status: 4 }],
  }));
  await page.route("**/assets/incidents/list", (route) => respond(route, {
    total: 1,
    incidents: [{
      id: "incident", description: "Повреждение опоры", ticket_id: ticket(1).id,
      occurred_at: "2026-11-21T10:00:00Z", repeated: true,
    }],
  }));
  await page.goto("/");
  await page.locator("aside nav").getByText("Инфраструктура", { exact: true }).click();
  await page.getByRole("button", { name: /Проверочная опора/ }).click();
  const passport = page.locator(".asset-detail");
  await expect(passport.getByRole("combobox")).toHaveValue("DAMAGED");
  const history = passport.getByRole("region", { name: "История инцидентов" });
  await expect(history.getByText("Повреждение опоры")).toBeVisible();
  await expect(history.getByText(`Заявка ${ticket(1).id}`)).toBeVisible();
});
