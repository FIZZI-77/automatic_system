import { expect, test, type Locator, type Page } from "@playwright/test";

async function openDemo(page: Page, role = "Администратор") {
  await page.route("**/api/moscow-infrastructure**", route => route.fulfill({ json: { features: [] } }));
  await page.route("**/api/valhalla-route**", route => route.fulfill({ json: { encoded_polylines: [] } }));
  await page.goto("/");
  await page.getByRole("button", { name: "Открыть демо" }).click();
  await page.locator(".demo-bar").getByRole("button", { name: role, exact: true }).click();
}

async function navigate(page: Page, name: string) {
  await page.locator("aside nav").getByText(name, { exact: true }).click();
}

async function expectReadable(locator: Locator) {
  const contrast = await locator.evaluate(element => {
    const rgb = (value: string) => (value.match(/[\d.]+/g) || []).map(Number);
    const luminance = (values: number[]) => values.slice(0, 3).reduce((sum, value, i) => {
      const v = value / 255;
      return sum + (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4) * [0.2126, 0.7152, 0.0722][i];
    }, 0);
    let parent: Element | null = element;
    let background = "rgb(255, 255, 255)";
    while (parent) {
      const color = getComputedStyle(parent).backgroundColor;
      const channels = rgb(color);
      if (channels.length === 3 || channels[3] === 1) { background = color; break; }
      parent = parent.parentElement;
    }
    const a = luminance(rgb(getComputedStyle(element).color));
    const b = luminance(rgb(background));
    return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
  });
  expect(contrast).toBeGreaterThanOrEqual(4.5);
}

for (const theme of ["light", "dark"]) {
  test(`reported frontend bugs in ${theme} theme`, async ({ page }, testInfo) => {
    test.setTimeout(60_000);
    await page.addInitScript(value => localStorage.setItem("city-ui-theme-v2", value), theme);
    await openDemo(page);
    await navigate(page, "SLA");
    await expect(page.locator(".sla-table")).not.toContainText(/IN_PROGRESS|ASSIGNED|NEW/);
    await expect(page.locator(".sla-table")).toContainText("В работе");

    await navigate(page, "Аудит");
    await page.locator(".audit-row").first().hover();
    await expectReadable(page.locator(".audit-row b").first());
    await page.locator(".audit-row").first().click();
    await expectReadable(page.locator(".audit-modal h2"));
    await expectReadable(page.locator(".audit-modal dd").first());
    await page.screenshot({ path: testInfo.outputPath(`audit-${theme}.png`) });
    await page.locator(".audit-modal .detail-close").click();

    await navigate(page, "Инфраструктура");
    await page.locator(".ops-grid > button").first().click();
    for (const action of ["Изменить", "Инцидент", "Осмотр", "Ремонт", "ТО"]) {
      await page.locator(".ops-actions").getByRole("button", { name: action, exact: true }).click();
      const fields = page.locator('.ops-modal .ops-form input:not([type="checkbox"]), .ops-modal .ops-form textarea, .ops-modal .ops-form select');
      for (const field of await fields.all()) {
        await expect(field).toBeVisible();
        expect((await field.boundingBox())?.height).toBeGreaterThanOrEqual(44);
        await expect(field).toHaveCSS("border-top-style", "solid");
        await expectReadable(field);
      }
      if (action === "Осмотр") await page.screenshot({ path: testInfo.outputPath(`asset-${theme}.png`) });
      await page.locator(".ops-modal .modal-close").click();
    }

    await navigate(page, "Управление");
    await page.locator(".management-tabs").getByRole("button", { name: /Бригады/ }).click();
    await expectReadable(page.locator(".brigade-control select").first());
    await page.getByRole("button", { name: "Состав", exact: true }).first().click();
    await expectReadable(page.locator(".management-modal h2"));
    await expectReadable(page.locator(".members-list b").first());
    await page.screenshot({ path: testInfo.outputPath(`members-${theme}.png`) });
    await page.locator(".management-modal .modal-close").click();
    await page.locator(".management-tabs").getByRole("button", { name: "Интеграции" }).click();
    await expectReadable(page.locator(".integration-empty"));
    await page.screenshot({ path: testInfo.outputPath(`integrations-${theme}.png`) });

    for (const role of ["Администратор", "Работник"]) {
      await page.locator(".demo-bar").getByRole("button", { name: role, exact: true }).click();
      await navigate(page, "Уведомления");
      await expect(page.locator(".notification-list")).toBeVisible();
      await expectReadable(page.locator(".notification-list b").first());
    }
    await navigate(page, "Отчёты");
    const select = page.locator('.ticket-report-builder select[name="ticket_id"]');
    await expect(select).toBeVisible();
    expect((await select.boundingBox())?.height).toBeLessThanOrEqual(56);
    await page.screenshot({ path: testInfo.outputPath(`reports-${theme}.png`) });
    await navigate(page, "Профиль");
    await expectReadable(page.locator(".profile-summary h3"));
    await expectReadable(page.locator(".profile-summary p"));
    await expectReadable(page.getByRole("button", { name: "Подтвердить email" }));
    await expectReadable(page.locator(".profile-work dd").first());
    const security = await page.locator(".security-form").boundingBox();
    expect(security?.height).toBeLessThan(440);
    const widths = await page.locator(".security-form button").evaluateAll(buttons => buttons.map(button => button.getBoundingClientRect().width));
    expect(Math.max(...widths) - Math.min(...widths)).toBeLessThan(2);
    await page.screenshot({ path: testInfo.outputPath(`profile-${theme}.png`) });
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.locator(".security-form")).toHaveCSS("position", "static");
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
    await page.locator(".profile-summary").screenshot({ path: testInfo.outputPath(`profile-summary-mobile-${theme}.png`) });
    await page.locator(".security-form").scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath(`profile-mobile-${theme}.png`) });
  });
}

test("generated site icon is available", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator('link[rel="icon"]')).toHaveAttribute("href", "/city-logo.png");
  const response = await page.request.get("/city-logo.png");
  expect(response.ok()).toBeTruthy();
  expect(response.headers()["content-type"]).toContain("image/png");
});

for (const theme of ["light", "dark"]) {
  test(`map controls stay separate and readable in ${theme} theme`, async ({ page }, testInfo) => {
    await page.addInitScript(value => localStorage.setItem("city-ui-theme-v2", value), theme);
    await openDemo(page, "Диспетчер");
    await navigate(page, "Живая карта");
    const filters = page.locator(".map-route-filters");
    const trigger = page.locator(".layers-trigger");
    await page.getByLabel("Фильтр по заявке").selectOption({ index: 1 });
    for (const width of [1440, 1024, 390]) {
      await page.setViewportSize({ width, height: 1000 });
      await expect(filters).toBeVisible();
      const a = (await filters.boundingBox())!;
      const b = (await trigger.boundingBox())!;
      expect(a.x + a.width <= b.x || b.x + b.width <= a.x || a.y + a.height <= b.y || b.y + b.height <= a.y).toBeTruthy();
      await expectReadable(page.getByLabel("Фильтр по департаменту"));
      await trigger.click();
      await expect(trigger).toHaveAttribute("aria-expanded", "true");
      await expectReadable(page.locator(".layers-title b"));
      await expectReadable(page.locator(".layers-title span"));
      await expectReadable(page.locator(".map-shell .leaflet-control-zoom-in span"));
      const panel = (await page.locator(".layers-window").boundingBox())!;
      const map = (await page.locator(".map-shell").boundingBox())!;
      expect(panel.y + panel.height).toBeLessThanOrEqual(map.y + map.height);
      await expect(page.locator(".map-shell .leaflet-control-attribution")).toHaveCount(0);
      await page.locator(".layers-window input[type=checkbox]").first().uncheck();
      await expect(page.locator(".layers-window input[type=checkbox]").first()).not.toBeChecked();
      await page.locator(".map-card").screenshot({ path: testInfo.outputPath(`map-${theme}-${width}.png`), animations: "disabled" });
      await page.getByRole("button", { name: "Закрыть слои карты" }).click();
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    await expectReadable(page.getByLabel("Поиск машин"));
    await expectReadable(page.getByLabel("Актуальность координат"));
    await page.getByLabel("Актуальность координат").selectOption("stale");
    await page.getByLabel("Поиск машин").fill("несуществующая машина");
    await expect(page.locator(".vehicle-list .list-empty")).toBeVisible();
    await page.getByLabel("Поиск машин").clear();
    await page.getByLabel("Актуальность координат").selectOption("all");
    await expect(page.locator(".vehicle-list > button").first()).toBeVisible();
    await page.locator(".vehicle-list").screenshot({ path: testInfo.outputPath(`vehicles-${theme}.png`), animations: "disabled" });
  });

  test(`remaining form controls follow ${theme} theme`, async ({ page }, testInfo) => {
    await page.addInitScript(value => localStorage.setItem("city-ui-theme-v2", value), theme);
    await openDemo(page);
    await navigate(page, "Заявки");
    await page.locator(".work-ticket-list").getByText("Повреждение водопровода", { exact: true }).click();
    await expectReadable(page.locator(".incident-relations h3"));
    await expectReadable(page.locator(".incident-relations input").first());
    await expectReadable(page.locator(".incident-relations button").first());
    await expect(page.locator(".ticket-cancel-form input")).toHaveCSS("border-radius", "12px");
    await expect(page.locator(".ticket-cancel-form input")).toHaveCSS("padding-left", "16px");
    const spacing = await page.locator(".completion-form").evaluate(form => {
      const note = form.querySelector("p")!.getBoundingClientRect();
      const submit = form.querySelector('button[type="submit"]')!.getBoundingClientRect();
      return submit.top - note.bottom;
    });
    expect(spacing).toBeGreaterThanOrEqual(16);
    await page.locator(".incident-relations").screenshot({ path: testInfo.outputPath(`incident-${theme}.png`) });
    await page.locator(".ticket-cancel-form").screenshot({ path: testInfo.outputPath(`cancel-${theme}.png`) });
    await page.locator(".completion-form").screenshot({ path: testInfo.outputPath(`completion-${theme}.png`) });
    await page.locator(".ticket-modal .detail-close").click();
    await navigate(page, "Отчёты");
    await expect(page.locator(".report-history-head .filter-search")).toHaveCSS("background-color", "rgba(0, 0, 0, 0)");
    await page.locator(".report-history-head").screenshot({ path: testInfo.outputPath(`report-search-${theme}.png`) });
    await navigate(page, "Управление");
    await page.getByRole("button", { name: "+ Сотрудник", exact: true }).click();
    await expectReadable(page.locator(".schedule-fields label").first());
    await expectReadable(page.locator(".schedule-fields select"));
    await page.locator(".schedule-fields").screenshot({ path: testInfo.outputPath(`schedule-${theme}.png`) });
    await page.locator(".management-modal .modal-close").click();
    await navigate(page, "Зоны бригад");
    await expectReadable(page.locator(".zones-map .leaflet-control-zoom-in span"));
    await expect(page.locator(".zones-map .leaflet-control-attribution")).toHaveCount(0);
    const buttons = page.locator(".zone-actions button");
    expect(await buttons.nth(0).evaluate(el => getComputedStyle(el).backgroundColor)).toBe(await buttons.nth(1).evaluate(el => getComputedStyle(el).backgroundColor));
    await page.locator(".zones-page").screenshot({ path: testInfo.outputPath(`zones-${theme}.png`) });
    await navigate(page, "Аналитика");
    const section = page.locator(".analytics-section").filter({ has: page.getByRole("heading", { name: "Состояние аналитических проекций", exact: true }) });
    await section.locator("summary").click();
    const card = section.locator(".analytics-kpis article").first();
    await expect(card).toBeVisible();
    const outer = (await section.boundingBox())!;
    const inner = (await card.boundingBox())!;
    expect(inner.x - outer.x).toBeGreaterThanOrEqual(24);
    if (theme === "dark") await expect(card).toHaveCSS("background-image", /linear-gradient/);
    const header = (await page.locator(".analytics-page > .page-toolbar").boundingBox())!;
    const first = (await page.locator(".analytics-page > .analytics-section").first().boundingBox())!;
    expect(first.y - header.y - header.height).toBeGreaterThanOrEqual(24);
    await section.screenshot({ path: testInfo.outputPath(`analytics-${theme}.png`) });
    await page.setViewportSize({ width: 390, height: 1000 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
    await section.screenshot({ path: testInfo.outputPath(`analytics-mobile-${theme}.png`) });
  });
}
