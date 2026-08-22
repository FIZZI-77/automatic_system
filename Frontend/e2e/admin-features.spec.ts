import { expect, test } from "@playwright/test";
import { loginThroughUi } from "./support/auth";

test.describe("Административные модули", () => {
  test.beforeEach(async ({ page }) => loginThroughUi(page, "admin"));

  test("управление содержит фильтры и все справочники", async ({ page }) => {
    await page.locator("aside nav").getByText("Управление", { exact: true }).click();
    await expect(page.getByRole("heading", { name: "Управление системой" })).toBeVisible();
    await expect(page.getByRole("button", { name: /Сотрудники/ })).toBeVisible();
    await expect(page.getByRole("button", { name: /Бригады/ })).toBeVisible();
    await expect(page.getByRole("button", { name: /Департаменты/ })).toBeVisible();
    await expect(page.locator(".management-filters, .service-filters").first()).toBeVisible();
    await page.getByRole("button", { name: /Бригады/ }).click();
    await expect(page.getByRole("button", { name: "+ Бригада" })).toBeVisible();
  });

  test("регламенты открываются в компактной редактируемой карточке", async ({ page }) => {
    await page.locator("aside nav").getByText("Регламенты", { exact: true }).click();
    await expect(page.getByLabel("Активность")).toBeVisible();
    const firstRule = page.locator(".catalog-list > button").first();
    await expect(firstRule).toBeVisible();
    await firstRule.click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByLabel("Название")).toBeVisible();
    await expect(dialog.getByLabel("Срок реакции, мин")).toBeVisible();
    await expect(dialog.getByLabel("Срок выполнения, мин")).toBeVisible();
    const box = await dialog.boundingBox();
    expect(box?.width || 0).toBeLessThan(900);
    await dialog.getByRole("button", { name: "×" }).click();
  });

  test("квалификации и удостоверения доступны для управления", async ({ page }) => {
    await page.locator("aside nav").getByText("Квалификации", { exact: true }).click();
    await expect(page.getByRole("heading", { name: "Навыки и допуски сотрудников" })).toBeVisible();
    await expect(page.getByRole("button", { name: /Навыки/ }).first()).toBeVisible();
    await page.getByRole("button", { name: /Сотрудники/ }).click();
    const person = page.locator(".people-qualification-list > button").first();
    await expect(person).toBeVisible();
    await person.click();
    await expect(page.getByText("Действующие навыки")).toBeVisible();
    await expect(page.getByText("Удостоверения", { exact: true })).toBeVisible();

    await page.locator("aside nav").getByText("Удостоверения", { exact: true }).click();
    await expect(page.getByRole("heading", { name: /Удостоверения и допуски/ })).toBeVisible();
    await expect(page.locator(".certification-list, .certifications-list").first()).toBeVisible();
  });

  test("SLA и аудит показывают человекочитаемые карточки", async ({ page }) => {
    await page.locator("aside nav").getByText("SLA", { exact: true }).click();
    await expect(page.getByRole("heading", { name: "Исполнение SLA" })).toBeVisible();
    await expect(page.getByText("Всего под контролем")).toBeVisible();
    const slaRow = page.locator(".sla-table > button").first();
    if (await slaRow.count()) {
      await slaRow.click();
      await expect(page.getByRole("dialog").getByText("Расчёт и история")).toBeVisible();
      await page.locator(".sla-detail-modal").click({ position: { x: 5, y: 5 } });
      await expect(page.getByRole("dialog")).toBeHidden();
    }

    await page.locator("aside nav").getByText("Аудит", { exact: true }).click();
    await expect(page.getByRole("heading", { name: "Журнал аудита" })).toBeVisible();
    const auditRow = page.locator(".audit-row").first();
    if (await auditRow.count()) {
      await auditRow.click();
      await expect(page.getByRole("dialog")).toBeVisible();
      await page.locator(".audit-modal").click({ position: { x: 5, y: 5 } });
      await expect(page.getByRole("dialog")).toBeHidden();
    }
  });

  test("аналитика выводит расширенный набор показателей", async ({ page }) => {
    await page.locator("aside nav").getByText("Аналитика", { exact: true }).click();
    for (const text of ["Обращения и SLA по дням", "Состояние SLA", "Предупреждения реакции", "Нарушения выполнения", "Городская инфраструктура"]) {
      await expect(page.getByText(text, { exact: true }).first()).toBeVisible();
    }
    await expect(page.getByRole("button", { name: "30 дней" })).toBeVisible();
  });

  test("конструктор отчётов поддерживает общий отчёт и отчёт по заявке", async ({ page }) => {
    await page.locator("aside nav").getByText("Отчёты", { exact: true }).click();
    await expect(page.getByText("Полный аналитический отчёт")).toBeVisible();
    await expect(page.getByText("Отчёт о выполнении")).toBeVisible();
    await expect(page.getByLabel("Название")).toBeVisible();
    await expect(page.getByLabel("Заявка")).toBeVisible();
    await expect(page.getByRole("button", { name: /Сформировать полный отчёт/ })).toBeVisible();
    await expect(page.getByRole("button", { name: /Сформировать отчёт по заявке/ })).toBeVisible();
  });
});
