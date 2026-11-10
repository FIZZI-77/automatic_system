import { expect, test } from "@playwright/test";
import { mapTooltip } from "../app/map-tooltip";

test("map tooltips keep external HTML literal", async ({ page }) => {
  await page.setContent("<main></main>");
  await page.addScriptTag({
    content: `window.createMapTooltip = ${mapTooltip.toString()};`,
  });
  for (const text of [
    '<img src=x onerror="window.tooltipExecuted=true">',
    '<svg onload="window.tooltipExecuted=true"></svg>',
    "Центральная зона · приоритет 10",
  ]) {
    await page.evaluate((text) => {
      const view = window as typeof window & {
        createMapTooltip: (text: string) => HTMLElement;
      };
      document
        .querySelector("main")!
        .replaceChildren(view.createMapTooltip(text));
    }, text);
    await expect(page.locator("main")).toHaveText(text);
    await expect(page.locator("main img, main svg")).toHaveCount(0);
  }
  expect(
    await page.evaluate(
      () =>
        (window as typeof window & { tooltipExecuted?: boolean })
          .tooltipExecuted,
    ),
  ).toBeUndefined();
});
