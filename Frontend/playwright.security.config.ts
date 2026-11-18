import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  testMatch: "map-tooltip-security.spec.ts",
  use: { browserName: "chromium", headless: true },
  reporter: "list",
});
