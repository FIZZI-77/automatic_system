import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  testMatch: ["smoke.spec.ts", "map-tooltip-security.spec.ts"],
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  outputDir: "test-results/smoke",
  reporter: [
    ["list"],
    ["html", { outputFolder: "playwright-report/smoke", open: "never" }],
  ],
  use: {
    ...devices["Desktop Chrome"],
    baseURL: "http://127.0.0.1:3107",
    locale: "ru-RU",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: "npm run start -- --port 3107 --hostname 127.0.0.1",
    url: "http://127.0.0.1:3107",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
