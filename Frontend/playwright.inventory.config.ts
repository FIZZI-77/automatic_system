import { defineConfig } from "@playwright/test";
import config from "./playwright.config";

// Contract inventory reads source files; it does not need Gateway, seed or teardown.
export default defineConfig({
  ...config,
  globalSetup: undefined,
  globalTeardown: undefined,
  testMatch: /gateway-(coverage|route-sweep)\.spec\.ts/,
  grep: /каждая OpenAPI|ожидаемый полный/,
  reporter: "list",
});
