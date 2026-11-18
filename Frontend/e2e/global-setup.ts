import {
  frontendHealthUrl,
  gatewayHealthUrl,
  seedDemoData,
  waitForUrl,
} from "./support/environment";

export default async function globalSetup() {
  const healthChecks = [waitForUrl(`${gatewayHealthUrl}/health`)];
  if (process.env.E2E_API_ONLY !== "1") {
    healthChecks.push(waitForUrl(frontendHealthUrl));
  }
  await Promise.all(healthChecks);
  seedDemoData();
}
