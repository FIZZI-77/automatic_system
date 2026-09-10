import {
  frontendHealthUrl,
  gatewayHealthUrl,
  seedDemoData,
  waitForUrl,
} from "./support/environment";

export default async function globalSetup() {
  await Promise.all([
    waitForUrl(frontendHealthUrl),
    waitForUrl(`${gatewayHealthUrl}/health`),
  ]);
  seedDemoData();
}
