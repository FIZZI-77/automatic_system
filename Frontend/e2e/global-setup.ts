import { frontendUrl, gatewayUrl, seedDemoData, waitForUrl } from "./support/environment";

export default async function globalSetup() {
  await Promise.all([
    waitForUrl(frontendUrl),
    waitForUrl(`${gatewayUrl}/health`),
  ]);
  seedDemoData();
}
