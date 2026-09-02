import { gatewayHealthUrl, seedDemoData, waitForUrl } from "./support/environment";

export default async function globalTeardown() {
  if (process.env.E2E_RESTORE_SEED === "0") return;
  try {
    await waitForUrl(`${gatewayHealthUrl}/health`, 5_000);
  } catch {
    return;
  }
  seedDemoData();
}
