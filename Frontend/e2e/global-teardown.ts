import { seedDemoData } from "./support/environment";

export default async function globalTeardown() {
  if (process.env.E2E_RESTORE_SEED !== "0") seedDemoData();
}
