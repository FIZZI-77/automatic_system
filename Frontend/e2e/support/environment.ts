import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

export const frontendUrl = process.env.E2E_BASE_URL || "http://127.0.0.1:3000";
export const gatewayUrl = process.env.E2E_API_URL || "http://127.0.0.1:8081";
export const frontendHealthUrl = process.env.E2E_FRONTEND_HEALTH_URL || frontendUrl;
export const gatewayHealthUrl = process.env.E2E_GATEWAY_HEALTH_URL || gatewayUrl;
export const demoPassword = process.env.E2E_DEMO_PASSWORD || "CityDemo123!";

export const accounts = {
  admin: "demo.admin@city.local",
  dispatcher: "demo.dispatcher@city.local",
  worker: "demo.worker1@city.local",
  worker2: "demo.worker2@city.local",
  user: "demo.user@city.local",
} as const;

const currentFile = fileURLToPath(import.meta.url);
export const repositoryRoot = path.resolve(path.dirname(currentFile), "..", "..", "..");

export async function waitForUrl(url: string, timeoutMs = 120_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError = "";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(5_000) });
      if (response.ok) return;
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error(`Сервис ${url} не готов за ${timeoutMs / 1000} с: ${lastError}`);
}

export function seedDemoData() {
  if (process.env.E2E_SKIP_SEED === "1") return;
  const shell = process.platform === "win32" ? "powershell.exe" : "pwsh";
  execFileSync(shell, [
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", path.join(repositoryRoot, "scripts", "seed-demo-data.ps1"),
    "-BaseUrl", gatewayUrl,
  ], { cwd: repositoryRoot, stdio: "inherit", timeout: 180_000 });
}
