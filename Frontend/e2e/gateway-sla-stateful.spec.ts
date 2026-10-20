import { expect, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { gatewayUrl } from "./support/environment";
import { bearer, createEphemeralAccount, deleteEphemeralAccount, type EphemeralAccount } from "./support/ephemeral-auth";
import { queryPlatformPostgres } from "./support/cluster-storage";

test.describe("SLA API: CRUD правил и PostgreSQL", () => {
  test.skip(process.env.E2E_STORAGE_ASSERTIONS !== "1", "Нужен доступ kubectl к тестовому кластеру");
  let admin: EphemeralAccount;
  let ruleID = "";
  const departmentID = randomUUID();

  test.beforeAll(async ({ request }) => { admin = await createEphemeralAccount(request, "admin"); });
  test.afterAll(() => {
    if (ruleID) queryPlatformPostgres("sla", `DELETE FROM sla_rules WHERE id='${ruleID}'`);
    if (admin) deleteEphemeralAccount(admin);
  });

  test("create/get/list/update/delete и невалидный create без записи", async ({ request }) => {
    const post = async (path: string, data: unknown) => request.post(`${gatewayUrl}${path}`, { headers: bearer(admin.token), data });
    const before = queryPlatformPostgres("sla", "SELECT count(*) FROM sla_rules");
    expect((await post("/sla/rules/create", { name: "invalid", response_time_seconds: 0, resolution_time_seconds: 0, warning_percent: 0 })).status()).toBe(400);
    expect(queryPlatformPostgres("sla", "SELECT count(*) FROM sla_rules")).toBe(before);

    const created = await post("/sla/rules/create", { name: "E2E SLA", department_id: departmentID, priority: "HIGH", response_time_seconds: 60, resolution_time_seconds: 120, warning_percent: 80 });
    expect(created.status(), await created.text()).toBe(201);
    ruleID = ((await created.json()) as { rule: { id: string } }).rule.id;
    expect(queryPlatformPostgres("sla", `SELECT name FROM sla_rules WHERE id='${ruleID}'`)).toBe("E2E SLA");
    expect((await post("/sla/rules/get", { id: ruleID })).status()).toBe(200);
    expect((await post("/sla/rules/list", { department_id: departmentID, limit: 20, offset: 0 })).status()).toBe(200);
    expect((await post("/sla/rules/update", { id: ruleID, name: "E2E SLA updated", response_time_seconds: 90, resolution_time_seconds: 180, warning_percent: 75, active: true })).status()).toBe(200);
    expect(queryPlatformPostgres("sla", `SELECT name||'|'||response_seconds FROM sla_rules WHERE id='${ruleID}'`)).toBe("E2E SLA updated|90");
    expect((await post("/sla/rules/delete", { id: ruleID })).status()).toBe(200);
    expect(queryPlatformPostgres("sla", `SELECT active FROM sla_rules WHERE id='${ruleID}'`)).toBe("f");
  });
});
