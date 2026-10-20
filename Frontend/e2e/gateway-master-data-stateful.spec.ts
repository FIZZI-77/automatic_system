import { expect, test, type APIRequestContext } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { gatewayUrl } from "./support/environment";
import { bearer, createEphemeralAccount, deleteEphemeralAccount, type EphemeralAccount } from "./support/ephemeral-auth";
import { queryPlatformPostgres, queryTicketPostgres } from "./support/cluster-storage";

async function post(request: APIRequestContext, account: EphemeralAccount, path: string, data: unknown = {}) {
  const response = await request.post(`${gatewayUrl}${path}`, { headers: bearer(account.token), data });
  const body = await response.json().catch(() => ({}));
  return { response, body };
}

test.describe("Справочники Gateway: CRUD и хранилища", () => {
  test.skip(process.env.E2E_STORAGE_ASSERTIONS !== "1", "Нужен доступ kubectl к тестовому кластеру");
  let admin: EphemeralAccount;
  let departmentID = "";
  let categoryID = "";
  let skillID = "";
  let zoneID = "";
  const suffix = randomUUID();

  test.beforeAll(async ({ request }) => { admin = await createEphemeralAccount(request, "admin"); });
  test.afterAll(() => {
    if (zoneID) queryPlatformPostgres("location", `DELETE FROM geo_zones WHERE id='${zoneID}'`);
    if (skillID) queryPlatformPostgres("brigade_db", `DELETE FROM skills WHERE id='${skillID}'`);
    if (categoryID) queryTicketPostgres(`DELETE FROM ticket_categories WHERE id='${categoryID}'`);
    if (departmentID) queryPlatformPostgres("department_db", `DELETE FROM departments WHERE id='${departmentID}'`);
    if (admin) deleteEphemeralAccount(admin);
  });

  test("departments: create/get/list/update/delete и invalid без записи", async ({ request }) => {
    const invalidName = `x-${suffix}`;
    const invalid = await post(request, admin, "/departments/create", { name: "x", description: invalidName });
    expect(invalid.response.status()).toBe(400);
    expect(queryPlatformPostgres("department_db", `SELECT count(*) FROM departments WHERE description='${invalidName}'`)).toBe("0");

    const created = await post(request, admin, "/departments/create", { name: `E2E ${suffix}`, description: "created" });
    expect(created.response.status(), JSON.stringify(created.body)).toBe(201);
    departmentID = created.body.department.id;
    expect(queryPlatformPostgres("department_db", `SELECT name FROM departments WHERE id='${departmentID}'`)).toBe(`E2E ${suffix}`);

    expect((await post(request, admin, "/departments/get", { id: departmentID })).response.status()).toBe(200);
    expect((await post(request, admin, "/departments/list", { limit: 100, offset: 0 })).response.status()).toBe(200);
    const updated = await post(request, admin, "/departments/update", { id: departmentID, name: `E2E updated ${suffix}`, status: "inactive" });
    expect(updated.response.status(), JSON.stringify(updated.body)).toBe(200);
    expect(queryPlatformPostgres("department_db", `SELECT status FROM departments WHERE id='${departmentID}'`)).toBe("INACTIVE");
    const deleted = await post(request, admin, "/departments/delete", { id: departmentID });
    expect(deleted.response.status(), JSON.stringify(deleted.body)).toBe(200);
    expect(queryPlatformPostgres("department_db", `SELECT status FROM departments WHERE id='${departmentID}'`)).toBe("ARCHIVED");
  });

  test("ticket-categories: create/get/list/update/delete и duplicate без второй записи", async ({ request }) => {
    const code = `e2e_${suffix.replaceAll("-", "")}`;
    const created = await post(request, admin, "/ticket-categories/create", { code, name: `E2E ${suffix}`, description: "created" });
    expect(created.response.status(), JSON.stringify(created.body)).toBe(201);
    categoryID = created.body.category.id;
    expect(queryTicketPostgres(`SELECT code FROM ticket_categories WHERE id='${categoryID}'`)).toBe(code);

    const duplicate = await post(request, admin, "/ticket-categories/create", { code, name: "duplicate" });
    expect([400, 409]).toContain(duplicate.response.status());
    expect(queryTicketPostgres(`SELECT count(*) FROM ticket_categories WHERE code='${code}'`)).toBe("1");
    expect((await post(request, admin, "/ticket-categories/get", { category_id: categoryID })).response.status()).toBe(200);
    expect((await post(request, admin, "/ticket-categories/list", { limit: 100, offset: 0 })).response.status()).toBe(200);
    expect((await post(request, admin, "/ticket-categories/update", { category_id: categoryID, name: "E2E updated", is_active: true })).response.status()).toBe(200);
    expect(queryTicketPostgres(`SELECT name FROM ticket_categories WHERE id='${categoryID}'`)).toBe("E2E updated");
    expect((await post(request, admin, "/ticket-categories/delete", { category_id: categoryID })).response.status()).toBe(200);
    expect(queryTicketPostgres(`SELECT is_active FROM ticket_categories WHERE id='${categoryID}'`)).toBe("f");
  });

  test("skills: create/list/update/deactivate и duplicate без второй записи", async ({ request }) => {
    const code = `e2e_${suffix.replaceAll("-", "")}`;
    const created = await post(request, admin, "/skills/create", { code, name: `E2E ${suffix}`, description: "created" });
    expect(created.response.status(), JSON.stringify(created.body)).toBe(201);
    skillID = created.body.skill.id;
    expect(queryPlatformPostgres("brigade_db", `SELECT code FROM skills WHERE id='${skillID}'`)).toBe(code);
    const duplicate = await post(request, admin, "/skills/create", { code, name: "duplicate" });
    expect([400, 409]).toContain(duplicate.response.status());
    expect(queryPlatformPostgres("brigade_db", `SELECT count(*) FROM skills WHERE code='${code}'`)).toBe("1");
    expect((await post(request, admin, "/skills/list", { limit: 100, offset: 0 })).response.status()).toBe(200);
    expect((await post(request, admin, "/skills/update", { id: skillID, name: "E2E updated" })).response.status()).toBe(200);
    expect(queryPlatformPostgres("brigade_db", `SELECT name FROM skills WHERE id='${skillID}'`)).toBe("E2E updated");
    expect((await post(request, admin, "/skills/deactivate", { id: skillID })).response.status()).toBe(200);
    expect(queryPlatformPostgres("brigade_db", `SELECT active FROM skills WHERE id='${skillID}'`)).toBe("f");
  });

  test("geo-zones: create/list/check/update/delete и invalid без записи", async ({ request }) => {
    const name = `E2E ${suffix}`;
    const invalid = await post(request, admin, "/geo-zones/create", { department_id: "bad", name, geo_json: "{}" });
    expect(invalid.response.status()).toBe(400);
    expect(queryPlatformPostgres("location", `SELECT count(*) FROM geo_zones WHERE name='${name}'`)).toBe("0");
    const polygon = '{"type":"Polygon","coordinates":[[[37.60,55.75],[37.62,55.75],[37.62,55.77],[37.60,55.77],[37.60,55.75]]]}';
    const created = await post(request, admin, "/geo-zones/create", { department_id: "10000000-0000-4000-8000-000000000001", name, geo_json: polygon });
    expect(created.response.status(), JSON.stringify(created.body)).toBe(201);
    zoneID = created.body.zone.id;
    expect(queryPlatformPostgres("location", `SELECT name FROM geo_zones WHERE id='${zoneID}'`)).toBe(name);
    expect((await post(request, admin, "/geo-zones/list", { department_id: "10000000-0000-4000-8000-000000000001", limit: 100 })).response.status()).toBe(200);
    expect((await post(request, admin, "/geo-zones/check-point", { latitude: 55.76, longitude: 37.61, zone_ids: [zoneID] })).response.status()).toBe(200);
    expect((await post(request, admin, "/geo-zones/update", { id: zoneID, name: `${name} updated` })).response.status()).toBe(200);
    expect(queryPlatformPostgres("location", `SELECT name FROM geo_zones WHERE id='${zoneID}'`)).toBe(`${name} updated`);
    expect((await post(request, admin, "/geo-zones/delete", { id: zoneID })).response.status()).toBe(200);
    expect(queryPlatformPostgres("location", `SELECT active FROM geo_zones WHERE id='${zoneID}'`)).toBe("f");
  });
});
