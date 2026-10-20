import { expect, test, type APIRequestContext } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { gatewayUrl } from "./support/environment";
import { bearer, createEphemeralAccount, deleteEphemeralAccount, type EphemeralAccount } from "./support/ephemeral-auth";
import { queryPlatformPostgres, queryTicketPostgres } from "./support/cluster-storage";

const departmentID = "10000000-0000-4000-8000-000000000001";
const categoryID = "20000000-0000-4000-8000-000000000001";

async function post(request: APIRequestContext, account: EphemeralAccount | undefined, path: string, data: unknown = {}) {
  const response = await request.post(`${gatewayUrl}${path}`, { headers: account ? bearer(account.token) : undefined, data });
  const body = await response.json().catch(() => ({}));
  return { response, body };
}

test.describe("Tickets API: жизненный цикл и фактические записи", () => {
  test.skip(process.env.E2E_STORAGE_ASSERTIONS !== "1", "Нужен доступ kubectl к тестовому кластеру");
  let admin: EphemeralAccount;
  const ticketIDs: string[] = [];
  const integrationIDs: string[] = [];
  let brigadeID = "";
  const suffix = randomUUID();

  test.beforeAll(async ({ request }) => { admin = await createEphemeralAccount(request, "admin"); });
  test.afterAll(() => {
    if (ticketIDs.length) {
      const ids = ticketIDs.map((value) => `'${value}'`).join(",");
      queryTicketPostgres(`DELETE FROM ticket_report_files WHERE report_id IN (SELECT id FROM ticket_reports WHERE ticket_id IN (${ids})); DELETE FROM ticket_reports WHERE ticket_id IN (${ids}); DELETE FROM ticket_status_history WHERE ticket_id IN (${ids}); DELETE FROM outbox_events WHERE aggregate_id IN (${ids}); DELETE FROM tickets WHERE id IN (${ids});`);
    }
    if (integrationIDs.length) queryTicketPostgres(`DELETE FROM ticket_integrations WHERE id IN (${integrationIDs.map((value) => `'${value}'`).join(",")})`);
    if (brigadeID) queryPlatformPostgres("brigade_db", `DELETE FROM brigade_status_history WHERE brigade_id='${brigadeID}'; DELETE FROM brigades WHERE id='${brigadeID}'`);
    if (admin) deleteEphemeralAccount(admin);
  });

  test("create/update/assign/status/report/complete/feedback сохраняют согласованное состояние", async ({ request }) => {
    const invalidBefore = queryTicketPostgres("SELECT count(*) FROM tickets");
    const invalid = await post(request, admin, "/tickets/create", { title: "invalid" });
    expect(invalid.response.status()).toBe(400);
    expect(queryTicketPostgres("SELECT count(*) FROM tickets")).toBe(invalidBefore);

    const created = await post(request, admin, "/tickets/create", {
      department_id: departmentID, category_id: categoryID, user_id: admin.userID,
      title: `E2E ticket ${suffix}`, description: "created", priority: "HIGH", address: "Москва", latitude: 55.76, longitude: 37.61,
    });
    expect(created.response.status(), JSON.stringify(created.body)).toBe(201);
    const ticketID = created.body.ticket.id as string;
    ticketIDs.push(ticketID);
    expect(queryTicketPostgres(`SELECT title FROM tickets WHERE id='${ticketID}'`)).toBe(`E2E ticket ${suffix}`);

    const brigade = await post(request, admin, "/brigades/create", { department_id: departmentID, name: `E2E ticket brigade ${suffix}`, description: "isolated" });
    expect(brigade.response.status(), JSON.stringify(brigade.body)).toBe(201);
    brigadeID = brigade.body.brigade.id;
    expect(queryPlatformPostgres("brigade_db", `SELECT count(*) FROM brigades WHERE id='${brigadeID}'`)).toBe("1");

    expect((await post(request, admin, "/tickets/get", { ticket_id: ticketID })).response.status()).toBe(200);
    expect((await post(request, admin, "/tickets/list", { user_id: admin.userID, limit: 20, offset: 0 })).response.status()).toBe(200);
    expect((await post(request, admin, "/tickets/update", { ticket_id: ticketID, title: "E2E updated", priority: "EMERGENCY" })).response.status()).toBe(200);
    expect(queryTicketPostgres(`SELECT title||'|'||priority FROM tickets WHERE id='${ticketID}'`)).toBe("E2E updated|EMERGENCY");

    const assigned = await post(request, admin, "/tickets/assign-brigade", { ticket_id: ticketID, brigade_id: brigadeID, comment: "e2e" });
    expect(assigned.response.status(), JSON.stringify(assigned.body)).toBe(200);
    expect(queryTicketPostgres(`SELECT brigade_id::text||'|'||status FROM tickets WHERE id='${ticketID}'`)).toBe(`${brigadeID}|ASSIGNED`);
    expect((await post(request, admin, "/tickets/change-status", { ticket_id: ticketID, new_status: "in_progress", comment: "e2e" })).response.status()).toBe(200);

    const report = await post(request, admin, "/tickets/reports/create", { ticket_id: ticketID, description: "E2E work", file_ids: [] });
    expect(report.response.status(), JSON.stringify(report.body)).toBe(200);
    expect(queryTicketPostgres(`SELECT count(*) FROM ticket_reports WHERE ticket_id='${ticketID}' AND description='E2E work'`)).toBe("1");
    expect((await post(request, admin, "/tickets/reports/list", { ticket_id: ticketID })).response.status()).toBe(200);

    expect((await post(request, admin, "/tickets/complete", { ticket_id: ticketID, comment: "done" })).response.status()).toBe(200);
    expect(queryTicketPostgres(`SELECT status FROM tickets WHERE id='${ticketID}'`)).toBe("DONE");
    const feedback = await post(request, admin, "/tickets/feedback/submit", { ticket_id: ticketID, rating: 5, problem_resolved: true, comment: "ok" });
    expect(feedback.response.status(), JSON.stringify(feedback.body)).toBe(200);
    expect(queryTicketPostgres(`SELECT feedback_rating||'|'||feedback_resolved FROM tickets WHERE id='${ticketID}'`)).toBe("5|true");
    expect((await post(request, admin, "/tickets/feedback/get", { ticket_id: ticketID })).response.status()).toBe(200);
    expect((await post(request, admin, "/tickets/status-history", { ticket_id: ticketID, limit: 100, offset: 0 })).response.status()).toBe(200);
  });

  test("cancel переводит отдельную заявку в CANCELED, повторная отмена отклоняется", async ({ request }) => {
    const created = await post(request, admin, "/tickets/create", {
      department_id: departmentID, category_id: categoryID, user_id: admin.userID,
      title: `E2E cancel ${suffix}`, description: "cancel", priority: "LOW", address: "Москва", latitude: 55.76, longitude: 37.61,
    });
    expect(created.response.status(), JSON.stringify(created.body)).toBe(201);
    const ticketID = created.body.ticket.id as string;
    ticketIDs.push(ticketID);
    expect((await post(request, admin, "/tickets/cancel", { ticket_id: ticketID, reason: "e2e" })).response.status()).toBe(200);
    expect(queryTicketPostgres(`SELECT status FROM tickets WHERE id='${ticketID}'`)).toBe("CANCELED");
    expect((await post(request, admin, "/tickets/cancel", { ticket_id: ticketID, reason: "again" })).response.status()).toBe(409);
  });

  test("incident requests attach/detach/list сохраняют состав инцидента", async ({ request }) => {
    const makeRequest = async (title: string) => {
      const result = await post(request, admin, "/tickets/requests/create", {
        department_id: departmentID, category_id: categoryID, title, description: "e2e", priority: "HIGH", address: "Москва", latitude: 55.76, longitude: 37.61,
      });
      expect(result.response.status(), JSON.stringify(result.body)).toBe(201);
      ticketIDs.push(result.body.incident.id, result.body.request.id);
      return result.body as { incident: { id: string }; request: { id: string } };
    };
    const first = await makeRequest(`E2E incident A ${suffix}`);
    const second = await makeRequest(`E2E incident B ${suffix}`);
    const detachOwnIncident = await post(request, admin, "/tickets/requests/detach", { request_id: second.request.id, reason: "prepare attach" });
    expect(detachOwnIncident.response.status(), JSON.stringify(detachOwnIncident.body)).toBe(200);
    const attach = await post(request, admin, "/tickets/requests/attach", { incident_id: first.incident.id, request_id: second.request.id, reason: "e2e" });
    expect(attach.response.status(), JSON.stringify(attach.body)).toBe(200);
    expect(queryTicketPostgres(`SELECT incident_id FROM tickets WHERE id='${second.request.id}'`)).toBe(first.incident.id);
    expect((await post(request, admin, "/tickets/requests/list", { incident_id: first.incident.id, limit: 100, offset: 0 })).response.status()).toBe(200);
    expect((await post(request, admin, "/tickets/requests/detach", { request_id: second.request.id, reason: "e2e" })).response.status()).toBe(200);
    expect(queryTicketPostgres(`SELECT COALESCE(incident_id::text,'') FROM tickets WHERE id='${second.request.id}'`)).toBe("");
  });

  test("integration register + public request проверяют secret и идемпотентность записи", async ({ request }) => {
    const clientID = `e2e-${suffix}`;
    const registered = await post(request, admin, "/tickets/integrations/register", { name: "E2E", client_id: clientID, allowed_department_id: departmentID });
    expect(registered.response.status(), JSON.stringify(registered.body)).toBe(201);
    integrationIDs.push(registered.body.integration.id);
    expect(queryTicketPostgres(`SELECT client_id FROM ticket_integrations WHERE id='${registered.body.integration.id}'`)).toBe(clientID);

    const externalID = `external-${suffix}`;
    const invalidBefore = queryTicketPostgres(`SELECT count(*) FROM tickets WHERE external_id='${externalID}'`);
    const rejected = await post(request, undefined, "/integrations/tickets/requests", {
      client_id: clientID, secret: "wrong", external_id: externalID, department_id: departmentID, category_id: categoryID, user_id: admin.userID,
      title: "E2E external", description: "e2e", priority: "HIGH", address: "Москва", latitude: 55.76, longitude: 37.61,
    });
    expect([401, 403]).toContain(rejected.response.status());
    expect(queryTicketPostgres(`SELECT count(*) FROM tickets WHERE external_id='${externalID}'`)).toBe(invalidBefore);
    const accepted = await post(request, undefined, "/integrations/tickets/requests", {
      client_id: clientID, secret: registered.body.secret, external_id: externalID, department_id: departmentID, category_id: categoryID, user_id: admin.userID,
      title: "E2E external", description: "e2e", priority: "HIGH", address: "Москва", latitude: 55.76, longitude: 37.61,
    });
    expect(accepted.response.status(), JSON.stringify(accepted.body)).toBe(201);
    ticketIDs.push(accepted.body.incident.id, accepted.body.request.id);
    expect(queryTicketPostgres(`SELECT count(*) FROM tickets WHERE external_id='${externalID}'`)).toBe("1");
  });
});
