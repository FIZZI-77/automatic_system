import { expect, test, type APIRequestContext } from "@playwright/test";
import { gatewayUrl } from "./support/environment";
import { bearer, createEphemeralAccount, deleteEphemeralAccount, type EphemeralAccount } from "./support/ephemeral-auth";
import { queryPlatformPostgres, queryTicketPostgres } from "./support/cluster-storage";

const id = {
  department: "10000000-0000-4000-8000-000000000001",
  category: "20000000-0000-4000-8000-000000000001",
  brigade: "30000000-0000-4000-8000-000000000001",
  skill: "40000000-0000-4000-8000-000000000001",
  userProfile: "50000000-0000-4000-8000-000000000001",
  workProfile: "51000000-0000-4000-8000-000000000001",
  ticket: "60000000-0000-4000-8000-000000000003",
  ticketDone: "60000000-0000-4000-8000-000000000004",
  route: "70000000-0000-4000-8000-000000000001",
  report: "c0000000-0000-4000-8000-000000000001",
  asset: "d0000000-0000-4000-8000-000000000001",
} as const;

type ReadCase = { path: string; body?: Record<string, unknown>; expected?: number[] };

const cases: ReadCase[] = [
  { path: "/analytics/tickets/overview", body: { filter: {} } },
  { path: "/analytics/sla/summary", body: { filter: {} } },
  { path: "/analytics/tickets/daily", body: { filter: {} } },
  { path: "/analytics/tickets/breakdown", body: { filter: {}, dimension: "status", limit: 20 } },
  { path: "/analytics/assets/summary", body: { filter: {} } },
  { path: "/analytics/dispatch/failures", body: { filter: {} } },
  { path: "/analytics/brigades/workload", body: { filter: {} } },
  { path: "/analytics/workers/active", body: { filter: {} } },
  { path: "/analytics/dispatch/funnel", body: { filter: {} } },
  { path: "/analytics/dispatch/effectiveness", body: { filter: {} } },
  { path: "/analytics/operations/insights", body: { filter: {} } },
  { path: "/analytics/operations/latency", body: { filter: {}, group_by: "department" } },
  { path: "/analytics/projections/health" },
  { path: "/analytics/dispatch/operations", body: { filter: {} } },
  { path: "/analytics/brigades/performance", body: { filter: {} } },
  { path: "/analytics/departments/performance", body: { filter: {} } },
  { path: "/tickets/get", body: { ticket_id: id.ticket } },
  { path: "/tickets/list", body: { limit: 20, offset: 0 } },
  { path: "/tickets/status-history", body: { ticket_id: id.ticket, limit: 20, offset: 0 } },
  { path: "/tickets/reports/list", body: { ticket_id: id.ticketDone } },
  { path: "/ticket-categories/get", body: { category_id: id.category } },
  { path: "/ticket-categories/list", body: { limit: 20, offset: 0 } },
  { path: "/departments/get", body: { id: id.department } },
  { path: "/departments/list", body: { limit: 20, offset: 0 } },
  { path: "/brigades/get", body: { id: id.brigade } },
  { path: "/brigades/list", body: { department_id: id.department, limit: 20, offset: 0 } },
  { path: "/brigades/available", body: { department_id: id.department, limit: 20 } },
  { path: "/brigades/can-handle-ticket", body: { brigade_id: id.brigade, department_id: id.department, latitude: 55.76, longitude: 37.61, required_skill_ids: [id.skill] } },
  { path: "/brigade-members/list", body: { brigade_id: id.brigade, limit: 20, offset: 0 } },
  { path: "/brigade-members/history", body: { brigade_id: id.brigade, limit: 20, offset: 0 } },
  { path: "/brigade-members/status-history", body: { brigade_id: id.brigade, limit: 20, offset: 0 } },
  { path: "/skills/list", body: { limit: 20, offset: 0 } },
  { path: "/brigade-skills/list", body: { brigade_id: id.brigade } },
  { path: "/brigade-schedules/list", body: { brigade_id: id.brigade } },
  { path: "/brigade-zones/list", body: { brigade_id: id.brigade, limit: 20, offset: 0 } },
  { path: "/brigade-zones/covers-point", body: { brigade_id: id.brigade, latitude: 55.76, longitude: 37.61 } },
  { path: "/brigade-zones/find-by-point", body: { department_id: id.department, latitude: 55.76, longitude: 37.61, limit: 20 } },
  { path: "/locations/current-batch", body: { brigade_ids: [id.brigade], allow_stale: true } },
  { path: "/locations/history", body: { brigade_id: id.brigade, from: "2020-01-01T00:00:00Z", to: "2030-01-01T00:00:00Z", limit: 20, offset: 0 } },
  { path: "/locations/nearby", body: { latitude: 55.76, longitude: 37.61, radius_meters: 10000, only_fresh: false, limit: 20 } },
  { path: "/geo-zones/list", body: { department_id: id.department, limit: 20, offset: 0 } },
  { path: "/geo-zones/check-point", body: { latitude: 55.76, longitude: 37.61, department_id: id.department } },
  { path: "/routing/get", body: { id: id.route } },
  { path: "/routing/list", body: { brigade_id: id.brigade, limit: 20, offset: 0 } },
  { path: "/user-profiles/get", body: { id: id.userProfile } },
  { path: "/user-profiles/list", body: { limit: 20, offset: 0 } },
  { path: "/work-profiles/get", body: { id: id.workProfile } },
  { path: "/work-profiles/list", body: { department_id: id.department, limit: 20, offset: 0 } },
  { path: "/profile-checks/can-join-brigade", body: { work_profile_id: id.workProfile, brigade_department_id: id.department } },
  { path: "/certification-types/list", body: { limit: 20, offset: 0 } },
  { path: "/certification-type-skills/list", body: { certification_type_id: "52000000-0000-4000-8000-000000000001" } },
  { path: "/work-profile-certifications/list", body: { work_profile_id: id.workProfile, limit: 20, offset: 0 } },
  { path: "/work-profile-skills/list-effective", body: { work_profile_id: id.workProfile } },
  { path: "/work-profile-skills/batch-list-effective", body: { work_profile_ids: [id.workProfile] } },
  { path: "/work-profile-skills/has-skills", body: { work_profile_id: id.workProfile, required_skill_ids: [id.skill] } },
  { path: "/notifications/list", body: { limit: 20, offset: 0 } },
  { path: "/notifications/preferences/get" },
  { path: "/notifications/templates/list", body: { limit: 20, offset: 0 } },
  { path: "/notifications/deliveries/list", body: { limit: 20, offset: 0 } },
  { path: "/audit/list", body: { limit: 20, offset: 0 } },
  { path: "/reports/get", body: { report_id: id.report } },
  { path: "/reports/list", body: { limit: 20, offset: 0 } },
  { path: "/assets/get", body: { asset_id: id.asset } },
  { path: "/assets/resolve", body: { identifier: "DEMO-LIGHT-124" } },
  { path: "/assets/list", body: { limit: 20, offset: 0 } },
  { path: "/assets/nearby", body: { latitude: 55.76, longitude: 37.61, radius_meters: 10000, limit: 20 } },
  { path: "/assets/prediction", body: { asset_id: id.asset } },
  { path: "/assets/maintenance/due", body: { due_before: "2030-01-01T00:00:00Z", limit: 20 } },
];

async function post(request: APIRequestContext, account: EphemeralAccount, item: ReadCase) {
  return request.post(`${gatewayUrl}${item.path}`, {
    headers: bearer(account.token),
    data: item.body,
  });
}

test.describe("Позитивная read-поверхность Gateway", () => {
  test.skip(process.env.E2E_STORAGE_ASSERTIONS !== "1", "Нужен доступ kubectl к тестовому кластеру");
  let admin: EphemeralAccount;

  test.beforeAll(async ({ request }) => { admin = await createEphemeralAccount(request, "admin"); });
  test.afterAll(() => { if (admin) deleteEphemeralAccount(admin); });

  test("все подготовленные read-операции отвечают успешно и не меняют основные таблицы", async ({ request }) => {
    const before = {
      tickets: queryTicketPostgres("SELECT count(*) FROM tickets"),
      departments: queryPlatformPostgres("department_db", "SELECT count(*) FROM departments"),
      brigades: queryPlatformPostgres("brigade_db", "SELECT count(*) FROM brigades"),
      profiles: queryPlatformPostgres("profile_db", "SELECT count(*) FROM user_profiles"),
      assets: queryPlatformPostgres("asset", "SELECT count(*) FROM assets"),
    };

    for (const item of cases) {
      const response = await post(request, admin, item);
      expect(item.expected || [200], `${item.path}: ${response.status()} ${await response.text()}`).toContain(response.status());
    }

    const auditID = queryPlatformPostgres("audit", "SELECT id FROM audit_entries ORDER BY occurred_at DESC LIMIT 1");
    expect(auditID, "audit_entries должен содержать хотя бы одну запись").not.toBe("");
    expect((await post(request, admin, { path: "/audit/get", body: { id: auditID } })).status()).toBe(200);

    const slaRuleID = queryPlatformPostgres("sla", "SELECT id FROM sla_rules ORDER BY created_at LIMIT 1");
    expect((await post(request, admin, { path: "/sla/rules/list", body: { limit: 20, offset: 0 } })).status()).toBe(200);
    expect((await post(request, admin, { path: "/sla/rules/get", body: { id: slaRuleID } })).status()).toBe(200);
    expect((await post(request, admin, { path: "/sla/tickets/list", body: { limit: 20, offset: 0 } })).status()).toBe(200);
    const slaTicketID = queryPlatformPostgres("sla", "SELECT ticket_id FROM ticket_slas ORDER BY created_at DESC LIMIT 1");
    expect(slaTicketID, "ticket_slas должен содержать хотя бы одну запись").not.toBe("");
    expect((await post(request, admin, { path: "/sla/tickets/get", body: { ticket_id: slaTicketID } })).status()).toBe(200);
    expect((await post(request, admin, { path: "/sla/history/list", body: { ticket_id: slaTicketID } })).status()).toBe(200);

    expect({
      tickets: queryTicketPostgres("SELECT count(*) FROM tickets"),
      departments: queryPlatformPostgres("department_db", "SELECT count(*) FROM departments"),
      brigades: queryPlatformPostgres("brigade_db", "SELECT count(*) FROM brigades"),
      profiles: queryPlatformPostgres("profile_db", "SELECT count(*) FROM user_profiles"),
      assets: queryPlatformPostgres("asset", "SELECT count(*) FROM assets"),
    }).toEqual(before);
  });
});
