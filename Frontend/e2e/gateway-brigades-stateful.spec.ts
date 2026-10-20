import { expect, test, type APIRequestContext } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { gatewayUrl } from "./support/environment";
import { bearer, createEphemeralAccount, deleteEphemeralAccount, type EphemeralAccount } from "./support/ephemeral-auth";
import { queryPlatformPostgres } from "./support/cluster-storage";

const departmentID = "10000000-0000-4000-8000-000000000001";
const skillID = "40000000-0000-4000-8000-000000000001";

async function post(request: APIRequestContext, account: EphemeralAccount, path: string, data: unknown = {}) {
  const response = await request.post(`${gatewayUrl}${path}`, { headers: bearer(account.token), data });
  const body = await response.json().catch(() => ({}));
  return { response, body };
}

test.describe("Brigades API: состав, навыки, график, зоны и статусы", () => {
  test.skip(process.env.E2E_STORAGE_ASSERTIONS !== "1", "Нужен доступ kubectl к тестовому кластеру");
  let admin: EphemeralAccount;
  let brigadeID = "";
  let memberID = "";
  let zoneID = "";
  let userProfileID = "";
  let workProfileID = "";
  const suffix = randomUUID();

  test.beforeAll(async ({ request }) => { admin = await createEphemeralAccount(request, "admin"); });
  test.afterAll(() => {
    if (brigadeID) {
      queryPlatformPostgres("brigade_db", `DELETE FROM brigade_shifts WHERE brigade_id='${brigadeID}'; DELETE FROM outbox_events WHERE aggregate_id='${brigadeID}'; DELETE FROM brigades WHERE id='${brigadeID}'`);
    }
    if (workProfileID) queryPlatformPostgres("profile_db", `DELETE FROM work_profile_status_history WHERE work_profile_id='${workProfileID}'; DELETE FROM outbox_events WHERE aggregate_id='${workProfileID}'; DELETE FROM work_profiles WHERE id='${workProfileID}'`);
    if (userProfileID) queryPlatformPostgres("profile_db", `DELETE FROM outbox_events WHERE aggregate_id='${userProfileID}'; DELETE FROM user_profiles WHERE id='${userProfileID}'`);
    if (admin) deleteEphemeralAccount(admin);
  });

  test("полный жизненный цикл всех brigade-подресурсов", async ({ request }) => {
    const invalidBefore = queryPlatformPostgres("brigade_db", "SELECT count(*) FROM brigades");
    expect((await post(request, admin, "/brigades/create", { department_id: "bad", name: "x" })).response.status()).toBe(400);
    expect(queryPlatformPostgres("brigade_db", "SELECT count(*) FROM brigades")).toBe(invalidBefore);

    const created = await post(request, admin, "/brigades/create", { department_id: departmentID, name: `E2E brigade ${suffix}`, description: "created", specialization: "e2e" });
    expect(created.response.status(), JSON.stringify(created.body)).toBe(201);
    brigadeID = created.body.brigade.id;
    expect(queryPlatformPostgres("brigade_db", `SELECT status FROM brigades WHERE id='${brigadeID}'`)).toBe("INACTIVE");
    expect((await post(request, admin, "/brigades/get", { id: brigadeID })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigades/list", { department_id: departmentID, limit: 20, offset: 0 })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigades/update", { id: brigadeID, name: "E2E brigade updated" })).response.status()).toBe(200);
    expect(queryPlatformPostgres("brigade_db", `SELECT name FROM brigades WHERE id='${brigadeID}'`)).toBe("E2E brigade updated");

    const memberUserID = admin.userID;
    userProfileID = queryPlatformPostgres("profile_db", `SELECT id FROM user_profiles WHERE user_id='${memberUserID}'`);
    expect(userProfileID, "Auth registration должен быть спроецирован в user_profiles").not.toBe("");
    const workProfile = await post(request, admin, "/work-profiles/create", { user_profile_id: userProfileID, department_id: departmentID, position: "E2E technician" });
    expect(workProfile.response.status(), JSON.stringify(workProfile.body)).toBe(201);
    workProfileID = workProfile.body.details.work_profile.id;
    expect((await post(request, admin, "/work-profiles/set-status", { id: workProfileID, status: "active", reason: "e2e" })).response.status()).toBe(200);
    await expect.poll(async () => (await post(request, admin, "/profile-checks/can-join-brigade", { work_profile_id: workProfileID, brigade_department_id: departmentID })).response.status(), { timeout: 15_000 }).toBe(200);
    const added = await post(request, admin, "/brigade-members/add", { brigade_id: brigadeID, user_id: memberUserID, profile_id: workProfileID, role: "lead" });
    expect(added.response.status(), JSON.stringify(added.body)).toBe(201);
    memberID = added.body.member.id;
    expect(queryPlatformPostgres("brigade_db", `SELECT role FROM brigade_members WHERE id='${memberID}'`)).toBe("LEAD");
    expect((await post(request, admin, "/brigade-members/list", { brigade_id: brigadeID, limit: 20, offset: 0 })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigade-members/history", { brigade_id: brigadeID, member_id: memberID, limit: 20, offset: 0 })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigades/get-by-user", { user_id: memberUserID, only_active: true })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigade-members/change-role", { brigade_id: brigadeID, member_id: memberID, role: "technician" })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigade-members/set-availability", { brigade_id: brigadeID, member_id: memberID, status: "unavailable", reason: "e2e" })).response.status()).toBe(200);
    expect(queryPlatformPostgres("brigade_db", `SELECT role||'|'||availability_status FROM brigade_members WHERE id='${memberID}'`)).toBe("TECHNICIAN|UNAVAILABLE");
    expect((await post(request, admin, "/brigade-members/status-history", { brigade_id: brigadeID, member_id: memberID, limit: 20, offset: 0 })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigade-members/set-availability", { brigade_id: brigadeID, member_id: memberID, status: "available", reason: "ready" })).response.status()).toBe(200);

    expect((await post(request, admin, "/brigade-skills/add", { brigade_id: brigadeID, skill_id: skillID })).response.status()).toBe(201);
    expect(queryPlatformPostgres("brigade_db", `SELECT count(*) FROM brigade_skills WHERE brigade_id='${brigadeID}' AND skill_id='${skillID}' AND active`)).toBe("1");
    expect((await post(request, admin, "/brigade-skills/list", { brigade_id: brigadeID })).response.status()).toBe(200);

    const schedule = await post(request, admin, "/brigade-schedules/set", { brigade_id: brigadeID, items: Array.from({ length: 7 }, (_, index) => ({ day_of_week: index + 1, starts_at: "00:00", ends_at: "23:59", timezone: "Europe/Moscow" })) });
    expect(schedule.response.status(), JSON.stringify(schedule.body)).toBe(200);
    expect(queryPlatformPostgres("brigade_db", `SELECT count(*) FROM brigade_schedule WHERE brigade_id='${brigadeID}' AND active`)).toBe("7");
    expect((await post(request, admin, "/brigade-schedules/list", { brigade_id: brigadeID })).response.status()).toBe(200);

    const polygon = '{"type":"Polygon","coordinates":[[[37.60,55.75],[37.62,55.75],[37.62,55.77],[37.60,55.77],[37.60,55.75]]]}';
    const zone = await post(request, admin, "/brigade-zones/create", { brigade_id: brigadeID, department_id: departmentID, name: "E2E zone", geo_json: polygon, priority: 10 });
    expect(zone.response.status(), JSON.stringify(zone.body)).toBe(201);
    zoneID = zone.body.zone.id;
    expect(queryPlatformPostgres("brigade_db", `SELECT count(*) FROM brigade_zones WHERE id='${zoneID}'`)).toBe("1");
    expect((await post(request, admin, "/brigade-zones/list", { brigade_id: brigadeID })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigade-zones/covers-point", { brigade_id: brigadeID, latitude: 55.76, longitude: 37.61 })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigade-zones/find-by-point", { department_id: departmentID, latitude: 55.76, longitude: 37.61, limit: 20 })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigade-zones/update", { id: zoneID, name: "E2E zone updated", priority: 20 })).response.status()).toBe(200);
    expect(queryPlatformPostgres("brigade_db", `SELECT name FROM brigade_zones WHERE id='${zoneID}'`)).toBe("E2E zone updated");

    expect((await post(request, admin, "/brigades/set-status", { brigade_id: brigadeID, status: "active", reason: "e2e" })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigades/set-status", { brigade_id: brigadeID, status: "available", reason: "e2e" })).response.status()).toBe(200);
    expect(queryPlatformPostgres("brigade_db", `SELECT status FROM brigades WHERE id='${brigadeID}'`)).toBe("AVAILABLE");
    expect((await post(request, admin, "/brigades/status-history", { brigade_id: brigadeID, limit: 20, offset: 0 })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigades/available", { department_id: departmentID, latitude: 55.76, longitude: 37.61, required_skill_ids: [skillID], limit: 20 })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigades/can-handle-ticket", { brigade_id: brigadeID, department_id: departmentID, latitude: 55.76, longitude: 37.61, required_skill_ids: [skillID] })).response.status()).toBe(200);

    expect((await post(request, admin, "/brigade-skills/remove", { brigade_id: brigadeID, skill_id: skillID })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigade-zones/delete", { id: zoneID })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigades/deactivate", { id: brigadeID, reason: "e2e" })).response.status()).toBe(200);
    expect((await post(request, admin, "/brigade-members/remove", { brigade_id: brigadeID, member_id: memberID, reason: "e2e" })).response.status()).toBe(200);
    expect(queryPlatformPostgres("brigade_db", `SELECT active FROM brigade_members WHERE id='${memberID}'`)).toBe("f");
    expect((await post(request, admin, "/brigades/archive", { id: brigadeID, reason: "e2e" })).response.status()).toBe(200);
    expect(queryPlatformPostgres("brigade_db", `SELECT status FROM brigades WHERE id='${brigadeID}'`)).toBe("ARCHIVED");
  });
});
