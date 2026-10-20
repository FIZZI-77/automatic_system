import { expect, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { gatewayUrl } from "./support/environment";
import { bearer, createEphemeralAccount, deleteEphemeralAccount, type EphemeralAccount } from "./support/ephemeral-auth";
import { queryPlatformPostgres } from "./support/cluster-storage";

const dep1 = "10000000-0000-4000-8000-000000000001";
const dep2 = "10000000-0000-4000-8000-000000000002";
const skillID = "40000000-0000-4000-8000-000000000001";

test.describe("Profiles API: профили, сертификации и skill grants", () => {
  test.skip(process.env.E2E_STORAGE_ASSERTIONS !== "1", "Нужен доступ kubectl к тестовому кластеру");
  let admin: EphemeralAccount;
  let userProfileID = "", workProfileID = "", certificationTypeID = "";
  const suffix = randomUUID().replaceAll("-", "");
  test.beforeAll(async ({ request }) => { admin = await createEphemeralAccount(request, "admin"); });
  test.afterAll(() => {
    if (workProfileID) queryPlatformPostgres("profile_db", `DELETE FROM work_profile_skill_grants WHERE work_profile_id='${workProfileID}'; DELETE FROM work_profile_certifications WHERE work_profile_id='${workProfileID}'; DELETE FROM work_profile_status_history WHERE work_profile_id='${workProfileID}'; DELETE FROM outbox_events WHERE aggregate_id='${workProfileID}'; DELETE FROM work_profiles WHERE id='${workProfileID}'`);
    if (certificationTypeID) queryPlatformPostgres("profile_db", `DELETE FROM certification_type_skills WHERE certification_type_id='${certificationTypeID}'; DELETE FROM certification_types WHERE id='${certificationTypeID}'`);
    if (userProfileID) queryPlatformPostgres("profile_db", `DELETE FROM outbox_events WHERE aggregate_id='${userProfileID}'; DELETE FROM user_profiles WHERE id='${userProfileID}'`);
    if (admin) deleteEphemeralAccount(admin);
  });

  test("все profile mutations сохраняют и изменяют ожидаемые строки", async ({ request }) => {
    const post = async (path: string, data: unknown = {}) => {
      const response = await request.post(`${gatewayUrl}${path}`, { headers: bearer(admin.token), data });
      const body = await response.json().catch(() => ({})); return { response, body };
    };
    const projectedProfileID = queryPlatformPostgres("profile_db", `SELECT id FROM user_profiles WHERE user_id='${admin.userID}'`);
    queryPlatformPostgres("profile_db", `DELETE FROM outbox_events WHERE aggregate_id='${projectedProfileID}'; DELETE FROM user_profiles WHERE id='${projectedProfileID}'`);
    const profilesBefore = queryPlatformPostgres("profile_db", "SELECT count(*) FROM user_profiles");
    expect((await post("/user-profiles/create", { full_name: "missing user" })).response.status()).toBe(400);
    expect(queryPlatformPostgres("profile_db", "SELECT count(*) FROM user_profiles")).toBe(profilesBefore);
    const createdProfile = await post("/user-profiles/create", { user_id: admin.userID, full_name: "E2E explicit profile", preferred_contact_method: "email" });
    expect(createdProfile.response.status(), JSON.stringify(createdProfile.body)).toBe(201); userProfileID = createdProfile.body.user_profile.id;
    expect(queryPlatformPostgres("profile_db", `SELECT user_id FROM user_profiles WHERE id='${userProfileID}'`)).toBe(admin.userID);
    expect(userProfileID).not.toBe("");
    expect((await post("/user-profiles/get-by-user", { user_id: admin.userID })).response.status()).toBe(200);
    expect((await request.get(`${gatewayUrl}/user-profiles/me`, { headers: bearer(admin.token) })).status()).toBe(200);
    expect((await post("/user-profiles/update", { id: userProfileID, full_name: "E2E Profile Updated", preferred_contact_method: "push" })).response.status()).toBe(200);
    expect(queryPlatformPostgres("profile_db", `SELECT full_name FROM user_profiles WHERE id='${userProfileID}'`)).toBe("E2E Profile Updated");

    const work = await post("/work-profiles/create", { user_profile_id: userProfileID, department_id: dep1, employee_number: `E2E-${suffix}`, position: "E2E worker" });
    expect(work.response.status(), JSON.stringify(work.body)).toBe(201); workProfileID = work.body.details.work_profile.id;
    expect((await post("/work-profiles/get-by-user", { user_id: admin.userID })).response.status()).toBe(200);
    expect((await post("/work-profiles/update", { id: workProfileID, position: "E2E senior worker" })).response.status()).toBe(200);
    expect((await post("/work-profiles/set-status", { id: workProfileID, status: "active", reason: "e2e" })).response.status()).toBe(200);
    expect((await post("/profile-checks/resolve-working-department", { user_id: admin.userID })).response.status()).toBe(200);
    expect((await post("/work-profiles/change-department", { id: workProfileID, department_id: dep2, reason: "e2e" })).response.status()).toBe(200);
    expect(queryPlatformPostgres("profile_db", `SELECT department_id FROM work_profiles WHERE id='${workProfileID}'`)).toBe(dep2);
    expect((await post("/work-profiles/status-history", { work_profile_id: workProfileID, limit: 20, offset: 0 })).response.status()).toBe(200);

    const ct = await post("/certification-types/create", { code: `E2E_${suffix}`, name: "E2E certification", default_validity_days: 365, requires_file: false });
    expect(ct.response.status(), JSON.stringify(ct.body)).toBe(201); certificationTypeID = ct.body.certification_type.id;
    expect((await post("/certification-types/update", { id: certificationTypeID, name: "E2E certification updated" })).response.status()).toBe(200);
    expect((await post("/certification-type-skills/add", { certification_type_id: certificationTypeID, skill_id: skillID, proficiency_level: "expert" })).response.status()).toBe(201);
    expect(queryPlatformPostgres("profile_db", `SELECT count(*) FROM certification_type_skills WHERE certification_type_id='${certificationTypeID}' AND skill_id='${skillID}' AND active`)).toBe("1");

    const upload = async (number: string) => post("/work-profile-certifications/upload", { work_profile_id: workProfileID, certification_type_id: certificationTypeID, certificate_number: number, issuer: "E2E", issued_at: "2026-01-01T00:00:00Z", expires_at: "2027-01-01T00:00:00Z" });
    const verified = await upload(`V-${suffix}`); expect(verified.response.status(), JSON.stringify(verified.body)).toBe(201);
    const verifiedID = verified.body.certification.id;
    expect((await post("/work-profile-certifications/verify", { id: verifiedID })).response.status()).toBe(200);
    expect((await post("/work-profile-certifications/revoke", { id: verifiedID, reason: "e2e" })).response.status()).toBe(200);
    const rejected = await upload(`R-${suffix}`); expect(rejected.response.status()).toBe(201);
    expect((await post("/work-profile-certifications/reject", { id: rejected.body.certification.id, rejection_reason: "e2e" })).response.status()).toBe(200);
    expect((await post("/work-profile-certifications/expire", { limit: 20 })).response.status()).toBe(200);

    const grant = await post("/work-profile-skills/grant-manual", { work_profile_id: workProfileID, skill_id: skillID, proficiency_level: "expert", reason: "e2e" });
    expect(grant.response.status(), JSON.stringify(grant.body)).toBe(201);
    expect((await post("/work-profile-skills/revoke", { id: grant.body.skill_grant.id, reason: "e2e" })).response.status()).toBe(200);
    expect((await post("/certification-type-skills/remove", { certification_type_id: certificationTypeID, skill_id: skillID })).response.status()).toBe(200);
    expect((await post("/work-profiles/deactivate", { id: workProfileID, reason: "e2e" })).response.status()).toBe(200);
    expect(queryPlatformPostgres("profile_db", `SELECT status FROM work_profiles WHERE id='${workProfileID}'`)).toBe("INACTIVE");
  });
});
