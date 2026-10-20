import { expect, test, type APIRequestContext } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { gatewayUrl } from "./support/environment";
import { bearer, createEphemeralAccount, deleteEphemeralAccount, type EphemeralAccount } from "./support/ephemeral-auth";
import { queryPlatformPostgres, queryTicketPostgres } from "./support/cluster-storage";

const departmentID = "10000000-0000-4000-8000-000000000001";
const categoryID = "20000000-0000-4000-8000-000000000001";
const occupiedSeedBrigadeID = "30000000-0000-4000-8000-000000000003";
const manualBrigadeID = "30000000-0000-4000-8000-000000000004";
const cancelBrigadeID = "30000000-0000-4000-8000-000000000005";

type DispatchOperation = {
  id: string;
  ticket_id: string;
  brigade_id?: string;
  route_id?: string;
  mode: number;
  status: number;
  version: number;
};

async function post(request: APIRequestContext, account: EphemeralAccount, path: string, data: unknown = {}) {
  const response = await request.post(`${gatewayUrl}${path}`, { headers: bearer(account.token), data });
  const body = await response.json().catch(() => ({}));
  return { response, body };
}

test.describe("Dispatch API: ручное, отменённое и автоматическое назначение", () => {
  test.skip(process.env.E2E_STORAGE_ASSERTIONS !== "1", "Нужен доступ kubectl к тестовому кластеру");
  let admin: EphemeralAccount;
  let dispatcher: EphemeralAccount;
  let adminUserProfileID = "";
  let userProfileID = "";
  let workProfileID = "";
  const ticketIDs: string[] = [];
  const operationIDs: string[] = [];
  const routeIDs: string[] = [];
  const locationEventIDs: string[] = [];
  let occupiedSeedStatus = "";
  const suffix = randomUUID().replaceAll("-", "");

  test.beforeAll(async ({ request }) => {
    admin = await createEphemeralAccount(request, "admin");
    dispatcher = await createEphemeralAccount(request, "dispatcher");
    adminUserProfileID = queryPlatformPostgres("profile_db", `SELECT id FROM user_profiles WHERE user_id='${admin.userID}'`);
    userProfileID = queryPlatformPostgres("profile_db", `SELECT id FROM user_profiles WHERE user_id='${dispatcher.userID}'`);
    expect(userProfileID).not.toBe("");

    const work = await post(request, admin, "/work-profiles/create", {
      user_profile_id: userProfileID,
      department_id: departmentID,
      employee_number: `DISPATCH-${suffix}`,
      position: "E2E dispatcher",
    });
    expect(work.response.status(), JSON.stringify(work.body)).toBe(201);
    workProfileID = work.body.details.work_profile.id;
    const activated = await post(request, admin, "/work-profiles/set-status", {
      id: workProfileID,
      status: "active",
      reason: "dispatch e2e",
    });
    expect(activated.response.status(), JSON.stringify(activated.body)).toBe(200);

    await expect.poll(async () => {
      const resolved = await post(request, dispatcher, "/profile-checks/resolve-working-department", { user_id: dispatcher.userID });
      return resolved.response.status() === 200 && resolved.body.can_operate === true && resolved.body.department_id === departmentID;
    }, { timeout: 15_000 }).toBe(true);

    occupiedSeedStatus = queryPlatformPostgres("brigade_db", `SELECT status FROM brigades WHERE id='${occupiedSeedBrigadeID}'`);
    queryPlatformPostgres("brigade_db", `UPDATE brigades SET status='BUSY', updated_at=now() WHERE id='${occupiedSeedBrigadeID}'`);

    const locations = [
      [manualBrigadeID, 55.7596, 37.6150],
      [cancelBrigadeID, 55.7658, 37.6088],
    ] as const;
    const sequence = Date.now();
    for (const [index, [brigadeID, latitude, longitude]] of locations.entries()) {
      const eventID = randomUUID();
      locationEventIDs.push(eventID);
      const recorded = await post(request, dispatcher, "/locations/record", {
        event_id: eventID,
        event_version: 1,
        occurred_at: new Date().toISOString(),
        device_id: `dispatch-e2e-${index}-${suffix}`,
        vehicle_id: randomUUID(),
        brigade_id: brigadeID,
        sequence: sequence + index,
        latitude,
        longitude,
        speed_kmh: 0,
        heading: 0,
        accuracy_meters: 2,
        simulated: true,
      });
      expect(recorded.response.status(), JSON.stringify(recorded.body)).toBe(201);
    }
  });

  test.afterAll(() => {
    if (operationIDs.length) {
      const ids = operationIDs.map((id) => `'${id}'`).join(",");
      queryPlatformPostgres("dispatch", `DELETE FROM dispatch_outbox_events WHERE aggregate_id IN (${ids}); DELETE FROM dispatch_operations WHERE id IN (${ids})`);
    }
    if (routeIDs.length) {
      const ids = routeIDs.map((id) => `'${id}'`).join(",");
      queryPlatformPostgres("routing", `DELETE FROM outbox_events WHERE aggregate_id IN (${ids}); DELETE FROM routes WHERE id IN (${ids})`);
    }
    if (ticketIDs.length) {
      const ids = ticketIDs.map((id) => `'${id}'`).join(",");
      queryTicketPostgres(`DELETE FROM ticket_status_history WHERE ticket_id IN (${ids}); DELETE FROM outbox_events WHERE aggregate_id IN (${ids}); DELETE FROM tickets WHERE id IN (${ids})`);
    }
    if (locationEventIDs.length) {
      queryPlatformPostgres("location", `DELETE FROM position_history WHERE event_id IN (${locationEventIDs.map((id) => `'${id}'`).join(",")})`);
    }
    queryPlatformPostgres("brigade_db", `
      UPDATE brigades SET status='AVAILABLE', updated_at=now() WHERE id IN ('${manualBrigadeID}','${cancelBrigadeID}');
      UPDATE brigades SET status='${occupiedSeedStatus || "AVAILABLE"}', updated_at=now() WHERE id='${occupiedSeedBrigadeID}';
      DELETE FROM brigade_status_history WHERE brigade_id IN ('${manualBrigadeID}','${cancelBrigadeID}') AND changed_by_user_id='${dispatcher?.userID}';
    `);
    if (workProfileID) {
      queryPlatformPostgres("profile_db", `DELETE FROM work_profile_status_history WHERE work_profile_id='${workProfileID}'; DELETE FROM outbox_events WHERE aggregate_id='${workProfileID}'; DELETE FROM work_profiles WHERE id='${workProfileID}'`);
    }
    if (userProfileID) queryPlatformPostgres("profile_db", `DELETE FROM outbox_events WHERE aggregate_id='${userProfileID}'; DELETE FROM user_profiles WHERE id='${userProfileID}'`);
    if (adminUserProfileID) queryPlatformPostgres("profile_db", `DELETE FROM outbox_events WHERE aggregate_id='${adminUserProfileID}'; DELETE FROM user_profiles WHERE id='${adminUserProfileID}'`);
    if (dispatcher) deleteEphemeralAccount(dispatcher);
    if (admin) deleteEphemeralAccount(admin);
  });

  test("preview/reserve/get/list/confirm/cancel/auto согласуют четыре сервиса и хранилища", async ({ request }) => {
    const createTicket = async (label: string) => {
      const created = await post(request, dispatcher, "/tickets/create", {
        department_id: departmentID,
        category_id: categoryID,
        user_id: dispatcher.userID,
        title: `Dispatch E2E ${label} ${suffix}`,
        description: label,
        priority: "HIGH",
        address: "Москва",
        latitude: 55.7605,
        longitude: 37.6120,
      });
      expect(created.response.status(), JSON.stringify(created.body)).toBe(201);
      ticketIDs.push(created.body.ticket.id);
      return created.body.ticket.id as string;
    };

    const beforeInvalid = queryPlatformPostgres("dispatch", "SELECT count(*) FROM dispatch_operations");
    const invalid = await post(request, dispatcher, "/dispatch/reserve", { ticket_id: randomUUID() });
    expect(invalid.response.status()).toBe(400);
    expect(queryPlatformPostgres("dispatch", "SELECT count(*) FROM dispatch_operations")).toBe(beforeInvalid);

    const manualTicketID = await createTicket("manual");
    const preview = await post(request, dispatcher, "/dispatch/preview", { ticket_id: manualTicketID, limit: 10 });
    expect(preview.response.status(), JSON.stringify(preview.body)).toBe(200);
    expect(preview.body.candidates.some((candidate: { brigade_id: string }) => candidate.brigade_id === manualBrigadeID)).toBe(true);

    const reserved = await post(request, dispatcher, "/dispatch/reserve", {
      ticket_id: manualTicketID,
      brigade_id: manualBrigadeID,
      requested_by: dispatcher.userID,
      reservation_ttl_seconds: 120,
    });
    expect(reserved.response.status(), JSON.stringify(reserved.body)).toBe(201);
    const manual = reserved.body.operation as DispatchOperation;
    operationIDs.push(manual.id);
    expect(queryPlatformPostgres("dispatch", `SELECT mode||'|'||status||'|'||brigade_id FROM dispatch_operations WHERE id='${manual.id}'`)).toBe(`MANUAL|RESERVED|${manualBrigadeID}`);
    const manualVersion = Number(queryPlatformPostgres("dispatch", `SELECT version FROM dispatch_operations WHERE id='${manual.id}'`));
    expect(manual.version).toBe(manualVersion);
    expect(queryPlatformPostgres("brigade_db", `SELECT status FROM brigades WHERE id='${manualBrigadeID}'`)).toBe("BUSY");
    expect((await post(request, dispatcher, "/dispatch/get", { id: manual.id })).response.status()).toBe(200);
    expect((await post(request, dispatcher, "/dispatch/list", { ticket_id: manualTicketID, status: "RESERVED", limit: 20, offset: 0 })).response.status()).toBe(200);

    const confirmed = await post(request, dispatcher, "/dispatch/confirm", {
      id: manual.id,
      confirmed_by: dispatcher.userID,
      expected_version: manualVersion,
    });
    expect(confirmed.response.status(), JSON.stringify(confirmed.body)).toBe(200);
    const assigned = confirmed.body.operation as DispatchOperation;
    expect(assigned.status).toBe(4);
    expect(assigned.route_id).toBeTruthy();
    routeIDs.push(assigned.route_id!);
    expect(queryPlatformPostgres("dispatch", `SELECT status||'|'||route_id FROM dispatch_operations WHERE id='${manual.id}'`)).toBe(`ASSIGNED|${assigned.route_id}`);
    expect(queryPlatformPostgres("routing", `SELECT status FROM routes WHERE id='${assigned.route_id}'`)).toBe("PLANNED");
    expect(queryTicketPostgres(`SELECT status||'|'||brigade_id FROM tickets WHERE id='${manualTicketID}'`)).toBe(`ASSIGNED|${manualBrigadeID}`);

    const cancelTicketID = await createTicket("cancel");
    const cancelReserved = await post(request, dispatcher, "/dispatch/reserve", {
      ticket_id: cancelTicketID,
      brigade_id: cancelBrigadeID,
      requested_by: dispatcher.userID,
      reservation_ttl_seconds: 120,
    });
    expect(cancelReserved.response.status(), JSON.stringify(cancelReserved.body)).toBe(201);
    const cancellable = cancelReserved.body.operation as DispatchOperation;
    operationIDs.push(cancellable.id);
    const cancelled = await post(request, dispatcher, "/dispatch/cancel", {
      id: cancellable.id,
      cancelled_by: dispatcher.userID,
      expected_version: cancellable.version,
      reason: "dispatch e2e cancellation",
    });
    expect(cancelled.response.status(), JSON.stringify(cancelled.body)).toBe(200);
    expect(queryPlatformPostgres("dispatch", `SELECT status FROM dispatch_operations WHERE id='${cancellable.id}'`)).toBe("CANCELLED");
    expect(queryPlatformPostgres("brigade_db", `SELECT status FROM brigades WHERE id='${cancelBrigadeID}'`)).toBe("AVAILABLE");
    const staleCancel = await post(request, dispatcher, "/dispatch/cancel", {
      id: cancellable.id,
      cancelled_by: dispatcher.userID,
      expected_version: cancellable.version,
      reason: "repeat",
    });
    expect(staleCancel.response.status()).toBe(409);

    const autoTicketID = await createTicket("auto");
    const automatic = await post(request, dispatcher, "/dispatch/auto", {
      ticket_id: autoTicketID,
      requested_by: dispatcher.userID,
      candidate_limit: 10,
    });
    expect(automatic.response.status(), JSON.stringify(automatic.body)).toBe(201);
    const auto = automatic.body.operation as DispatchOperation;
    operationIDs.push(auto.id);
    expect(auto.status).toBe(4);
    expect(auto.mode).toBe(2);
    expect(auto.route_id).toBeTruthy();
    routeIDs.push(auto.route_id!);
    expect(queryPlatformPostgres("dispatch", `SELECT mode||'|'||status FROM dispatch_operations WHERE id='${auto.id}'`)).toBe("AUTOMATIC|ASSIGNED");
    expect(queryTicketPostgres(`SELECT status||'|'||brigade_id FROM tickets WHERE id='${autoTicketID}'`)).toBe(`ASSIGNED|${auto.brigade_id}`);
    expect(queryPlatformPostgres("routing", `SELECT count(*) FROM routes WHERE id='${auto.route_id}' AND ticket_id='${autoTicketID}'`)).toBe("1");
  });
});
