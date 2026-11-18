import { expect, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { gatewayUrl } from "./support/environment";
import {
  bearer,
  createEphemeralAccount,
  deleteEphemeralAccount,
  type EphemeralAccount,
} from "./support/ephemeral-auth";
import { queryPlatformPostgres } from "./support/cluster-storage";

test.describe("Locations + Routing API", () => {
  test.skip(
    process.env.E2E_STORAGE_ASSERTIONS !== "1",
    "Нужен доступ kubectl к тестовому кластеру",
  );
  let admin: EphemeralAccount;
  const brigadeID = randomUUID(),
    vehicleID = randomUUID(),
    eventID = randomUUID(),
    ticketID = randomUUID();
  let routeID = "";
  test.beforeAll(async ({ request }) => {
    admin = await createEphemeralAccount(request, "admin");
  });
  test.afterAll(() => {
    queryPlatformPostgres(
      "location",
      `DELETE FROM position_history WHERE event_id='${eventID}'`,
    );
    if (routeID)
      queryPlatformPostgres(
        "routing",
        `DELETE FROM outbox_events WHERE aggregate_id='${routeID}'; DELETE FROM routes WHERE id='${routeID}'`,
      );
    if (admin) deleteEphemeralAccount(admin);
  });

  test("record/current/history/nearby и полный lifecycle маршрута", async ({
    request,
  }) => {
    const post = async (path: string, data: unknown = {}) => {
      const response = await request.post(`${gatewayUrl}${path}`, {
        headers: bearer(admin.token),
        data,
      });
      const body = await response.json().catch(() => ({}));
      return { response, body };
    };
    const invalidBefore = queryPlatformPostgres(
      "location",
      `SELECT count(*) FROM position_history WHERE brigade_id='${brigadeID}'`,
    );
    expect(
      (
        await post("/locations/record", {
          event_id: eventID,
          event_version: 1,
          occurred_at: new Date().toISOString(),
          device_id: "e2e",
          vehicle_id: vehicleID,
          brigade_id: brigadeID,
          sequence: 1,
          latitude: 190,
          longitude: 37.61,
        })
      ).response.status(),
    ).toBe(400);
    expect(
      queryPlatformPostgres(
        "location",
        `SELECT count(*) FROM position_history WHERE brigade_id='${brigadeID}'`,
      ),
    ).toBe(invalidBefore);
    const recorded = await post("/locations/record", {
      event_id: eventID,
      event_version: 1,
      occurred_at: new Date().toISOString(),
      device_id: `e2e-${eventID}`,
      vehicle_id: vehicleID,
      brigade_id: brigadeID,
      sequence: 1,
      latitude: 55.76,
      longitude: 37.61,
      speed_kmh: 10,
      heading: 90,
      accuracy_meters: 3,
      simulated: true,
    });
    expect(recorded.response.status(), JSON.stringify(recorded.body)).toBe(201);
    expect(
      (
        await post("/locations/current", {
          subject_type: "brigade",
          subject_id: brigadeID,
        })
      ).response.status(),
    ).toBe(200);
    expect(
      (
        await post("/locations/current-batch", {
          brigade_ids: [brigadeID],
          allow_stale: true,
        })
      ).response.status(),
    ).toBe(200);
    expect(
      (
        await post("/locations/nearby", {
          latitude: 55.76,
          longitude: 37.61,
          radius_meters: 1000,
          brigade_ids: [brigadeID],
          only_fresh: false,
          limit: 20,
        })
      ).response.status(),
    ).toBe(200);
    await expect
      .poll(
        () =>
          Number(
            queryPlatformPostgres(
              "location",
              `SELECT count(*) FROM position_history WHERE event_id='${eventID}'`,
            ),
          ),
        { timeout: 15_000 },
      )
      .toBe(1);
    expect(
      (
        await post("/locations/history", {
          brigade_id: brigadeID,
          from: "2026-01-01T00:00:00Z",
          to: "2027-01-01T00:00:00Z",
          limit: 20,
          offset: 0,
        })
      ).response.status(),
    ).toBe(200);

    const origin = { latitude: 55.76, longitude: 37.61 },
      destination = { latitude: 55.765, longitude: 37.62 },
      options = { travel_mode: "auto" };
    for (const [path, data] of [
      ["/routing/build", { origin, destination, options }],
      [
        "/routing/matrix",
        { sources: [origin], targets: [destination], options },
      ],
      [
        "/routing/rank-candidates",
        {
          destination,
          candidates: [{ brigade_id: brigadeID, location: origin }],
          options,
          limit: 10,
        },
      ],
    ] as const) {
      const response = await post(path, data);
      expect(
        response.response.status(),
        `${path}: ${JSON.stringify(response.body)}`,
      ).toBe(200);
    }
    const created = await post("/routing/create", {
      ticket_id: ticketID,
      brigade_id: brigadeID,
      origin,
      destination,
      options,
    });
    expect(created.response.status(), JSON.stringify(created.body)).toBe(201);
    routeID = created.body.route.id;
    expect(
      queryPlatformPostgres(
        "routing",
        `SELECT status FROM routes WHERE id='${routeID}'`,
      ),
    ).toBe("PLANNED");
    expect(
      (await post("/routing/get", { id: routeID })).response.status(),
    ).toBe(200);
    expect(
      (
        await post("/routing/list", {
          ticket_id: ticketID,
          limit: 20,
          offset: 0,
        })
      ).response.status(),
    ).toBe(200);
    expect(
      (
        await post("/routing/recalculate", {
          id: routeID,
          current_position: origin,
        })
      ).response.status(),
    ).toBe(200);
    expect(
      Number(
        queryPlatformPostgres(
          "routing",
          `SELECT revision FROM routes WHERE id='${routeID}'`,
        ),
      ),
    ).toBeGreaterThan(1);
    expect(
      (
        await post("/routing/set-status", { id: routeID, status: "ACTIVE" })
      ).response.status(),
    ).toBe(200);
    expect(
      (
        await post("/routing/set-status", { id: routeID, status: "COMPLETED" })
      ).response.status(),
    ).toBe(200);
    expect(
      queryPlatformPostgres(
        "routing",
        `SELECT status FROM routes WHERE id='${routeID}'`,
      ),
    ).toBe("COMPLETED");
  });
});
