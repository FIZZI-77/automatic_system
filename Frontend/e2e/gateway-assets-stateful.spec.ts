import { expect, test, type APIRequestContext } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { gatewayUrl } from "./support/environment";
import {
  bearer,
  createEphemeralAccount,
  deleteEphemeralAccount,
  type EphemeralAccount,
} from "./support/ephemeral-auth";
import { queryPlatformPostgres } from "./support/cluster-storage";

const departmentID = "10000000-0000-4000-8000-000000000001";

async function post(
  request: APIRequestContext,
  account: EphemeralAccount,
  path: string,
  data: unknown,
) {
  return request.post(`${gatewayUrl}${path}`, {
    headers: bearer(account.token),
    data,
  });
}

test.describe("Assets API: полная stateful-цепочка", () => {
  test.skip(
    process.env.E2E_STORAGE_ASSERTIONS !== "1",
    "Нужен доступ kubectl к тестовому кластеру",
  );
  let admin: EphemeralAccount;
  let assetID = "";
  const externalID = `e2e-${randomUUID()}`;

  test.beforeAll(async ({ request }) => {
    admin = await createEphemeralAccount(request, "admin");
  });
  test.afterAll(() => {
    if (assetID) {
      queryPlatformPostgres(
        "asset",
        `DELETE FROM maintenance_plans WHERE asset_id='${assetID}'; DELETE FROM asset_repairs WHERE asset_id='${assetID}'; DELETE FROM asset_incidents WHERE asset_id='${assetID}'; DELETE FROM asset_inspections WHERE asset_id='${assetID}'; DELETE FROM failure_predictions WHERE asset_id='${assetID}'; DELETE FROM asset_status_history WHERE asset_id='${assetID}'; DELETE FROM outbox_events WHERE aggregate_id='${assetID}'; DELETE FROM assets WHERE id='${assetID}';`,
      );
    }
    if (admin) deleteEphemeralAccount(admin);
  });

  test("create/update/status/incident/repair/inspection/maintenance/recalculate пишут ожидаемые строки", async ({
    request,
  }) => {
    const invalid = await post(request, admin, "/assets/create", {
      external_id: `${externalID}-invalid`,
      department_id: departmentID,
      type: "LIGHT",
      name: "invalid",
      geometry_geo_json: '{"type":"Point","coordinates":[37.61,55.76]}',
      criticality: 2,
    });
    expect(invalid.status()).toBe(400);
    expect(
      queryPlatformPostgres(
        "asset",
        `SELECT count(*) FROM assets WHERE external_id='${externalID}-invalid'`,
      ),
    ).toBe("0");

    const created = await post(request, admin, "/assets/create", {
      external_id: externalID,
      department_id: departmentID,
      type: "LIGHT",
      name: "E2E asset",
      address: "E2E",
      district: "E2E",
      municipality: "E2E",
      geometry_geo_json: '{"type":"Point","coordinates":[37.61,55.76]}',
      inspection_interval_days: 30,
      response_norm_minutes: 15,
      repair_norm_minutes: 60,
      criticality: 0.7,
    });
    expect(created.status(), await created.text()).toBe(201);
    assetID = ((await created.json()) as { asset: { id: string } }).asset.id;
    expect(
      queryPlatformPostgres(
        "asset",
        `SELECT external_id||'|'||name FROM assets WHERE id='${assetID}'`,
      ),
    ).toBe(`${externalID}|E2E asset`);

    const updated = await post(request, admin, "/assets/update", {
      asset_id: assetID,
      name: "E2E asset updated",
      criticality: 0.8,
    });
    expect(updated.status(), await updated.text()).toBe(200);
    expect(
      queryPlatformPostgres(
        "asset",
        `SELECT name||'|'||criticality FROM assets WHERE id='${assetID}'`,
      ),
    ).toBe("E2E asset updated|0.8");

    const status = await post(request, admin, "/assets/status", {
      asset_id: assetID,
      status: "UNDER_REPAIR",
      reason: "e2e",
    });
    expect(status.status(), await status.text()).toBe(200);
    expect(
      queryPlatformPostgres(
        "asset",
        `SELECT status FROM assets WHERE id='${assetID}'`,
      ),
    ).toBe("UNDER_REPAIR");
    expect(
      queryPlatformPostgres(
        "asset",
        `SELECT count(*) FROM asset_status_history WHERE asset_id='${assetID}' AND reason='e2e'`,
      ),
    ).toBe("1");

    const incident = await post(request, admin, "/assets/incidents", {
      asset_id: assetID,
      failure_type: "e2e_failure",
      description: "e2e",
      source: "e2e",
      priority: "HIGH",
    });
    expect(incident.status(), await incident.text()).toBe(201);
    const incidentID = ((await incident.json()) as { incident: { id: string } })
      .incident.id;
    expect(
      queryPlatformPostgres(
        "asset",
        `SELECT failure_type FROM asset_incidents WHERE id='${incidentID}'`,
      ),
    ).toBe("e2e_failure");

    const repair = await post(request, admin, "/assets/repairs", {
      asset_id: assetID,
      incident_id: incidentID,
      description: "fixed",
      replaced_components: "lamp",
      duration_minutes: 12,
    });
    expect(repair.status(), await repair.text()).toBe(201);
    expect(
      queryPlatformPostgres(
        "asset",
        `SELECT count(*) FROM asset_repairs WHERE asset_id='${assetID}' AND incident_id='${incidentID}'`,
      ),
    ).toBe("1");
    expect(
      queryPlatformPostgres(
        "asset",
        `SELECT status FROM assets WHERE id='${assetID}'`,
      ),
    ).toBe("ACTIVE");

    const inspection = await post(request, admin, "/assets/inspections", {
      asset_id: assetID,
      kind: "E2E",
      result: "OK",
      recommendation: "none",
      defect_found: false,
      condition_score: 0.9,
    });
    expect(inspection.status(), await inspection.text()).toBe(201);
    expect(
      queryPlatformPostgres(
        "asset",
        `SELECT count(*) FROM asset_inspections WHERE asset_id='${assetID}' AND kind='E2E'`,
      ),
    ).toBe("1");

    const plan = await post(request, admin, "/assets/maintenance/create", {
      asset_id: assetID,
      kind: "inspection",
      interval_days: 30,
      next_due_at: "2027-01-01T00:00:00Z",
    });
    expect(plan.status(), await plan.text()).toBe(201);
    expect(
      queryPlatformPostgres(
        "asset",
        `SELECT count(*) FROM maintenance_plans WHERE asset_id='${assetID}' AND kind='inspection'`,
      ),
    ).toBe("1");

    const recalculate = await post(
      request,
      admin,
      "/assets/risks/recalculate",
      { department_id: departmentID },
    );
    expect(recalculate.status(), await recalculate.text()).toBe(200);
    expect(
      Number(
        queryPlatformPostgres(
          "asset",
          `SELECT count(*) FROM failure_predictions WHERE asset_id='${assetID}'`,
        ),
      ),
    ).toBeGreaterThanOrEqual(1);

    for (const [path, body] of [
      ["/assets/get", { asset_id: assetID }],
      ["/assets/resolve", { identifier: externalID }],
      ["/assets/list", { department_id: departmentID, limit: 20 }],
      [
        "/assets/nearby",
        { latitude: 55.76, longitude: 37.61, radius_meters: 1000 },
      ],
      ["/assets/prediction", { asset_id: assetID }],
      [
        "/assets/maintenance/due",
        { due_before: "2028-01-01T00:00:00Z", limit: 20 },
      ],
    ] as const) {
      const response = await post(request, admin, path, body);
      expect(response.status(), `${path}: ${await response.text()}`).toBe(200);
    }
  });
});
