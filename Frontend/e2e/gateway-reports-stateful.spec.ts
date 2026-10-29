import { expect, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { gatewayUrl } from "./support/environment";
import {
  bearer,
  createEphemeralAccount,
  deleteEphemeralAccount,
  type EphemeralAccount,
} from "./support/ephemeral-auth";
import {
  queryPlatformPostgres,
  queryTicketPostgres,
} from "./support/cluster-storage";

const progressTicketID = "60000000-0000-4000-8000-000000000003";

test.describe("Reports API: очередь, генерация, retry/cancel и completion", () => {
  test.skip(
    process.env.E2E_STORAGE_ASSERTIONS !== "1",
    "Нужен доступ kubectl к тестовому кластеру",
  );
  let admin: EphemeralAccount;
  let profileID = "";
  let workReportID = "";
  const reportIDs: string[] = [];
  const generatedFileIDs: string[] = [];
  test.beforeAll(async ({ request }) => {
    admin = await createEphemeralAccount(request, "admin");
    profileID = queryPlatformPostgres(
      "profile_db",
      `SELECT id FROM user_profiles WHERE user_id='${admin.userID}'`,
    );
  });
  test.afterAll(() => {
    if (reportIDs.length) {
      const ids = reportIDs.map((id) => `'${id}'`).join(",");
      queryPlatformPostgres(
        "report",
        `DELETE FROM outbox_events WHERE aggregate_id IN (${ids}); DELETE FROM reports WHERE id IN (${ids})`,
      );
    }
    if (generatedFileIDs.length)
      queryPlatformPostgres(
        "file",
        `DELETE FROM files WHERE id IN (${generatedFileIDs.map((id) => `'${id}'`).join(",")})`,
      );
    if (workReportID)
      queryTicketPostgres(
        `DELETE FROM ticket_report_files WHERE report_id='${workReportID}'; DELETE FROM ticket_reports WHERE id='${workReportID}'`,
      );
    if (profileID)
      queryPlatformPostgres(
        "profile_db",
        `DELETE FROM outbox_events WHERE aggregate_id='${profileID}'; DELETE FROM user_profiles WHERE id='${profileID}'`,
      );
    if (admin) deleteEphemeralAccount(admin);
  });
  test("все report endpoints меняют ожидаемые строки и отдают артефакт", async ({
    request,
  }) => {
    const post = async (
      path: string,
      data: unknown = {},
      headers: Record<string, string> = {},
    ) => {
      const response = await request.post(`${gatewayUrl}${path}`, {
        headers: { ...bearer(admin.token), ...headers },
        data,
      });
      const body = await response.json().catch(() => ({}));
      return { response, body };
    };
    const before = queryPlatformPostgres(
      "report",
      "SELECT count(*) FROM reports",
    );
    expect(
      (
        await post("/reports/create", {
          name: "x",
          type: "unknown",
          format: "txt",
        })
      ).response.status(),
    ).toBe(400);
    expect(
      queryPlatformPostgres("report", "SELECT count(*) FROM reports"),
    ).toBe(before);
    const created = await post("/reports/create", {
      name: "Gateway E2E ticket overview",
      type: "ticket_overview",
      format: "csv",
      filter: {},
    });
    expect(created.response.status(), JSON.stringify(created.body)).toBe(202);
    const generatedID = created.body.report.id as string;
    reportIDs.push(generatedID);
    expect(
      (
        await post("/reports/get", { report_id: generatedID })
      ).response.status(),
    ).toBe(200);
    expect(
      (
        await post("/reports/list", { limit: 100, offset: 0 })
      ).response.status(),
    ).toBe(200);
    await expect
      .poll(
        () =>
          queryPlatformPostgres(
            "report",
            `SELECT status FROM reports WHERE id='${generatedID}'`,
          ),
        { timeout: 45_000, intervals: [500, 1000, 2000] },
      )
      .toBe("COMPLETED");
    const fileID = queryPlatformPostgres(
      "report",
      `SELECT file_id FROM reports WHERE id='${generatedID}'`,
    );
    expect(fileID).not.toBe("");
    generatedFileIDs.push(fileID);
    expect(
      queryPlatformPostgres(
        "file",
        `SELECT status||'|'||resource_type||'|'||resource_id FROM files WHERE id='${fileID}'`,
      ),
    ).toBe(`LINKED|report|${generatedID}`);
    const download = await post("/reports/download-url", {
      report_id: generatedID,
    });
    expect(download.response.status(), JSON.stringify(download.body)).toBe(200);
    const artifact = await request.get(download.body.download_url);
    expect(artifact.status()).toBe(200);
    expect((await artifact.body()).length).toBeGreaterThan(0);
    expect(
      (
        await post("/reports/cancel", { report_id: generatedID })
      ).response.status(),
    ).toBe(409);
    expect(
      (
        await post("/reports/retry", { report_id: generatedID })
      ).response.status(),
    ).toBe(409);
    const pendingID = randomUUID();
    reportIDs.push(pendingID);
    queryPlatformPostgres(
      "report",
      `INSERT INTO reports(id,requested_by,actor_roles,name,type,format,status,filter) VALUES('${pendingID}','${admin.userID}',ARRAY['admin'],'E2E cancel','TICKET_OVERVIEW','CSV','PENDING','{}')`,
    );
    const cancelled = await post("/reports/cancel", { report_id: pendingID });
    expect(cancelled.response.status(), JSON.stringify(cancelled.body)).toBe(
      200,
    );
    expect(
      queryPlatformPostgres(
        "report",
        `SELECT status FROM reports WHERE id='${pendingID}'`,
      ),
    ).toBe("CANCELED");
    const failedID = randomUUID();
    reportIDs.push(failedID);
    queryPlatformPostgres(
      "report",
      `INSERT INTO reports(id,requested_by,actor_roles,name,type,format,status,filter,error,attempts) VALUES('${failedID}','${admin.userID}',ARRAY['admin'],'E2E retry','TICKET_OVERVIEW','CSV','FAILED','{}','fixture failure',1)`,
    );
    const retried = await post("/reports/retry", { report_id: failedID });
    expect(retried.response.status(), JSON.stringify(retried.body)).toBe(200);
    await expect
      .poll(
        () =>
          queryPlatformPostgres(
            "report",
            `SELECT status FROM reports WHERE id='${failedID}'`,
          ),
        { timeout: 45_000, intervals: [500, 1000, 2000] },
      )
      .toBe("COMPLETED");
    const retryFileID = queryPlatformPostgres(
      "report",
      `SELECT file_id FROM reports WHERE id='${failedID}'`,
    );
    generatedFileIDs.push(retryFileID);
    const completion = await post(
      "/reports/completion/create",
      {
        ticket_id: progressTicketID,
        description: `Gateway completion ${randomUUID()}`,
        file_ids: [],
      },
      { "Idempotency-Key": randomUUID() },
    );
    expect(completion.response.status(), JSON.stringify(completion.body)).toBe(
      202,
    );
    workReportID = completion.body.work_report.id;
    expect(
      queryTicketPostgres(
        `SELECT count(*) FROM ticket_reports WHERE id='${workReportID}' AND ticket_id='${progressTicketID}'`,
      ),
    ).toBe("1");
    for (const generatedFileID of generatedFileIDs) {
      expect(
        (
          await post("/files/delete", { file_id: generatedFileID })
        ).response.status(),
      ).toBe(200);
      expect(
        queryPlatformPostgres(
          "file",
          `SELECT status FROM files WHERE id='${generatedFileID}'`,
        ),
      ).toBe("DELETED");
    }
  });
});
