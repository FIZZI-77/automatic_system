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

test.describe("Files API: presigned upload и фактический объект", () => {
  test.skip(
    process.env.E2E_STORAGE_ASSERTIONS !== "1",
    "Нужен доступ kubectl к тестовому кластеру",
  );
  let user: EphemeralAccount;
  let profileID = "";
  let fileID = "";
  const resourceID = randomUUID();
  const payload = Buffer.from("gateway-file-e2e\n", "utf8");
  test.beforeAll(async ({ request }) => {
    user = await createEphemeralAccount(request, "user");
    profileID = queryPlatformPostgres(
      "profile_db",
      `SELECT id FROM user_profiles WHERE user_id='${user.userID}'`,
    );
  });
  test.afterAll(() => {
    if (fileID)
      queryPlatformPostgres("file", `DELETE FROM files WHERE id='${fileID}'`);
    if (profileID)
      queryPlatformPostgres(
        "profile_db",
        `DELETE FROM outbox_events WHERE aggregate_id='${profileID}'; DELETE FROM user_profiles WHERE id='${profileID}'`,
      );
    if (user) deleteEphemeralAccount(user);
  });
  test("upload/download работают, произвольная привязка запрещена", async ({
    request,
  }) => {
    const post = async (path: string, data: unknown = {}) => {
      const response = await request.post(`${gatewayUrl}${path}`, {
        headers: bearer(user.token),
        data,
      });
      const body = await response.json().catch(() => ({}));
      return { response, body };
    };
    const before = queryPlatformPostgres("file", "SELECT count(*) FROM files");
    expect(
      (
        await post("/files/uploads/create", {
          name: "bad.exe",
          content_type: "application/octet-stream",
          size: 1,
        })
      ).response.status(),
    ).toBe(400);
    expect(queryPlatformPostgres("file", "SELECT count(*) FROM files")).toBe(
      before,
    );
    const created = await post("/files/uploads/create", {
      name: "gateway-e2e.csv",
      content_type: "text/csv",
      size: payload.length,
    });
    expect(created.response.status(), JSON.stringify(created.body)).toBe(201);
    fileID = created.body.file.id;
    expect(
      queryPlatformPostgres(
        "file",
        `SELECT status||'|'||size FROM files WHERE id='${fileID}'`,
      ),
    ).toBe(`PENDING_UPLOAD|${payload.length}`);
    const oversized = await request.put(created.body.upload_url, {
      headers: { "Content-Type": "text/csv" },
      data: Buffer.concat([payload, Buffer.from("extra")]),
    });
    expect(oversized.status()).toBe(403);
    const upload = await request.put(created.body.upload_url, {
      headers: { "Content-Type": "text/csv" },
      data: payload,
    });
    expect(upload.status(), await upload.text()).toBeLessThan(300);
    const confirmed = await post("/files/uploads/confirm", { file_id: fileID });
    expect(confirmed.response.status(), JSON.stringify(confirmed.body)).toBe(
      200,
    );
    expect(
      queryPlatformPostgres(
        "file",
        `SELECT status FROM files WHERE id='${fileID}'`,
      ),
    ).toBe("UPLOADED");
    expect(
      (
        await post("/files/link", {
          file_id: fileID,
          resource_type: "e2e",
          resource_id: resourceID,
        })
      ).response.status(),
    ).toBe(403);
    expect(
      queryPlatformPostgres(
        "file",
        `SELECT status FROM files WHERE id='${fileID}'`,
      ),
    ).toBe("UPLOADED");
    const listed = await post("/files/list", {
      resource_type: "e2e",
      resource_id: resourceID,
    });
    expect(listed.response.status()).toBe(200);
    expect(listed.body.files).toEqual([]);
    const download = await post("/files/download-url", { file_id: fileID });
    expect(download.response.status(), JSON.stringify(download.body)).toBe(200);
    const bytes = await request.get(download.body.download_url);
    expect(bytes.status()).toBe(200);
    expect(await bytes.body()).toEqual(payload);
    expect(
      (await post("/files/delete", { file_id: fileID })).response.status(),
    ).toBe(200);
    expect(
      queryPlatformPostgres(
        "file",
        `SELECT status FROM files WHERE id='${fileID}'`,
      ),
    ).toBe("DELETED");
    expect(
      (
        await post("/files/download-url", { file_id: fileID })
      ).response.status(),
    ).toBe(404);
  });
});
