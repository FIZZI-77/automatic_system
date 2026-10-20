import { expect, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { gatewayUrl } from "./support/environment";
import { bearer, createEphemeralAccount, deleteEphemeralAccount, type EphemeralAccount } from "./support/ephemeral-auth";
import { publishNotification, queryPlatformPostgres } from "./support/cluster-storage";

test.describe("Notifications API и WebSocket", () => {
  test.skip(process.env.E2E_STORAGE_ASSERTIONS !== "1", "Нужен доступ kubectl к тестовому кластеру");
  let admin: EphemeralAccount; let profileID = ""; let deviceID = ""; let templateID = "";
  const notificationIDs = [randomUUID(), randomUUID()]; const deliveryID = randomUUID(); const eventType = `gateway.e2e.${randomUUID()}`;
  test.beforeAll(async ({ request }) => {
    admin = await createEphemeralAccount(request, "admin"); profileID = queryPlatformPostgres("profile_db", `SELECT id FROM user_profiles WHERE user_id='${admin.userID}'`);
    queryPlatformPostgres("notification", `
      INSERT INTO notifications(id,event_id,user_id,event_type,title,body,data) VALUES
      ('${notificationIDs[0]}','e2e-${notificationIDs[0]}','${admin.userID}','gateway.e2e','First','Body','{}'),
      ('${notificationIDs[1]}','e2e-${notificationIDs[1]}','${admin.userID}','gateway.e2e','Second','Body','{}');
      INSERT INTO deliveries(id,notification_id,channel,recipient,status,title,body) VALUES('${deliveryID}','${notificationIDs[0]}','EMAIL','e2e@city.local','SENT','First','Body');
    `);
  });
  test.afterAll(() => {
    queryPlatformPostgres("notification", `DELETE FROM deliveries WHERE id='${deliveryID}'; DELETE FROM notifications WHERE id IN ('${notificationIDs[0]}','${notificationIDs[1]}'); DELETE FROM devices WHERE user_id='${admin?.userID}'; DELETE FROM notification_preferences WHERE user_id='${admin?.userID}'; DELETE FROM notification_templates WHERE event_type='${eventType}'`);
    if (profileID) queryPlatformPostgres("profile_db", `DELETE FROM outbox_events WHERE aggregate_id='${profileID}'; DELETE FROM user_profiles WHERE id='${profileID}'`);
    if (admin) deleteEphemeralAccount(admin);
  });
  test("list/read/read-all/preferences/devices/templates/deliveries и live message", async ({ request }) => {
    const post = async (path: string, data: unknown = {}) => { const response = await request.post(`${gatewayUrl}${path}`, { headers: bearer(admin.token), data }); const body = await response.json().catch(() => ({})); return { response, body }; };
    const listed = await post("/notifications/list", { unread_only: true, limit: 20, offset: 0 }); expect(listed.response.status()).toBe(200); expect(listed.body.notifications.length).toBeGreaterThanOrEqual(2);
    const missing = await post("/notifications/read", { notification_id: randomUUID() }); expect(missing.response.status()).toBe(404);
    expect((await post("/notifications/read", { notification_id: notificationIDs[0] })).response.status()).toBe(200);
    expect(queryPlatformPostgres("notification", `SELECT read FROM notifications WHERE id='${notificationIDs[0]}'`)).toBe("t");
    expect((await post("/notifications/read-all", {})).response.status()).toBe(200);
    expect(queryPlatformPostgres("notification", `SELECT count(*) FROM notifications WHERE user_id='${admin.userID}' AND NOT read`)).toBe("0");
    expect((await post("/notifications/preferences/get", {})).response.status()).toBe(200);
    const preferences = await post("/notifications/preferences/update", { in_app_enabled: true, push_enabled: false, email_enabled: true, sms_enabled: true, email: "e2e@city.local", phone: "+79990000000" }); expect(preferences.response.status(), JSON.stringify(preferences.body)).toBe(200);
    expect(queryPlatformPostgres("notification", `SELECT push_enabled||'|'||sms_enabled||'|'||email FROM notification_preferences WHERE user_id='${admin.userID}'`)).toBe("false|true|e2e@city.local");
    const beforeDevices = queryPlatformPostgres("notification", `SELECT count(*) FROM devices WHERE user_id='${admin.userID}'`);
    expect([400, 409, 500]).toContain((await post("/notifications/devices/register", { token: `bad-${randomUUID()}`, platform: "desktop" })).response.status());
    expect(queryPlatformPostgres("notification", `SELECT count(*) FROM devices WHERE user_id='${admin.userID}'`)).toBe(beforeDevices);
    const device = await post("/notifications/devices/register", { token: `e2e-${randomUUID()}`, platform: "web" }); expect(device.response.status(), JSON.stringify(device.body)).toBe(201); deviceID = device.body.device.id;
    expect(queryPlatformPostgres("notification", `SELECT active FROM devices WHERE id='${deviceID}'`)).toBe("t");
    expect((await post("/notifications/devices/delete", { device_id: deviceID })).response.status()).toBe(200);
    expect(queryPlatformPostgres("notification", `SELECT active FROM devices WHERE id='${deviceID}'`)).toBe("f");
    const template = await post("/notifications/templates/upsert", { event_type: eventType, channel: "email", subject: "E2E", body: "Hello {{ticket_id}}", active: true }); expect(template.response.status(), JSON.stringify(template.body)).toBe(200); templateID = template.body.template.id;
    expect(queryPlatformPostgres("notification", `SELECT channel||'|'||active FROM notification_templates WHERE id='${templateID}'`)).toBe("EMAIL|true");
    expect((await post("/notifications/templates/list", { event_type: eventType, channel: "email", limit: 20, offset: 0 })).response.status()).toBe(200);
    const deliveries = await post("/notifications/deliveries/list", { status: "sent", channel: "email", limit: 20, offset: 0 }); expect(deliveries.response.status()).toBe(200); expect(deliveries.body.deliveries.some((item: { id: string }) => item.id === deliveryID)).toBe(true);

    const wsURL = gatewayUrl.replace(/^http/, "ws") + `/notifications/ws?access_token=${encodeURIComponent(admin.token)}`;
    const payload = JSON.stringify({ type: "gateway.e2e", notification_id: notificationIDs[0] });
    const received = new Promise<string>((resolve, reject) => {
      const socket = new WebSocket(wsURL);
      const timer = setTimeout(() => { socket.close(); reject(new Error("WebSocket message timeout")); }, 10_000);
      socket.addEventListener("open", () => publishNotification(admin.userID, payload));
      socket.addEventListener("message", (event) => { clearTimeout(timer); socket.close(); resolve(String(event.data)); });
      socket.addEventListener("error", () => { clearTimeout(timer); reject(new Error("WebSocket connection failed")); });
    });
    expect(await received).toBe(payload);
  });
});
