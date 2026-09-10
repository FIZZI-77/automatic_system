import http from "k6/http";
import { check, fail, sleep } from "k6";

const baseUrl = __ENV.BASE_URL || "http://api-gateway:8081";
const sleepSeconds = Number(__ENV.K6_SLEEP_SECONDS || "1");
const iterations = Number(__ENV.K6_ITERATIONS || "0");
const userOffset = Number(__ENV.K6_USER_OFFSET || "0");
const users = JSON.parse(open(__ENV.K6_USERS_FILE || "/scripts/users.json"));
let session = null;

const thresholds = {
  checks: ["rate>0.95"],
  http_req_failed: ["rate<0.05"],
  http_req_duration: ["p(95)<1500"],
};

export const options = iterations > 0 ? {
  vus: Number(__ENV.K6_VUS || "1"),
  iterations: iterations,
  thresholds: thresholds,
} : {
  vus: Number(__ENV.K6_VUS || "1"),
  duration: __ENV.K6_DURATION || "2m",
  thresholds: thresholds,
};

function pickUser() {
  return users[(userOffset + __VU - 1) % users.length];
}

function headers(token, extra = {}) {
  const result = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
  Object.keys(extra).forEach((key) => {
    result[key] = extra[key];
  });
  return result;
}

function post(path, body, token, expected, extraHeaders = {}) {
  const res = http.post(`${baseUrl}${path}`, JSON.stringify(body), {
    headers: headers(token, extraHeaders),
  });

  check(res, {
    [`${path} ${expected}`]: (r) => r.status === expected,
  });

  if (res.status !== expected) {
    console.error(`${path} failed: status=${res.status} body=${res.body}`);
  }

  return res;
}

function get(path, token, expected) {
  const res = http.get(`${baseUrl}${path}`, {
    headers: headers(token),
  });

  check(res, {
    [`${path} ${expected}`]: (r) => r.status === expected,
  });

  if (res.status !== expected) {
    console.error(`${path} failed: status=${res.status} body=${res.body}`);
  }

  return res;
}

function json(res, path) {
  try {
    return res.json();
  } catch (err) {
    fail(`invalid JSON from ${path}: ${err}`);
  }
}

function idFrom(res, path, selector) {
  const value = selector(json(res, path));
  if (!value) {
    fail(`missing id from ${path}: ${res.body}`);
  }
  return value;
}

export function setup() {
  if (!Array.isArray(users) || users.length === 0) {
    fail("users.json is empty. Run load-tests/seed-business-users.ps1 first.");
  }
}

function ensureSession() {
  if (session) {
    return session;
  }

  const user = pickUser();

  const loginRes = http.post(
    `${baseUrl}/auth/login`,
    JSON.stringify({
      email: user.email,
      password: user.password,
      client_id: user.client_id || `k6-business-${__VU}`,
    }),
    { headers: { "Content-Type": "application/json" } },
  );
  check(loginRes, { "login ok": (r) => r.status === 200 });
  if (loginRes.status !== 200) {
    fail(`login failed: status=${loginRes.status} body=${loginRes.body}`);
  }

  const loginBody = json(loginRes, "/auth/login");
  const token = loginBody.access_token;
  const meRes = get("/auth/me", token, 200);
  session = {
    token: token,
    actorID: loginBody.user_id || meRes.json("user_id"),
  };
  return session;
}

export default function () {
  const currentSession = ensureSession();
  const token = currentSession.token;
  const actorID = currentSession.actorID;
  const unique = `${__VU}-${__ITER}-${Date.now()}`;

  get("/health", token, 200);

  const departmentRes = post("/departments/create", {
    name: `Load Department ${unique}`,
    description: "Created by k6 business flow",
  }, token, 201);
  const departmentID = idFrom(departmentRes, "/departments/create", (body) => body.department && body.department.id);

  post("/departments/get", { id: departmentID }, token, 200);
  post("/departments/list", { limit: 20, offset: 0, sort_by: "created_at", sort_order: "desc" }, token, 200);
  post("/departments/update", {
    id: departmentID,
    name: `Load Department ${unique} Updated`,
    description: "Updated by k6 business flow",
    status: "active",
  }, token, 200);

  const categoryRes = post("/ticket-categories/create", {
    code: `k6-${unique}`,
    name: `Load Category ${unique}`,
    description: "Created by k6 business flow",
  }, token, 201);
  const categoryID = idFrom(categoryRes, "/ticket-categories/create", (body) => body.category && body.category.id);

  post("/ticket-categories/get", { category_id: categoryID }, token, 200);
  post("/ticket-categories/list", { only_active: true, limit: 20, offset: 0 }, token, 200);
  post("/ticket-categories/update", {
    category_id: categoryID,
    name: `Load Category ${unique} Updated`,
    description: "Updated by k6 business flow",
    is_active: true,
  }, token, 200);

  const brigadeRes = post("/brigades/create", {
    department_id: departmentID,
    name: `Load Brigade ${unique}`,
    description: "Created by k6 business flow",
    specialization: "water",
  }, token, 201, { "X-Actor-Department-ID": departmentID });
  const brigadeID = idFrom(brigadeRes, "/brigades/create", (body) => body.brigade && body.brigade.id);

  post("/brigades/get", { id: brigadeID }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigades/list", { department_id: departmentID, limit: 20, offset: 0 }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigades/update", {
    id: brigadeID,
    name: `Load Brigade ${unique} Updated`,
    description: "Updated by k6 business flow",
    specialization: "water_repair",
  }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigades/status-history", { brigade_id: brigadeID, limit: 20, offset: 0 }, token, 200, { "X-Actor-Department-ID": departmentID });

  const memberRes = post("/brigade-members/add", {
    brigade_id: brigadeID,
    user_id: actorID,
    role: "lead",
    changed_by_user_id: actorID,
  }, token, 201, { "X-Actor-Department-ID": departmentID });
  const memberID = idFrom(memberRes, "/brigade-members/add", (body) => body.member && body.member.id);

  post("/brigade-members/list", { brigade_id: brigadeID, active: true, limit: 20, offset: 0 }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigade-members/change-role", {
    brigade_id: brigadeID,
    member_id: memberID,
    role: "driver",
    changed_by_user_id: actorID,
  }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigade-members/set-availability", {
    brigade_id: brigadeID,
    member_id: memberID,
    status: "available",
    reason: "k6 availability",
    changed_by_user_id: actorID,
  }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigade-members/history", { brigade_id: brigadeID, member_id: memberID, limit: 20, offset: 0 }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigade-members/status-history", { brigade_id: brigadeID, member_id: memberID, limit: 20, offset: 0 }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigades/get-by-user", { user_id: actorID, only_active: true }, token, 200, { "X-Actor-Department-ID": departmentID });

  const skillRes = post("/skills/create", {
    code: `skill-${unique}`,
    name: `Load Skill ${unique}`,
    description: "Created by k6 business flow",
  }, token, 201);
  const skillID = idFrom(skillRes, "/skills/create", (body) => body.skill && body.skill.id);

  post("/skills/list", { active: true, limit: 20, offset: 0 }, token, 200);
  post("/skills/update", {
    id: skillID,
    name: `Load Skill ${unique} Updated`,
    description: "Updated by k6 business flow",
    active: true,
  }, token, 200);
  post("/brigade-skills/add", { brigade_id: brigadeID, skill_id: skillID }, token, 201, { "X-Actor-Department-ID": departmentID });
  post("/brigade-skills/list", { brigade_id: brigadeID, active: true }, token, 200, { "X-Actor-Department-ID": departmentID });

  post("/brigade-schedules/set", {
    brigade_id: brigadeID,
    items: [1, 2, 3, 4, 5, 6, 7].map(function (day) {
      return {
        day_of_week: day,
        starts_at: "00:00",
        ends_at: "23:59",
        timezone: "Europe/Moscow",
      };
    }),
  }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigade-schedules/list", { brigade_id: brigadeID, active: true }, token, 200, { "X-Actor-Department-ID": departmentID });

  const geoJSON = JSON.stringify({
    type: "Polygon",
    coordinates: [[
      [37.50, 55.70],
      [37.80, 55.70],
      [37.80, 55.90],
      [37.50, 55.90],
      [37.50, 55.70],
    ]],
  });
  const zoneRes = post("/brigade-zones/create", {
    brigade_id: brigadeID,
    department_id: departmentID,
    name: `Load Zone ${unique}`,
    geo_json: geoJSON,
    priority: 1,
  }, token, 201, { "X-Actor-Department-ID": departmentID });
  const zoneID = idFrom(zoneRes, "/brigade-zones/create", (body) => body.zone && body.zone.id);

  post("/brigade-zones/list", { brigade_id: brigadeID, active: true }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigade-zones/covers-point", { brigade_id: brigadeID, longitude: 37.6173, latitude: 55.7558 }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigade-zones/find-by-point", {
    department_id: departmentID,
    longitude: 37.6173,
    latitude: 55.7558,
    only_available: false,
    required_skill_ids: [],
    required_roles: [],
    limit: 20,
    offset: 0,
  }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigade-zones/update", {
    id: zoneID,
    name: `Load Zone ${unique} Updated`,
    geo_json: geoJSON,
    priority: 2,
    active: true,
  }, token, 200, { "X-Actor-Department-ID": departmentID });

  post("/brigades/set-status", {
    brigade_id: brigadeID,
    status: "active",
    reason: "k6 activation",
    changed_by_user_id: actorID,
  }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigades/set-status", {
    brigade_id: brigadeID,
    status: "available",
    reason: "k6 availability",
    changed_by_user_id: actorID,
  }, token, 200, { "X-Actor-Department-ID": departmentID });

  const ticketRes = post("/tickets/create", {
    department_id: departmentID,
    category_id: categoryID,
    title: `Load Ticket ${unique}`,
    description: "Created by k6 business flow",
    priority: "medium",
    address: "Moscow center",
    latitude: 55.7558,
    longitude: 37.6173,
  }, token, 201);
  const ticketID = idFrom(ticketRes, "/tickets/create", (body) => body.ticket && body.ticket.id);

  post("/tickets/get", { ticket_id: ticketID }, token, 200);
  post("/tickets/list", { department_id: departmentID, limit: 20, offset: 0 }, token, 200);
  post("/tickets/update", {
    ticket_id: ticketID,
    title: `Load Ticket ${unique} Updated`,
    description: "Updated by k6 business flow",
    priority: "high",
    address: "Moscow center updated",
    latitude: 55.756,
    longitude: 37.618,
  }, token, 200);
  post("/tickets/assign-brigade", {
    ticket_id: ticketID,
    brigade_id: brigadeID,
    comment: "Assigned by k6",
  }, token, 200);
  post("/tickets/change-status", {
    ticket_id: ticketID,
    new_status: "in_progress",
    comment: "Started by k6",
  }, token, 200);
  post("/tickets/status-history", { ticket_id: ticketID, limit: 20, offset: 0 }, token, 200);
  post("/tickets/complete", { ticket_id: ticketID, comment: "Completed by k6" }, token, 200);

  const cancelTicketRes = post("/tickets/create", {
    department_id: departmentID,
    category_id: categoryID,
    title: `Load Cancel Ticket ${unique}`,
    description: "Created by k6 business flow",
    priority: "low",
    address: "Moscow center",
    latitude: 55.7558,
    longitude: 37.6173,
  }, token, 201);
  const cancelTicketID = idFrom(cancelTicketRes, "/tickets/create cancel", (body) => body.ticket && body.ticket.id);
  post("/tickets/cancel", { ticket_id: cancelTicketID, reason: "Canceled by k6" }, token, 200);

  post("/brigades/available", {
    department_id: departmentID,
    longitude: 37.6173,
    latitude: 55.7558,
    required_skill_ids: [],
    required_roles: [],
    limit: 20,
    offset: 0,
  }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigades/can-handle-ticket", {
    brigade_id: brigadeID,
    department_id: departmentID,
    longitude: 37.6173,
    latitude: 55.7558,
    required_skill_ids: [],
    required_roles: [],
  }, token, 200, { "X-Actor-Department-ID": departmentID });

  post("/brigades/deactivate", { id: brigadeID, reason: "Deactivated by k6", changed_by_user_id: actorID }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigade-zones/delete", { id: zoneID }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigade-skills/remove", { brigade_id: brigadeID, skill_id: skillID }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/brigade-members/remove", {
    brigade_id: brigadeID,
    member_id: memberID,
    reason: "Removed by k6",
    changed_by_user_id: actorID,
  }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/skills/deactivate", { id: skillID }, token, 200);
  post("/ticket-categories/delete", { category_id: categoryID }, token, 200);
  post("/brigades/archive", { id: brigadeID, reason: "Archived by k6", changed_by_user_id: actorID }, token, 200, { "X-Actor-Department-ID": departmentID });
  post("/departments/delete", { id: departmentID }, token, 200);

  sleep(sleepSeconds);
}
