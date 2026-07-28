import http from "k6/http";
import { check, sleep } from "k6";

const baseUrl = __ENV.BASE_URL || "http://api-gateway:8081";
const hostname = (__ENV.HOSTNAME || "local").toLowerCase().replace(/[^a-z0-9-]/g, "");
const password = __ENV.K6_USER_PASSWORD || "Password123!";
const sleepSeconds = Number(__ENV.K6_SLEEP_SECONDS || "1");
const includeBusiness = (__ENV.K6_INCLUDE_BUSINESS || "false").toLowerCase() === "true";
const includeRestricted = (__ENV.K6_INCLUDE_RESTRICTED || "false").toLowerCase() === "true";

export const options = {
  vus: Number(__ENV.K6_VUS || "1"),
  duration: __ENV.K6_DURATION || "2m",
  thresholds: {
    http_req_failed: ["rate<0.05"],
    http_req_duration: ["p(95)<1000"],
  },
};

function jsonHeaders(token) {
  const headers = {
    "Content-Type": "application/json",
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  return headers;
}

export function setup() {
  const random = Math.random().toString(36).slice(2, 10);
  const unique = `${hostname}-${Date.now()}-${random}`;
  const email = `k6-${unique}@load.local`;
  const username = `k6-${unique}`.slice(0, 50);

  const registerRes = http.post(
    `${baseUrl}/auth/register`,
    JSON.stringify({
      email,
      password,
      username,
    }),
    { headers: jsonHeaders() },
  );

  check(registerRes, {
    "register created or already exists": (res) => res.status === 201 || res.status === 409,
  });
  if (registerRes.status !== 201 && registerRes.status !== 409) {
    console.error(`register failed: status=${registerRes.status} body=${registerRes.body}`);
  }

  const loginRes = http.post(
    `${baseUrl}/auth/login`,
    JSON.stringify({
      email,
      password,
      client_id: `k6-${hostname}`,
    }),
    { headers: jsonHeaders() },
  );

  check(loginRes, {
    "login ok": (res) => res.status === 200,
  });
  if (loginRes.status !== 200) {
    console.error(`login failed: status=${loginRes.status} body=${loginRes.body}`);
  }

  return {
    email,
    token: loginRes.json("access_token"),
  };
}

export default function (user) {
  const headers = jsonHeaders(user.token);

  const requests = [
    ["GET", `${baseUrl}/health`, null, { headers: jsonHeaders() }],
    ["GET", `${baseUrl}/auth/me`, null, { headers }],
  ];

  if (includeBusiness) {
    requests.push(
      ["POST", `${baseUrl}/tickets/list`, JSON.stringify({ limit: 20, offset: 0 }), { headers }],
      ["POST", `${baseUrl}/departments/list`, JSON.stringify({ limit: 20, offset: 0 }), { headers }],
      ["POST", `${baseUrl}/ticket-categories/list`, JSON.stringify({ limit: 20, offset: 0 }), { headers }],
    );
    if (includeRestricted) {
      requests.push(
        ["POST", `${baseUrl}/brigades/list`, JSON.stringify({ limit: 20, offset: 0 }), { headers }],
      );
    }
  }

  const responses = http.batch(requests);

  check(responses[0], { "health ok": (res) => res.status === 200 });
  check(responses[1], { "me ok": (res) => res.status === 200 });

  if (includeBusiness) {
    check(responses[2], { "tickets list ok": (res) => res.status === 200 });
    check(responses[3], { "departments list ok": (res) => res.status === 200 });
    check(responses[4], { "categories list ok": (res) => res.status === 200 });
    if (includeRestricted) {
      check(responses[5], { "brigades list forbidden for user": (res) => res.status === 403 });
    }
  }

  sleep(sleepSeconds);
}
