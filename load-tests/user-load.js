import http from "k6/http";
import { check, fail, sleep } from "k6";

const baseUrl = __ENV.BASE_URL || "http://api-gateway:8081";
const profile = (__ENV.K6_PROFILE || "load").toLowerCase();
const password = __ENV.K6_USER_PASSWORD || "Password123!";
const sleepSeconds = Number(__ENV.K6_SLEEP_SECONDS || "1");
const runID = (__ENV.K6_RUN_ID || `${Date.now()}`).replace(/[^a-zA-Z0-9-]/g, "");
let session = null;

const profiles = {
  smoke: {
    executor: "shared-iterations",
    vus: Number(__ENV.K6_VUS || "1"),
    iterations: Number(__ENV.K6_ITERATIONS || "1"),
    maxDuration: __ENV.K6_DURATION || "1m",
  },
  load: {
    executor: "ramping-vus",
    startVUs: 0,
    stages: [
      { duration: __ENV.K6_RAMP_UP || "30s", target: Number(__ENV.K6_VUS || "20") },
      { duration: __ENV.K6_DURATION || "2m", target: Number(__ENV.K6_VUS || "20") },
      { duration: __ENV.K6_RAMP_DOWN || "30s", target: 0 },
    ],
    gracefulRampDown: "15s",
  },
  rate: {
    executor: "constant-arrival-rate",
    rate: Number(__ENV.K6_RATE || "20"),
    timeUnit: __ENV.K6_RATE_TIME_UNIT || "1s",
    duration: __ENV.K6_DURATION || "2m",
    preAllocatedVUs: Number(__ENV.K6_PREALLOCATED_VUS || "20"),
    maxVUs: Number(__ENV.K6_MAX_VUS || "100"),
  },
  stress: {
    executor: "ramping-vus",
    startVUs: 0,
    stages: [
      { duration: "30s", target: Number(__ENV.K6_VUS || "25") },
      { duration: "1m", target: Number(__ENV.K6_STRESS_VUS || "50") },
      { duration: "1m", target: Number(__ENV.K6_MAX_VUS || "100") },
      { duration: "30s", target: 0 },
    ],
    gracefulRampDown: "15s",
  },
  spike: {
    executor: "ramping-vus",
    startVUs: 0,
    stages: [
      { duration: "10s", target: Number(__ENV.K6_VUS || "10") },
      { duration: "10s", target: Number(__ENV.K6_MAX_VUS || "100") },
      { duration: "30s", target: Number(__ENV.K6_MAX_VUS || "100") },
      { duration: "10s", target: 0 },
    ],
    gracefulRampDown: "10s",
  },
  soak: {
    executor: "constant-vus",
    vus: Number(__ENV.K6_VUS || "20"),
    duration: __ENV.K6_DURATION || "30m",
  },
};

if (!profiles[profile]) {
  throw new Error(`unknown K6_PROFILE=${profile}`);
}

export const options = {
  scenarios: { user_api: profiles[profile] },
  thresholds: {
    checks: ["rate>0.99"],
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<1000", "p(99)<2000"],
  },
};

function jsonHeaders(token) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

function ensureSession() {
  if (session) return session;

  const suffix = `${runID}-${__VU}`.toLowerCase();
  const email = `k6-${suffix}@load.local`;
  const username = `k6-${suffix}`.slice(0, 50);
  const register = http.post(`${baseUrl}/auth/register`, JSON.stringify({ email, password, username }), {
    headers: jsonHeaders(),
    tags: { operation: "auth_register" },
  });
  check(register, { "register accepted": (r) => r.status === 201 || r.status === 409 });

  const login = http.post(`${baseUrl}/auth/login`, JSON.stringify({
    email,
    password,
    client_id: `k6-vu-${__VU}`,
  }), { headers: jsonHeaders(), tags: { operation: "auth_login" } });
  if (!check(login, { "login ok": (r) => r.status === 200 })) {
    fail(`login failed: status=${login.status} body=${login.body}`);
  }
  session = { token: login.json("access_token") };
  return session;
}

export default function () {
  const current = ensureSession();
  const responses = http.batch([
    ["GET", `${baseUrl}/health`, null, { tags: { operation: "health" } }],
    ["GET", `${baseUrl}/auth/me`, null, { headers: jsonHeaders(current.token), tags: { operation: "auth_me" } }],
    ["POST", `${baseUrl}/departments/list`, JSON.stringify({ limit: 20, offset: 0 }), { headers: jsonHeaders(current.token), tags: { operation: "departments_list" } }],
    ["POST", `${baseUrl}/ticket-categories/list`, JSON.stringify({ limit: 20, offset: 0 }), { headers: jsonHeaders(current.token), tags: { operation: "categories_list" } }],
  ]);

  check(responses[0], { "health ok": (r) => r.status === 200 });
  check(responses[1], { "me ok": (r) => r.status === 200 });
  check(responses[2], { "departments list ok": (r) => r.status === 200 });
  check(responses[3], { "categories list ok": (r) => r.status === 200 });
  sleep(sleepSeconds);
}
