import http from "k6/http";
import { check, fail, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

const baseURL = __ENV.BASE_URL || "http://api-gateway:8081";
const requestRate = Number(__ENV.K6_RATE || "20");
const preAllocatedVUs = Number(__ENV.K6_PREALLOCATED_VUS || "30");
const maxVUs = Number(__ENV.K6_MAX_VUS || "150");
const writePercent = Number(__ENV.K6_WRITE_PERCENT || "10");

const applicationFailures = new Rate("application_failures");
const businessDuration = new Trend("business_operation_duration", true);
const ticketsCreated = new Counter("tickets_created");

function arrivalScenario(startTime, duration, rate, phase) {
  return {
    executor: "constant-arrival-rate",
    exec: phase,
    startTime,
    duration,
    rate,
    timeUnit: "1s",
    preAllocatedVUs,
    maxVUs,
    gracefulStop: "15s",
    tags: { phase },
  };
}

export const options = {
  discardResponseBodies: true,
  scenarios: {
    warmup: arrivalScenario("0s", __ENV.K6_WARMUP_DURATION || "1m", Math.max(1, Math.ceil(requestRate / 4)), "warmup"),
    baseline: arrivalScenario(__ENV.K6_BASELINE_START || "1m", __ENV.K6_BASELINE_DURATION || "2m", requestRate, "baseline"),
    chaos: arrivalScenario(__ENV.K6_CHAOS_START || "3m", __ENV.K6_CHAOS_DURATION || "4m", requestRate, "chaos"),
    recovery: arrivalScenario(__ENV.K6_RECOVERY_START || "7m", __ENV.K6_RECOVERY_DURATION || "2m", requestRate, "recovery"),
  },
  thresholds: {
    "application_failures{phase:baseline}": ["rate<0.01"],
    "application_failures{phase:chaos}": ["rate<0.15"],
    "application_failures{phase:recovery}": ["rate<0.02"],
    "http_req_duration{phase:baseline}": ["p(95)<1000", "p(99)<2000"],
    "http_req_duration{phase:chaos}": ["p(95)<3000", "p(99)<5000"],
    "http_req_duration{phase:recovery}": ["p(95)<1500", "p(99)<3000"],
    "dropped_iterations": ["count<25"],
  },
};

function parseJSON(response, operation) {
  try {
    return response.json();
  } catch (error) {
    fail(`${operation}: invalid JSON: ${error}`);
  }
}

function login(email, password, clientID) {
  const response = http.post(`${baseURL}/auth/login`, JSON.stringify({
    email,
    password,
    client_id: clientID,
  }), {
    headers: { "Content-Type": "application/json", "X-Forwarded-For": "10.250.0.1" },
    responseType: "text",
    responseCallback: http.expectedStatuses(200),
    tags: { operation: "auth_login", phase: "setup" },
  });
  if (!check(response, { [`${clientID} login succeeds`]: (result) => result.status === 200 })) {
    fail(`${clientID} login failed: ${response.status} ${response.body}`);
  }
  return parseJSON(response, "auth/login").access_token;
}

function jsonHeaders(token) {
  const thirdOctet = Math.floor((__VU - 1) / 250) % 250;
  const fourthOctet = ((__VU - 1) % 250) + 1;
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    "X-Forwarded-For": `10.200.${thirdOctet}.${fourthOctet}`,
  };
}

function post(path, body, token, phase, expectedStatus, operation) {
  const response = http.post(`${baseURL}${path}`, JSON.stringify(body), {
    headers: jsonHeaders(token),
    responseType: phase === "setup" ? "text" : "none",
    responseCallback: http.expectedStatuses(expectedStatus),
    tags: { operation, phase },
    timeout: "10s",
  });
  const succeeded = response.status === expectedStatus;
  check(response, { [`${operation} ${expectedStatus}`]: () => succeeded }, { phase });
  applicationFailures.add(!succeeded, { phase, operation });
  return response;
}

export function setup() {
  const password = __ENV.K6_DEMO_PASSWORD || "CityDemo123!";
  const residentToken = login(__ENV.K6_RESIDENT_EMAIL || "demo.user@city.local", password, "k6-resident");
  const adminToken = login(__ENV.K6_ADMIN_EMAIL || "demo.admin@city.local", password, "k6-admin");

  const departments = post("/departments/list", { limit: 100, offset: 0 }, residentToken, "setup", 200, "departments_list");
  const categories = post("/ticket-categories/list", { only_active: true, limit: 100, offset: 0 }, residentToken, "setup", 200, "categories_list");
  const departmentList = parseJSON(departments, "departments/list").departments || [];
  const categoryList = parseJSON(categories, "ticket-categories/list").categories || [];
  const department = departmentList[0];
  const category = categoryList[0];
  if (!department || !department.id || !category || !category.id) {
    fail("Kubernetes load fixtures are missing. Run scripts/seed-demo-data.ps1 first.");
  }

  return {
    residentToken,
    adminToken,
    departmentID: department.id,
    categoryID: category.id,
  };
}

function workload(data, phase) {
  const startedAt = Date.now();
  const iteration = __ITER + __VU;
  const residentHeaders = jsonHeaders(data.residentToken);

  const requests = [
    ["GET", `${baseURL}/health`, null, {
      responseCallback: http.expectedStatuses(200),
      tags: { operation: "health", phase },
    }],
    ["POST", `${baseURL}/tickets/list`, JSON.stringify({ limit: 20, offset: 0 }), {
      headers: residentHeaders,
      responseCallback: http.expectedStatuses(200),
      tags: { operation: "tickets_list", phase },
    }],
    ["POST", `${baseURL}/departments/list`, JSON.stringify({ limit: 20, offset: 0 }), {
      headers: residentHeaders,
      responseCallback: http.expectedStatuses(200),
      tags: { operation: "departments_list", phase },
    }],
    ["POST", `${baseURL}/ticket-categories/list`, JSON.stringify({ only_active: true, limit: 20, offset: 0 }), {
      headers: residentHeaders,
      responseCallback: http.expectedStatuses(200),
      tags: { operation: "categories_list", phase },
    }],
  ];

  const names = ["health", "tickets_list", "departments_list", "categories_list"];
  if (iteration % 50 === 0) {
    requests.push(["GET", `${baseURL}/auth/me`, null, {
      headers: residentHeaders,
      responseCallback: http.expectedStatuses(200),
      tags: { operation: "auth_me", phase },
    }]);
    names.push("auth_me");
  }

  const responses = http.batch(requests);

  responses.forEach((response, index) => {
    const succeeded = response.status === 200;
    check(response, { [`${names[index]} succeeds`]: () => succeeded }, { phase });
    applicationFailures.add(!succeeded, { phase, operation: names[index] });
  });

  if (iteration % 20 === 0) {
    const unauthorized = http.get(`${baseURL}/auth/me`, {
      responseCallback: http.expectedStatuses(401),
      tags: { operation: "auth_me_unauthorized", phase },
    });
    const succeeded = unauthorized.status === 401;
    check(unauthorized, { "unauthorized request rejected": () => succeeded }, { phase });
    applicationFailures.add(!succeeded, { phase, operation: "auth_me_unauthorized" });
  }

  if (iteration % 100 < writePercent) {
    const unique = `${__VU}-${__ITER}-${Date.now()}`;
    const response = post("/tickets/create", {
      department_id: data.departmentID,
      category_id: data.categoryID,
      title: `k6 Kubernetes ${phase} ${unique}`,
      description: "Load and chaos test request",
      priority: "MEDIUM",
      address: "Москва, Тверская улица, 1",
      latitude: 55.757393,
      longitude: 37.613218,
    }, data.residentToken, phase, 201, "tickets_create");
    if (response.status === 201) {
      ticketsCreated.add(1, { phase });
    }
  }

  businessDuration.add(Date.now() - startedAt, { phase });
  sleep(0.1 + Math.random() * 0.4);
}

export function warmup(data) { workload(data, "warmup"); }
export function baseline(data) { workload(data, "baseline"); }
export function chaos(data) { workload(data, "chaos"); }
export function recovery(data) { workload(data, "recovery"); }
