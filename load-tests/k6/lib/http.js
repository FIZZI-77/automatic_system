import http from 'k6/http';
import { check } from 'k6';
import { baseURL, runID, token } from './config.js';
import { scenarioErrors, scenarioLatency } from './metrics.js';

export function jsonHeaders(accessToken = token) {
  const headers = { 'Content-Type': 'application/json', 'X-Load-Test-Run-ID': runID };
  if (__ENV.HOST_HEADER) headers.Host = __ENV.HOST_HEADER;
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  return { headers };
}

export function request(method, path, body = null, params = {}) {
  const response = http.request(method, `${baseURL}${path}`, body === null ? null : JSON.stringify(body), params);
  scenarioLatency.add(response.timings.duration);
  const ok = check(response, { 'status is 2xx': r => r.status >= 200 && r.status < 300 });
  if (!ok) scenarioErrors.add(1);
  return response;
}
