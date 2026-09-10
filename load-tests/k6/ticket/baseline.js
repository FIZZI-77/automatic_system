import http from 'k6/http';
import { check } from 'k6';
import { arrivalScenarios, baseURL, standardThresholds } from '../lib/config.js';

export const options = { scenarios: arrivalScenarios('workload', 'baseline'), thresholds: standardThresholds(300, 1000) };
export function workload() {
  const response = http.get(`${baseURL}/health`, { tags: { endpoint_type: 'baseline' } });
  check(response, { 'health is 200': r => r.status === 200 });
}
