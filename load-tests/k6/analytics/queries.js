import { arrivalScenarios, standardThresholds } from '../lib/config.js';
import { authToken } from '../lib/auth.js';
import { request, jsonHeaders } from '../lib/http.js';
export const options = { scenarios: arrivalScenarios(), thresholds: standardThresholds(1000, 2000) };
export function setup() { return { token: authToken() }; }
export function workload(data) { const routes = ['/analytics/tickets/overview', '/analytics/sla/summary', '/analytics/tickets/daily', '/analytics/assets/summary']; request('POST', routes[__ITER % routes.length], {}, jsonHeaders(data.token)); }
