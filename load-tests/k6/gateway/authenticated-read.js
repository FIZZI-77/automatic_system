import { arrivalScenarios, standardThresholds } from '../lib/config.js';
import { authToken } from '../lib/auth.js';
import { request, jsonHeaders } from '../lib/http.js';
export const options = { scenarios: arrivalScenarios(), thresholds: standardThresholds() };
export function setup() { return { token: authToken() }; }
export function workload(data) { request('GET', '/auth/me', null, jsonHeaders(data.token)); }
