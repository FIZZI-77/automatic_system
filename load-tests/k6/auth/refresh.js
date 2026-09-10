import { arrivalScenarios, standardThresholds, requireEnv } from '../lib/config.js';
import { request, jsonHeaders } from '../lib/http.js';
export const options = { scenarios: arrivalScenarios(), thresholds: standardThresholds() };
export function workload() { request('POST', '/auth/refresh', { refresh_token: requireEnv('REFRESH_TOKEN'), client_id: __ENV.CLIENT_ID || 'k6' }, jsonHeaders('')); }
