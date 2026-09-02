import { arrivalScenarios, standardThresholds, requireEnv } from '../lib/config.js';
import { request, jsonHeaders } from '../lib/http.js';
export const options = { scenarios: arrivalScenarios(), thresholds: standardThresholds() };
export function workload() { request('POST', '/auth/login', { email: requireEnv('LOAD_USER_EMAIL'), password: requireEnv('LOAD_USER_PASSWORD'), client_id: __ENV.CLIENT_ID || 'k6' }, jsonHeaders('')); }
