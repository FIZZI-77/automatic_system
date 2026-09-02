import { arrivalScenarios, standardThresholds, requireEnv } from '../lib/config.js';
import { authToken } from '../lib/auth.js';
import { request, jsonHeaders } from '../lib/http.js';
export const options = { scenarios: arrivalScenarios(), thresholds: standardThresholds(1000, 2000) };
export function setup() { return { token: authToken(), ticket: requireEnv('TICKET_ID') }; }
export function workload(data) { request('POST', '/dispatch/preview', { ticket_id: data.ticket, limit: Number(__ENV.CANDIDATE_COUNT || 10) }, jsonHeaders(data.token)); }
