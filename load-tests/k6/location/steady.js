import { arrivalScenarios, standardThresholds, requireEnv } from '../lib/config.js';
import { authToken } from '../lib/auth.js';
import { deterministicUUID } from '../lib/data.js';
import { request, jsonHeaders } from '../lib/http.js';
export const options = { scenarios: arrivalScenarios(), thresholds: standardThresholds(20, 50) };
export function setup() { return { token: authToken(), brigade: requireEnv('BRIGADE_ID'), vehicle: requireEnv('VEHICLE_ID') }; }
export function workload(data) { const sequence = __VU * 100000000 + __ITER + 1; request('POST', '/locations/record', { event_id: deterministicUUID(sequence), event_version: 1, occurred_at: new Date().toISOString(), device_id: `k6-${__VU}`, vehicle_id: data.vehicle, brigade_id: data.brigade, sequence, latitude: 55.75, longitude: 37.61, speed_kmh: 20, heading: 90, accuracy_meters: 5, simulated: true }, jsonHeaders(data.token)); }
