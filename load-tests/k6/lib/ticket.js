import { SharedArray } from 'k6/data';
import { env, requireEnv, runID } from './config.js';

const tokens = new SharedArray('ticket load-test tokens', () => {
  return env('ACCESS_TOKENS', env('ACCESS_TOKEN')).split(/[\s,;]+/).filter(Boolean);
});

const ticketIDs = new SharedArray('ticket ids', () => env('TICKET_IDS', env('TICKET_ID')).split(/[\s,;]+/).filter(Boolean));

export function tokenForVU() {
  if (tokens.length === 0) throw new Error('ACCESS_TOKEN or ACCESS_TOKENS is required');
  return tokens[(__VU - 1) % tokens.length];
}
export function ticketForIteration() {
  if (ticketIDs.length === 0) throw new Error('TICKET_ID or TICKET_IDS is required');
  return ticketIDs[(__VU + __ITER) % ticketIDs.length];
}

export function ticketHeaders(write = false) {
  const headers = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${tokenForVU()}`,
    'X-Load-Test-Run-ID': runID,
  };
  if (write) headers['Idempotency-Key'] = `${runID}-${__VU}-${__ITER}`;
  const clientPool = Number(env('CLIENT_IP_POOL_SIZE', '0'));
  if (clientPool > 0) {
    const index = ((__VU * 104729 + __ITER) % clientPool) + 1;
    headers['X-Forwarded-For'] = `198.18.${Math.floor(index / 254) % 254}.${(index % 254) + 1}`;
  }
  if (env('HOST_HEADER')) headers.Host = env('HOST_HEADER');
  return { headers, tags: { endpoint_type: write ? 'write' : 'read' } };
}

export function createBody() {
  const latitude = Number(env('TICKET_LATITUDE', '55.7558'));
  const longitude = Number(env('TICKET_LONGITUDE', '37.6173'));
  return {
    department_id: requireEnv('DEPARTMENT_ID'),
    category_id: requireEnv('CATEGORY_ID'),
    title: `load-test-${runID}-${__VU}-${__ITER}`,
    description: `controlled load test ${runID}; safe prefix load-test-`,
    priority: env('TICKET_PRIORITY', 'MEDIUM'),
    address: env('TICKET_ADDRESS', 'load-test-address'),
    latitude,
    longitude,
  };
}
