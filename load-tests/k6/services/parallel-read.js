import { arrivalScenarios, env, requireEnv } from '../lib/config.js';
import { authToken } from '../lib/auth.js';
import { request, jsonHeaders } from '../lib/http.js';

const services = [
  'auth', 'ticket', 'file', 'sla', 'notification', 'audit', 'analytics',
  'report', 'asset', 'department', 'brigade', 'location', 'routing',
  'dispatch', 'profile',
];

const scenarios = {};
const thresholds = {};
for (const service of services) {
  Object.assign(scenarios, arrivalScenarios(`${service}Workload`, service));
  thresholds[`http_req_failed{phase:measurement,service:${service}}`] = ['rate<0.001'];
  thresholds[`http_req_duration{phase:measurement,service:${service}}`] = ['p(95)<1000'];
  for (const rate of env('K6_RATES', env('K6_RATE', '3')).split(',')) {
    thresholds[`http_req_failed{phase:measurement,service:${service},load_stage:${rate}}`] = ['rate<0.001'];
    thresholds[`http_req_duration{phase:measurement,service:${service},load_stage:${rate}}`] = ['p(95)<1000'];
  }
}

export const options = { scenarios, thresholds };

export function setup() {
  return {
    token: authToken(),
    ticket: requireEnv('TICKET_ID'),
    brigade: requireEnv('BRIGADE_ID'),
  };
}

function params(data, service) {
  const result = jsonHeaders(data.token);
  result.tags = { service };
  return result;
}

function post(data, service, path, body = { limit: 20 }) {
  request('POST', path, body, params(data, service));
}

export function authWorkload(data) { request('GET', '/auth/me', null, params(data, 'auth')); }
export function ticketWorkload(data) { post(data, 'ticket', '/tickets/list'); }
export function fileWorkload(data) { post(data, 'file', '/files/list', { resource_type: 'ticket', resource_id: data.ticket }); }
export function slaWorkload(data) { post(data, 'sla', '/sla/rules/list'); }
export function notificationWorkload(data) { post(data, 'notification', '/notifications/list'); }
export function auditWorkload(data) { post(data, 'audit', '/audit/list'); }
export function analyticsWorkload(data) { post(data, 'analytics', '/analytics/tickets/overview', {}); }
export function reportWorkload(data) { post(data, 'report', '/reports/list'); }
export function assetWorkload(data) { post(data, 'asset', '/assets/list'); }
export function departmentWorkload(data) { post(data, 'department', '/departments/list'); }
export function brigadeWorkload(data) { post(data, 'brigade', '/brigades/list'); }
export function locationWorkload(data) { post(data, 'location', '/locations/current-batch', { brigade_ids: [data.brigade], allow_stale: true }); }
export function routingWorkload(data) { post(data, 'routing', '/routing/list'); }
export function dispatchWorkload(data) { post(data, 'dispatch', '/dispatch/list'); }
export function profileWorkload(data) { post(data, 'profile', '/user-profiles/list'); }
