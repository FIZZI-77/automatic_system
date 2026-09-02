import { arrivalScenarios, standardThresholds } from '../lib/config.js';
import { request } from '../lib/http.js';
import { createBody, ticketForIteration, ticketHeaders } from '../lib/ticket.js';

export const options = { scenarios: arrivalScenarios('workload', 'mixed'), thresholds: standardThresholds(300, 1000) };
export function workload() {
  const selector = (__VU * 31 + __ITER) % 100;
  if (selector < 55) request('POST', '/tickets/list', { limit: 50, sort_by: 'created_at', sort_order: 'desc' }, ticketHeaders());
  else if (selector < 85) request('POST', '/tickets/get', { ticket_id: ticketForIteration() }, ticketHeaders());
  else request('POST', '/tickets/create', createBody(), ticketHeaders(true));
}
