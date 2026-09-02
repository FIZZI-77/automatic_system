import { arrivalScenarios, standardThresholds } from '../lib/config.js';
import { request } from '../lib/http.js';
import { ticketForIteration, ticketHeaders } from '../lib/ticket.js';

export const options = { scenarios: arrivalScenarios('workload', 'read'), thresholds: standardThresholds(300, 1000) };
export function workload() {
  const selector = (__VU + __ITER) % 10;
  if (selector < 6) request('POST', '/tickets/list', { limit: 50, sort_by: 'created_at', sort_order: 'desc' }, ticketHeaders());
  else if (selector < 9) request('POST', '/tickets/get', { ticket_id: ticketForIteration() }, ticketHeaders());
  else request('POST', '/tickets/status-history', { ticket_id: ticketForIteration(), limit: 50 }, ticketHeaders());
}
