import { arrivalScenarios, standardThresholds } from '../lib/config.js';
import { request } from '../lib/http.js';
import { createBody, ticketHeaders } from '../lib/ticket.js';

export const options = { scenarios: arrivalScenarios('workload', 'write'), thresholds: standardThresholds(300, 1000) };
export function workload() { request('POST', '/tickets/create', createBody(), ticketHeaders(true)); }
