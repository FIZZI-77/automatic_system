import { arrivalScenarios, standardThresholds } from '../lib/config.js';
import { request, jsonHeaders } from '../lib/http.js';
export const options = {
    scenarios: arrivalScenarios(),
    thresholds: standardThresholds(),
    insecureSkipTLSVerify: true,
    summaryTrendStats: [
        "avg",
        "min",
        "med",
        "max",
        "p(90)",
        "p(95)",
        "p(99)"
    ]
};
export function workload() { request('GET', '/.well-known/jwks.json', null, jsonHeaders('')); }
