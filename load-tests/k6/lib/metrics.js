import { Counter, Trend } from 'k6/metrics';
export const scenarioErrors = new Counter('capacity_scenario_errors');
export const scenarioLatency = new Trend('capacity_scenario_latency', true);
