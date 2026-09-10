export function env(name, fallback = '') { return __ENV[name] === undefined ? fallback : __ENV[name]; }
export const baseURL = env('BASE_URL', 'http://localhost:8081').replace(/\/$/, '');
export const runID = env('K6_RUN_ID', `local-${Date.now()}`);
export const token = env('ACCESS_TOKEN');

export function requireEnv(name) {
  const value = env(name);
  if (!value) throw new Error(`${name} is required for this scenario`);
  return value;
}

function durationSeconds(value, name) {
  const match = /^(\d+(?:\.\d+)?)(ms|s|m|h)$/.exec(value);
  if (!match) throw new Error(`${name} must be a k6 duration such as 500ms, 30s, 3m, or 1h`);
  const multipliers = { ms: 0.001, s: 1, m: 60, h: 3600 };
  return Number(match[1]) * multipliers[match[2]];
}

export function arrivalScenarios(exec = 'workload', prefix = '') {
  const rates = env('K6_RATES', env('K6_RATE', '10')).split(',').map(Number);
  const warmup = env('K6_WARMUP', '30s');
  const measure = env('K6_MEASUREMENT', '3m');
  const stabilize = env('K6_STABILIZATION', '15s');
  const warmupSeconds = durationSeconds(warmup, 'K6_WARMUP');
  const measurementSeconds = durationSeconds(measure, 'K6_MEASUREMENT');
  const stabilizationSeconds = durationSeconds(stabilize, 'K6_STABILIZATION');
  const segmentSeconds = Number(env('K6_SEGMENT_SECONDS', String(warmupSeconds + measurementSeconds + stabilizationSeconds)));
  if (!Number.isFinite(segmentSeconds) || segmentSeconds <= 0) throw new Error('K6_SEGMENT_SECONDS must be positive');
  if (segmentSeconds < warmupSeconds + measurementSeconds + stabilizationSeconds) throw new Error('K6_SEGMENT_SECONDS must fit warmup, measurement, and stabilization');
  const scenarios = {};
  rates.forEach((rate, index) => {
    if (!Number.isFinite(rate) || rate <= 0) throw new Error('K6_RATES must contain positive numbers');
    const scenarioPrefix = prefix ? `${prefix}_` : '';
    scenarios[`${scenarioPrefix}warmup_${index}`] = { executor: 'constant-arrival-rate', exec, rate, timeUnit: '1s', duration: warmup, preAllocatedVUs: Math.max(2, rate), maxVUs: Math.max(5, rate * 4), startTime: `${index * segmentSeconds}s`, tags: { phase: 'warmup', load_stage: String(rate), run_id: runID } };
    scenarios[`${scenarioPrefix}measure_${index}`] = { executor: 'constant-arrival-rate', exec, rate, timeUnit: '1s', duration: measure, preAllocatedVUs: Math.max(2, rate), maxVUs: Math.max(5, rate * 4), startTime: `${index * segmentSeconds + warmupSeconds}s`, tags: { phase: 'measurement', load_stage: String(rate), run_id: runID } };
    scenarios[`${scenarioPrefix}stabilize_${index}`] = { executor: 'constant-arrival-rate', exec, rate: Math.max(1, Math.floor(rate / 4)), timeUnit: '1s', duration: stabilize, preAllocatedVUs: Math.max(2, Math.ceil(rate / 4)), maxVUs: Math.max(5, rate), startTime: `${index * segmentSeconds + warmupSeconds + measurementSeconds}s`, tags: { phase: 'stabilization', load_stage: String(rate), run_id: runID } };
  });
  return scenarios;
}

export function standardThresholds(p95 = Number(env('P95_MS', '500')), p99 = Number(env('P99_MS', '1000'))) {
  const errorRate = env('ERROR_RATE_MAX', '0.001');
  const thresholds = {
    'http_req_failed{phase:measurement}': [`rate<${errorRate}`],
    'http_req_duration{phase:measurement}': [`p(95)<${p95}`, `p(99)<${p99}`],
  };
  env('K6_RATES', env('K6_RATE', '10')).split(',').forEach(rate => {
    thresholds[`http_req_failed{phase:measurement,load_stage:${rate}}`] = [`rate<${errorRate}`];
    thresholds[`http_req_duration{phase:measurement,load_stage:${rate}}`] = [`p(95)<${p95}`, `p(99)<${p99}`];
  });
  return thresholds;
}
