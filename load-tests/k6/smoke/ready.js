import http from 'k6/http';
import { check } from 'k6';

export const options = {
  vus: 1,
  iterations: 1,
  thresholds: { checks: ['rate==1'] },
};

export default function () {
  const response = http.get(`${__ENV.BASE_URL}/readyz`);
  check(response, { 'Gateway is reachable from k6 container': value => value.status === 200 });
}
