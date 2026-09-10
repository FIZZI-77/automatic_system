import { request, jsonHeaders } from './http.js';
import { requireEnv } from './config.js';
import { sleep } from 'k6';

export function login() {
  let status = 0;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const response = request('POST', '/auth/login', { email: requireEnv('LOAD_USER_EMAIL'), password: requireEnv('LOAD_USER_PASSWORD'), client_id: __ENV.CLIENT_ID || 'k6' }, jsonHeaders(''));
    status = response.status;
    if (status === 200) return response.json();
    if (attempt < 3) sleep(5);
  }
  throw new Error(`login failed after 3 attempts: ${status}`);
}

export function authToken() {
  if (__ENV.ACCESS_TOKEN) return __ENV.ACCESS_TOKEN;
  return login().access_token;
}
