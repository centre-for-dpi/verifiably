// k6 — wallet-api horizontal-scale smoke test (Phase 6.2).
//
// Goal: detect whether wallet-api tolerates round-robin load balancing
// across replicas, OR whether sessions/keys break when a request hits a
// different pod than the one that created the wallet.
//
// Run against:
//   1. wallet-api with replicas=1 (baseline)
//   2. wallet-api with replicas=3 (under round-robin Service)
//   Compare the two results — same success rate? same p99? Or does the
//   3-replica run show 4xx/5xx spikes from cross-pod state mismatches?
//
// Usage:
//   k6 run --env BASE_URL=https://wallet.verifiably.local \
//          --env VUS=50 --env DURATION=2m \
//          deploy/k8s/test/load/wallet-scale.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:7001';
const VUS = Number.parseInt(__ENV.VUS || '50', 10);
const DURATION = __ENV.DURATION || '2m';

export const options = {
  scenarios: {
    wallet_lifecycle: {
      executor: 'ramping-vus',
      startVUs: 5,
      stages: [
        { duration: '20s', target: VUS },
        { duration: DURATION, target: VUS },
        { duration: '20s', target: 0 },
      ],
      gracefulRampDown: '10s',
    },
  },
  thresholds: {
    http_req_failed:   ['rate<0.02'],   // < 2% errors
    http_req_duration: ['p(95)<2000'],  // p95 < 2s
  },
};

const cross_pod_drift = new Rate('cross_pod_drift');
const session_failures = new Counter('session_failures');

export default function () {
  // Stage 1: register a wallet.
  const email = `lt-${__VU}-${__ITER}@test.local`;
  const reg = http.post(`${BASE_URL}/wallet-api/auth/register`,
    JSON.stringify({ name: 'lt', email, password: 'tester1234' }),
    { headers: { 'content-type': 'application/json' }, tags: { op: 'register' } });

  if (!check(reg, { 'register 200/201': r => [200, 201].includes(r.status) })) {
    session_failures.add(1);
    return;
  }
  const token = reg.json('token');

  // Stage 2: list wallets — this is the call most likely to surface
  // cross-pod state if the registration landed on a different pod than
  // this list call.
  const list = http.get(`${BASE_URL}/wallet-api/wallet/wallets`,
    { headers: { authorization: `Bearer ${token}` }, tags: { op: 'list' } });

  if (list.status === 401 || list.status === 403) {
    cross_pod_drift.add(1);
    session_failures.add(1);
  } else {
    cross_pod_drift.add(0);
  }
  check(list, { 'list 200': r => r.status === 200 });

  sleep(1);
}
