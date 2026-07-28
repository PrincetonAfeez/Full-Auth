// Core-path load/capacity test for Full Auth.
// Run:  BASE_URL=http://localhost:8000 k6 run loadtest/k6.js
// Thresholds encode the SLOs from Full Auth.md §26 / runbooks/monitoring.md.
import http from "k6/http";
import { check, sleep } from "k6";

const BASE = __ENV.BASE_URL || "http://localhost:8000";

export const options = {
  scenarios: {
    core_path: {
      executor: "ramping-vus",
      startVUs: 1,
      stages: [
        { duration: "30s", target: 25 },
        { duration: "1m", target: 25 },
        { duration: "30s", target: 0 },
      ],
    },
  },
  thresholds: {
    // Availability + latency SLOs for read/auth surfaces.
    http_req_failed: ["rate<0.01"], // < 1% errors
    "http_req_duration{name:login_page}": ["p(95)<250"], // §26 login page p95 < 250ms
    "http_req_duration{name:auth_status}": ["p(95)<250"],
    "http_req_duration{name:readyz}": ["p(95)<100"], // §26 health/ready p95 < 100ms
  },
};

export default function () {
  const login = http.get(`${BASE}/login/`, { tags: { name: "login_page" } });
  check(login, { "login page 200": (r) => r.status === 200 });

  const status = http.get(`${BASE}/api/v1/auth/status/`, { tags: { name: "auth_status" } });
  check(status, { "auth status 200": (r) => r.status === 200 });

  const ready = http.get(`${BASE}/readyz`, { tags: { name: "readyz" } });
  check(ready, { "readyz 200": (r) => r.status === 200 });

  sleep(1);
}
