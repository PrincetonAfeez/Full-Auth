# Load / Capacity Testing

`k6.js` exercises the core read/auth path (login page, `/api/v1/auth/status/`, `/readyz`) with a
ramping VU profile, and asserts the §26 latency SLOs as k6 thresholds.

```
BASE_URL=http://localhost:8000 k6 run loadtest/k6.js
```

To load-test the **authenticated** path, seed users first (`bootstrap_genesis` or a fixtures
script), then extend the scenario to POST `/login/` with CSRF and drive `/api/v1/me/`.

Record the peak sustained RPS and p95 latencies in the capacity notes when validating a release.
