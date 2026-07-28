# Runbook: Monitoring, Alerting & SLOs

## Endpoints
- `GET /healthz` — liveness (always 200 if the process is up).
- `GET /readyz` — readiness: checks Postgres (`SELECT 1`) and Redis; 503 if either is down. Point
  the uptime monitor and the load balancer health check here.
- `GET /metrics` — Prometheus text exposition (bearer-token guarded via `METRICS_TOKEN`):
  `fa_active_sessions`, `fa_open_risk_events`, `fa_outbox_dead_letter`, `fa_outbox_oldest_pending_seconds`.

## Uptime monitoring (must alert a human)
Configure an external monitor (e.g. hosted uptime check / Prometheus blackbox) to poll `/readyz`
every 60s from at least one off-host location and page on-call after 2 consecutive failures.

## Error tracking
Set `SENTRY_DSN` to capture exceptions (init is guarded in `config/settings.py`). All logs are
structured and carry the request id (`config/middleware.RequestIDMiddleware`) for correlation.

## SLOs (targets from Full Auth.md §26)
| Signal | Target |
|---|---|
| Availability (`/readyz` success) | 99.9% monthly |
| Login p95 latency | < 250 ms |
| Enforcement-middleware p95 overhead | < 20 ms |
| Password/2FA verification p95 | < 300 ms |

## Caching & invalidation strategy
The Redis cache holds only **derived/ephemeral** state; the database is always the source of truth:
- **Sessions** (`cached_db`) — DB is authoritative; cache is a read-through accelerator.
- **Throttle/lockout counters** — TTL-scoped keys; expire themselves (no manual invalidation).
- **HIBP circuit-breaker counter** — TTL-scoped.
- **Effective security policy** — memoized **per-request on the user instance** (not cross-request
  cached), so a policy edit still invalidates live sessions on the next request via `policy_version`.

There is therefore no manual cache-invalidation to coordinate: everything is TTL-based or
request-scoped. A total Redis loss is safe (see `disaster-recovery.md`).

## Slow-query visibility
- Set `DB_SLOW_QUERY_MS=<ms>` to log app-side queries slower than the threshold with the request id
  (`SlowQueryLoggingMiddleware`, self-disables at 0).
- In production also set Postgres `log_min_duration_statement` for authoritative slow-query logging.

## Alert conditions
- `/readyz` failing (2× 60s) → page.
- `fa_outbox_dead_letter > 0` → warn (email delivery failing; dead-letter log line at ERROR).
- `fa_outbox_oldest_pending_seconds > 900` → warn (worker stalled/behind).
- `fa_open_risk_events` spiking → review in the security console (`/console/`).
- Error rate / latency SLO burn (from Sentry + LB metrics) → page per burn-rate policy.
