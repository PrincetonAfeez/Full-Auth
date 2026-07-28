# Full Auth Platform

A Django identity and authentication platform scaffolded from `Full Auth.md`.

This build is a runnable product foundation, not a finished enterprise compliance program. It implements the core architecture and security spine: custom users, verified email state, organizations and memberships, scoped role services, security policies, MFA models/services, active-session tracking, per-request enforcement middleware, password reset challenges, audit/risk events, an outbox worker, web views, JSON API routes, health checks, Docker/Postgres/Redis, and focused tests.

## Run Locally

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock   # exact tested versions (Django 6.0)
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py bootstrap_genesis --username admin --email admin@example.test --password "ChangeMe123!"
.\.venv\Scripts\python.exe manage.py runserver
```

> **New accounts must verify their email before they can sign in.** Registration creates a
> `pending_activation` user; the verification link is printed to the worker/console email log. Until
> it is clicked, login is refused (the login page offers a "resend verification" link). The genesis
> admin above is created already-active.

Open http://127.0.0.1:8000 and sign in as the genesis admin. Because the genesis admin is
provisioned with `force_strong_mfa`, the **first login redirects to strong-factor enrollment**
(TOTP + backup codes) before the dashboard is reachable — you are never locked out. Password
reset and email-verification links are printed by the worker/console email backend.

## Run With Docker

```powershell
docker compose up --build
# Optional local DB backups: docker compose --profile local-backup up --build
cp .env.example .env   # local secrets (optional; dev defaults work for compose networking)
docker compose exec web python manage.py bootstrap_genesis --username admin --email admin@example.test --password "ChangeMe123!"
```

(Pass `--password` explicitly for non-interactive `docker compose exec`; omitting it falls back
to an interactive prompt.)

The sample Compose file runs:

- `web`: Django + Gunicorn (graceful shutdown)
- `worker`: SIGTERM-aware outbox drainer (`run_worker`)
- `postgres`: product database
- `redis`: session/cache/throttle backing cache
- `backup`: daily verified `pg_dump` to a `backups` volume (**requires `--profile local-backup`**)

## Operations

Runbooks live in [`docs/runbooks/`](docs/runbooks/): backup/restore, disaster-recovery (RTO/RPO),
deployment/rollback/staging, monitoring/alerting/SLOs, and incident-response. Data retention and
subject-rights are in [`docs/data-retention.md`](docs/data-retention.md); the API contract is
[`docs/openapi.yaml`](docs/openapi.yaml); scope-vs-reality is
[`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md).

Scheduled jobs (cron in prod): `process_outbox`/`run_worker`, `cleanup_expired` (retention),
`outbox_stats`. Health: `/healthz`, `/readyz`; metrics: `/metrics` (bearer-token guarded).

A runnable monitoring stack (Prometheus + blackbox + Alertmanager) is in `observability/` — bring
it up with `docker compose -f docker-compose.yml -f docker-compose.observability.yml up`. A k6
load test for the core path is in `loadtest/`.

> **Note:** closing an organization (`close_organization`) bumps each member's global
> `security_stamp`, so affected members are re-authenticated across **all** their organizations,
> not only the closed one. This is a deliberate offboarding fail-safe (see
> [docs/runbooks/disaster-recovery.md](docs/runbooks/disaster-recovery.md)).

## Test

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

Django's test runner remains available:

```powershell
.\.venv\Scripts\python.exe manage.py test
```

The suite (293 pytest cases across all apps plus `tests/`) covers session revocation, security-stamp invalidation, TOTP replay rejection, backup code reuse rejection, email OTP attempt caps, password reset latest-link-wins/session invalidation, tenant-scoped query filtering, SSO org-scoped access, step-up API parity, middleware rate limits, and platform console views.

## Important Security Notes

- Production boot fails if required secrets, Postgres, Redis, or TOTP encryption key settings are missing.
- Local development falls back to SQLite and locmem cache only when `DATABASE_URL`/`REDIS_URL` are absent.
- WebAuthn/passkeys are fully implemented: server ceremony crypto is verified against a software authenticator, and the browser client (`static/js/webauthn.js`) is wired for registration and assertion.
- Email is routed through the outbox; the default backend is console email. Users can mute non-critical categories; security-critical notices are never suppressible.
- No secrets are committed: the dev TOTP key is derived from `DJANGO_SECRET_KEY`; production requires a real `TOTP_ENCRYPTION_KEY` (fail-fast).
- A HaveIBeenPwned outage will not block signup/reset — a circuit breaker degrades gracefully and alerts.
