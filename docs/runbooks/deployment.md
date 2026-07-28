# Runbook: Deployment, Staging & Rollback

## Environments
- **development** — `docker compose up` (Postgres + Redis + web + worker + backup).
- **staging** — same image as prod, `FULL_AUTH_ENV=staging`, a separate DB/Redis and secrets.
  Use `docker-compose.staging.yml` as an override. Every change is verified in staging before prod.
- **production** — `FULL_AUTH_ENV=production`; fail-fast config validation enforces required
  secrets, secure cookies, real `ALLOWED_HOSTS`, and CSRF trusted origins at boot.

## Pre-prod verification gate
Before promoting to production:
1. CI is green on the merge commit (lint, migration-check, tests on Postgres+Redis, pip-audit, docker build).
2. Deploy the image to **staging**; run `python manage.py migrate` and smoke checks there:
   ```bash
   cp .env.production.example .env.staging   # fill with staging secrets
   docker compose -f docker-compose.yml -f docker-compose.staging.yml up --build -d
   python manage.py smoke_staging --base-url https://staging.example.com
   ```
3. Confirm `/readyz` = 200 and `/metrics` scrapes on staging.
4. Only then promote the **same image digest** to production.

## Production / staging secrets
- Copy `.env.production.example` to `.env.production` (prod) or `.env.staging` (staging). **Never** mount `.env.example` in deploy.
- Required vars are enforced at boot when `FULL_AUTH_ENV` is `production` or `staging` (see `config/settings.py`).
- Compose: `docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build`
- Local backup sidecar: `docker compose --profile local-backup up` (disabled in prod/staging overlays).

## Zero-downtime migrations (expand/contract)
Schema changes follow expand → migrate data → deploy code → contract:
1. **Expand:** add columns/tables as nullable/defaulted (backward compatible). Deploy.
2. **Deploy code** that writes both old and new shapes if needed.
3. **Contract:** in a later release, drop the old column. Never rename/drop in the same release
   that introduces the replacement.

## Rollback
- **Code/deploy fault:** redeploy the previous image digest. App is stateless.
- **Migration fault:** additive migrations are reversible — `python manage.py migrate <app> <prev>`.
  Because we use expand/contract, the previous image runs against the new (expanded) schema, so a
  code rollback alone is safe without reversing the migration.
- **Data corruption:** see `disaster-recovery.md` (restore path).

## Scheduled jobs (cron in prod)
- `python manage.py process_outbox` — or run the long-lived `run_worker` (graceful SIGTERM drain).
- `python manage.py cleanup_expired` — daily (retention).
- `python manage.py outbox_stats` — scrape-friendly queue depth (also on `/metrics`).
