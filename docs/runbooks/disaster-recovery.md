# Runbook: Disaster Recovery

## Targets
- **RPO (max data loss): 24 hours** with logical dumps alone; **≤ 5 minutes** when the managed
  Postgres PITR/WAL archiving is enabled (recommended for production).
- **RTO (max downtime): 1 hour** — time to provision a DB, restore the latest verified backup,
  redeploy the app image, and pass readiness checks.

## Failure scenarios & response
1. **App instance lost** — redeploy the pinned image (`requirements.lock`); stateless app, no data
   action. Traffic restored when `/readyz` returns 200.
2. **Redis lost** — cache is reconstructible. Sessions fall back to the DB (`cached_db` engine);
   throttle counters reset (fail-open unless `THROTTLE_FAIL_CLOSED=true`). No restore needed.
3. **Database lost/corrupted** — provision a new Postgres, run `scripts/restore.sh <latest.dump>`,
   point `DATABASE_URL` at it, redeploy. Verify `/readyz`, then spot-check login + audit log.
4. **Region outage** — restore the latest off-region backup into a standby region and repoint DNS.
   (Single-region is an accepted limitation; multi-region is future work.)

## DR drill (quarterly, tested)
1. Take a fresh backup.
2. Restore it into a scratch database with `scripts/restore.sh`.
3. Run `python manage.py migrate --check` (must be clean) and the smoke suite.
4. Record wall-clock restore time and confirm it is within RTO.
5. Log the drill date/result in the on-call channel.

## Rollback vs. restore
Prefer **rollback** (redeploy previous image) for code/deploy faults — see `deployment.md`.
Reserve **restore** for data loss/corruption. Migrations are additive/reversible; a schema restore
is only needed when data is damaged, not for a bad deploy.
