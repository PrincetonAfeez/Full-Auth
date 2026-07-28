# Runbook: Backup & Restore

## What is backed up
- **PostgreSQL** — the single source of truth (users, orgs, sessions, MFA, audit log, outbox).
  Redis holds only ephemeral session/throttle cache and is reconstructible; it is **not** backed up.

## Automated backups
`scripts/backup.sh` runs `pg_dump -Fc`, verifies the archive with `pg_restore --list`, and prunes
by `BACKUP_RETENTION_DAYS` (default 30). Run it on a schedule:

- **docker-compose:** the `backup` service runs it daily (see `docker-compose.yml`).
- **Managed Postgres (recommended for prod):** enable the provider's automated daily snapshots +
  point-in-time recovery (PITR) in addition to logical dumps.

```
DATABASE_URL=postgresql://user:pass@host:5432/fullauth BACKUP_DIR=/backups ./scripts/backup.sh
```

## Restore (tested procedure)
```
DATABASE_URL=postgresql://user:pass@host:5432/fullauth ./scripts/restore.sh /backups/fullauth-<STAMP>.dump
```
`restore.sh` restores with `--clean --if-exists`, then runs `migrate --check` to confirm the schema
matches the code. **A restore is verified as part of DR drills (see disaster-recovery.md).**

## Verification cadence
- Backups are integrity-checked on every run (`pg_restore --list`).
- A **full restore drill into a scratch database** is performed at least quarterly; record the date
  and measured restore time in [`docs/dr-log.md`](../dr-log.md). CI runs an automated drill on every merge.
