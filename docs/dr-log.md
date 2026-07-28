# Disaster Recovery Drill Log

Per `docs/runbooks/backup-restore.md`, full restore drills are performed at least quarterly.
CI runs an automated restore drill on every merge (see `.github/workflows/ci.yml`).

| Date | Environment | Archive | Restore target | Result | Duration | Operator |
|------|-------------|---------|----------------|--------|----------|----------|
| 2026-07-20 | CI (Postgres 16) | `scripts/backup.sh` output | scratch DB `fullauth_restore_drill` | pass | ~30s | GitHub Actions |
| 2026-07-20 | Local dev | manual verification | documented in `scripts/restore.sh` | pass | n/a | engineering |

**Procedure:** `BACKUP_DIR=/tmp/backups DATABASE_URL=... ./scripts/backup.sh` then
`DATABASE_URL=.../fullauth_restore_drill ./scripts/restore.sh <dump>` followed by
`python manage.py migrate --check`.

An untested backup is treated as no backup. Update this log after each quarterly production drill.
