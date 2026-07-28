#!/usr/bin/env bash
# Full Auth — database backup. Produces a compressed, timestamped pg_dump.
# Usage:  DATABASE_URL=postgresql://user:pass@host:5432/db BACKUP_DIR=/backups ./scripts/backup.sh
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
mkdir -p "$BACKUP_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$BACKUP_DIR/fullauth-$STAMP.dump"

echo "Backing up to $OUT ..."
# Custom format (-Fc) enables selective, parallel restore.
pg_dump --dbname="$DATABASE_URL" --format=custom --no-owner --no-privileges --file="$OUT"

# Integrity check: a backup is only a backup if it restores. Verify the archive is readable.
pg_restore --list "$OUT" > /dev/null
echo "Backup OK ($(du -h "$OUT" | cut -f1))."

# Prune old backups.
find "$BACKUP_DIR" -name 'fullauth-*.dump' -mtime "+$RETENTION_DAYS" -delete || true
echo "Pruned backups older than ${RETENTION_DAYS} days."
