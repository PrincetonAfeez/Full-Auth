#!/usr/bin/env bash
# Full Auth — database restore from a pg_dump custom-format archive.
# Usage:  DATABASE_URL=postgresql://user:pass@host:5432/db ./scripts/restore.sh <backup.dump>
# WARNING: --clean drops and recreates objects. Run against the target DB deliberately.
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
ARCHIVE="${1:?path to a .dump archive is required}"
[ -f "$ARCHIVE" ] || { echo "Archive not found: $ARCHIVE" >&2; exit 1; }

echo "Restoring $ARCHIVE into $DATABASE_URL ..."
pg_restore --dbname="$DATABASE_URL" --clean --if-exists --no-owner --no-privileges "$ARCHIVE"

echo "Restore complete. Verifying migrations are applied ..."
python manage.py migrate --check && echo "Schema up to date." || {
  echo "Migrations pending after restore; running migrate ..."; python manage.py migrate;
}
echo "Restore OK."
