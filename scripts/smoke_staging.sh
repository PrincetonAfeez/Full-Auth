#!/usr/bin/env sh
# Staging smoke gate — run against a deployed instance.
# Usage: ./scripts/smoke_staging.sh https://staging.example.com
set -eu
BASE_URL="${1:-http://127.0.0.1:8000}"
python manage.py smoke_staging --base-url "$BASE_URL"
