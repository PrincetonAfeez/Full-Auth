# API Versioning & Deprecation Policy

The public JSON API is mounted at `/api/v1/` (`config/urls.py`). Version **v1** is the current
stable surface documented in `docs/openapi.yaml`.

## Policy

1. **Breaking changes** require a new major path prefix (e.g. `/api/v2/`). Existing clients on
   v1 continue to receive compatible responses until the deprecation window ends.
2. **Non-breaking additions** (new optional fields, new endpoints) may ship under the current
   version without a version bump.
3. **Deprecation window:** minimum **90 days** notice via release notes and `Sunset` response
   header on affected v1 routes before removal.
4. **Authentication, rate limits, and error envelopes** remain stable across minor v1 changes.

## Pagination

List endpoints support `?limit=` (1–200, default 50) and `?offset=` (default 0). Responses
include a `page` object: `{ "total", "limit", "offset" }`.

## Rate limiting

Global API rate limit returns HTTP **429** with `Retry-After` header and JSON
`error.fields.retry_after` (seconds).
