# Implementation Status (spec vs. reality)

`Full Auth.md` is the aspirational scope/spec. This document is the honest map of what is actually
built and verified.

## Built and tested (293 pytest tests, green on SQLite and Postgres+Redis)
- Custom user model, verified-email lifecycle, registration → activation → login.
- Organizations, memberships, invitations (email-bound, verified-email, rank-checked), role
  hierarchy, org lifecycle (suspend/reactivate/close with tenant-data purge + SSO disable).
- Per-request fail-closed enforcement middleware; idle/absolute timeouts; session revocation.
- MFA: TOTP, Email OTP, WebAuthn/passkeys, backup codes; policy-filtered `allowed_2fa_methods`.
- Recent-auth / step-up (password, TOTP, backup codes, passkey; allowlisted actions; bound token; rate-limited; API parity).
- SSO reference OIDC connector auto-registered; org-scoped tenant enforcement; id_token-authoritative claims.
- Platform admin HTMX console with recent-auth on mutating actions.
- Append-only audit + risk events; cross-tenant isolation + expanded parity tests.

## Intentionally API-only surfaces (documented)
- Trusted-device list/trust/revoke and `GET /me/export/`.
- Organization admin (invite, role change, remove, policy update).
- Platform admin JSON API (`/api/v1/admin/*`).

## Intentionally NOT built (accepted limitations)
- OIDC/SAML/SCIM server shipped by default (reference connector registered; replace via `register_connector`).
- WebSockets/realtime; file uploads; native mobile app; multi-region residency tooling.
- Formal compliance program; external penetration test (recommended, not yet performed).
- Per-tenant resource quotas / noisy-neighbor isolation (shared infrastructure; document capacity planning instead).

## Deployment notes
- Local dev: `docker-compose.yml` (DEBUG defaults).
- Staging/production: use `docker-compose.prod.yml` overlay + real secrets (`FULL_AUTH_ENV=production`).
