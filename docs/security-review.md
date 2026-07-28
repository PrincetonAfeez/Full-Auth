# Security Review

## Adversarial review — findings & remediation
Independent adversarial reviews were performed over the full HTTP surface and service modules,
focused on IDOR/object-level authz, auth bypass, privilege escalation, token/secret handling,
injection, and enumeration.

### Audit remediation (Round 3 — 34 items, all implemented)
- Auth-scoped passkey registration gated to forced enrollment only; sign-count regression fails closed.
- Passkey step-up sends bound `action`/`next`; CSP-safe WebAuthn init (no inline scripts).
- OIDC connector: PKCE required, nonce, JWKS-backed `id_token` validation (`PyJWT`).
- HTMX console destructive actions require recent-auth (parity with API).
- Step-up rate limiting; MFA enroll attempt cap; invitation token 500 → 400; stale invite revocation.
- `allowed_2fa_methods` enforced via effective policy; org close disables SSO providers.
- `bootstrap_genesis` safe re-run (`--force`); verified email on genesis admin.
- TOTP cache encryption; production TOTP key fallback removed; email OTP resend fail-closed in deploy envs.
- WebAuthn requires `Origin` header; generic client error messages; append-only risk events preserved on regression.
- OpenAPI updated; `docker-compose.prod.yml` overlay; legacy admin console redirects to `/console/`.

### Categories verified clean
IDOR, auth-bypass (awaiting-2FA, factor policy, enrollment-only passkey register), self-elevation,
token/secret handling, injection, and enumeration (uniform reset/verification responses; tenant 404).

## Static analysis & CI
- `ruff`, `bandit`, `pip-audit` gates in CI.
- Full test suite (**290 pytest tests**) on Postgres + Redis in CI, including backup-restore drill.

## Penetration test scope checklist (external engagement recommended)
See prior sections: AuthN/session, AuthZ/tenancy, account lifecycle, injection, rate limiting, infra.

This document is committed as the security-review artifact; update it after each review.
