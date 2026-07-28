# Architecture Decision Records

## ADR-0001: Custom User Model

The platform uses `accounts.User`, derived from `AbstractUser`, from day one. Email is unique, verification state is explicit, and a `security_stamp` lets middleware invalidate live sessions after sensitive account changes.

## ADR-0002: Session-Authenticated API

The JSON API under `/api/v1/` uses Django sessions and CSRF rather than JWTs. This keeps web and API enforcement under one security model.

## ADR-0003: Scoped Roles

Django groups remain available for global permissions, while organization membership and role services enforce tenant-scoped role hierarchy.

## ADR-0004: Shared-Schema Tenancy

Tenant-scoped models carry an `organization` relationship and expose `visible_to()`/`for_organization()` query helpers. The default posture is deny unless membership is active.

## ADR-0005: Security Policy Engine

`SecurityPolicy` stores MFA, timeout, lockout, trusted-device, recent-auth, and factor-strength rules. Services read policy instead of hard-coding role behavior.

## ADR-0006: Enforcement Middleware

`SecurityEnforcementMiddleware` rechecks active-session state, user status, idle timeout, absolute timeout, security stamp, policy version, revocation, and awaiting-2FA state on every request.

## ADR-0007: MFA Factor Interface

TOTP, email OTP, backup codes, and WebAuthn share the `MFADevice` model. TOTP secrets are encrypted, accepted steps are monotonic, email OTP has attempt caps, and backup codes are hashed single-use values.

## ADR-0008: Password Reset

Password reset links are persisted as hashed challenges, expire, are consumed under row lock, and use latest-link-wins semantics. Completion bumps the user's security stamp and revokes live sessions.

## ADR-0009: Outbox

Security notifications and side effects are recorded in `OutboxEvent` inside the request transaction. A separate worker command drains events with row claiming, retries, and dead-letter handling.

## ADR-0010: Audit Facts

Security-relevant changes call `record_audit_event()`. The service redacts secret-like metadata keys, and audit rows are append-only by model contract (enforced at both the instance and queryset level).

## ADR-0011: Inline Email-OTP Delivery

Email-OTP codes are the one email sent **in the request path** rather than via the outbox. This is a deliberate exception to "no provider calls in request handlers": the code is time-sensitive and interactive, and routing it through the outbox would require persisting the plaintext code (violating "never store OTPs"). All other emails (reset, verification, awareness notices) go through the outbox/worker.

## ADR-0012: Request-ID Correlation

`RequestIDMiddleware` assigns a per-request id (honoring an inbound `X-Request-ID`), exposes it on `request.request_id`, echoes it as a response header, and injects it into every log record and audit event so a single request can be traced across logs, audit rows, and API error envelopes.

## ADR-0013: Right-to-Erasure vs. Append-Only Audit

`erase_user()` anonymizes/tombstones the subject (username, email, names) and destroys credentials (passwords, TOTP secrets, passkeys, backup codes, email projections) while **preserving** audit rows, which then reference an opaque subject id. Export, deactivation, and erasure are three distinct paths.

## ADR-0014: SSO as an Extension Point, Not a Product Feature

OIDC/SAML/SCIM are explicit non-goals (§3). We ship the *architecture* — `IdentityProvider`/`FederatedIdentity` models, a pluggable `SSOConnector` interface + registry, and provider-agnostic begin/callback views — with **no connector registered by default**, so SSO is inert but ready. JIT provisioning refuses silent takeover of an existing local account (link only on an IdP-asserted verified email).

## ADR-0015: Reproducible, Verified Dependencies

`requirements.txt` declares supported ranges; `requirements.lock` pins the exact versions the test suite is validated against (Django 6.0). The Dockerfile and CI install `requirements.lock` so the deployed artifact runs the tested set. Dependabot proposes updates; a lockfile bump requires a green suite.

## ADR-0016: Third-Party Resilience — HIBP Circuit Breaker

Breached-password screening fails **closed** on a brief HIBP blip (protecting the weak-password path), but a sustained outage trips a cache-backed circuit breaker that degrades to **fail-open** with a high-severity risk event, so a third-party outage cannot take down registration/reset. Availability of the core flow wins once the dependency is provably down.

## ADR-0017: Tenancy Enforcement — App Layer, Not Postgres RLS

**Decision:** enforce tenant isolation in the application layer (org-scoped `TenantQuerySet.visible_to`, per-endpoint `require_admin`/membership checks, and an explicit `verify_tenant_scope` defense-in-depth check), **not** Postgres Row-Level Security.

**Why not RLS here:** the access model is a poor fit for RLS. A user belongs to *many* organizations with different roles; platform admins and the security console legitimately read *across all* tenants; and RLS requires a per-connection `SET app.current_*` GUC that is fragile under persistent-connection pooling (`CONN_MAX_AGE`) — a leaked GUC across pooled requests would be a cross-tenant hazard *introduced* by RLS. RLS shines for strict single-tenant-per-request models; ours is multi-org with authorized global reads.

**How the invariant is guaranteed instead:** a *generated* cross-tenant isolation matrix test (`CrossTenantIsolationMatrixTests`) asserts identical deny behavior on **every** tenant-scoped route × foreign org, with a positive control, so a newly added route cannot silently skip isolation. This makes the invariant test-enforced rather than reliant on per-developer discipline. RLS remains a possible future defense-in-depth layer if the access model narrows.
