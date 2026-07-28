# Full Auth & Enterprise Identity Platform: Roles, Sessions, 2FA, Edge Cases (DB + API + Web) — v3

**Type:** Standalone full-product build. 

**One-line:** A production-ready Django identity and authentication platform with custom users, organization-scoped roles, hardened sessions, dual-method 2FA plus fully-implemented WebAuthn/passkeys, password reset, email verification, session fixation defenses, active-session/device management, a per-request enforcement middleware, multi-tenant isolation, policy enforcement, auditability, risk events, notifications, and an HTMX + session-authenticated JSON API surface.

**Product posture:** This is not a login/register demo. It is a go-to-market identity foundation for applications that need secure user lifecycle management, role enforcement, sessions, step-up verification, account recovery, and security operations.

**Register:** Mastery of Python, Django, security engineering, and system architecture. Enterprise-grade, production-ready.

**Stack constraint:** Entire app in the Python ecosystem. Web layer is Django + HTMX. API is session-authenticated JSON under the same security model. PostgreSQL database. Redis/managed cache for session, throttle, and lockout state. Background worker (Django 6.0 Tasks framework + persistent backend) drains the outbox. No Channels/WebSockets, no separate auth microservice, no JWT-first external developer platform in this product scope.

> **Changes in v3 (architecture pass).** Scope is *not* reduced — this revision keeps the full product and adds depth, resolves one coherence conflict, and promotes hedged controls to mandatory.
> - **Resolved:** WebAuthn/passkeys were hedged as "where feasible / where selected at build time," which contradicts "fully built, no MVP." Passkeys are now **fully in scope and fully implemented**, with the missing ceremony-challenge model and relying-party config added (§5, §13, ADR-0015).
> - **Added — enforcement spine:** a named per-request security middleware is now a first-class component. Session revocation, idle/absolute timeout, deactivation-mid-session, role-change-mid-session, and awaiting-2FA gating are all enforced here, in a defined order (§7a, ADR-0016).
> - **Added — multi-tenant isolation:** shared-schema with org-scoped querysets, deny-by-default, and a systematic cross-tenant isolation invariant and test (§10a, ADR-0017).
> - **Added — cache/worker tier:** Redis for session/throttle/lockout state; a background worker drains the outbox with `SKIP LOCKED` claiming, backoff, and dead-letter handling; compose gains worker + redis services (§7, §25, ADR-0018).
> - **Promoted to mandatory:** TOTP single-use step tracking + drift window + constant-time compare; Email-OTP per-challenge verification-attempt cap; breached-password screening (NIST 800-63B); TOTP secret encryption at rest with key management (§13, §15, ADR-0019, ADR-0020).
> - **Added — policy:** Email OTP cannot be the sole second factor for privileged roles when 2FA is required (§11, §13, ADR-0021).
> - **Added:** CORS/CSRF-header posture for the JSON API; lockout-as-DoS mitigation; bootstrap/genesis admin flow; recent-auth granularity decision; right-to-erasure reconciled with the append-only audit log; API-parity test matrix; `SECRET_KEY_FALLBACKS` rotation (§8, §17, §16, §22, §27, §24, ADR-0022..0024).

---

## 1. Product Thesis

Authentication is not a form. It is a security system.

The system must prove that it can safely manage identity across registration, login, role enforcement, 2FA, password reset, session revocation, device trust, recent-auth checks, API access, admin recovery, and hostile edge cases.

The core product promise:

> A user can safely authenticate, recover, manage sessions/devices, use second factors, and access only what their role and organization membership permits — while admins can operate the system with auditability and without silently weakening security.

The product must be inspectable by a security reviewer, support/admin operator, and future enterprise customer.

---

## 2. Locked Decisions

Settled decisions. Do not re-litigate during implementation.

| # | Area | Decision |
|---|---|---|
| 1 | User model | Custom user model from day one, based on `AbstractUser` |
| 2 | Primary login identifier | Username + password |
| 3 | Email identity | Email is unique, verified, and security-sensitive |
| 4 | API style | Session-authenticated JSON API, not JWT/token-first external API |
| 5 | Web layer | Django templates + HTMX, no SPA framework |
| 6 | Roles mechanism | Django Groups + explicit hierarchy/scoped-role service |
| 7 | Role hierarchy | Admin ⊃ Staff ⊃ Member |
| 8 | Enterprise identity layer | Organizations and organization-scoped memberships are in scope |
| 9 | 2FA factors | TOTP and Email OTP are in scope; backup codes required |
| 10 | Passkeys/WebAuthn | **Fully implemented** as a first-class strong factor behind the general factor interface (not deferred). Includes ceremony-challenge storage and relying-party config. |
| 11 | 2FA default posture | Opt-in by default, with configurable policy enforcement by role/org |
| 12 | 2FA recovery | Backup codes; Email OTP when enabled; Admin-assisted reset with step-up/audit |
| 13 | Session fixation | Rotate session key on login and again on 2FA completion |
| 14 | Intermediate auth state | Password-verified/awaiting-2FA is not fully authenticated; Django `login()` is not called until 2FA passes |
| 15 | Session expiry | Idle timeout and absolute timeout both enforced |
| 16 | Concurrent sessions | Tracked, visible, and revocable |
| 17 | Trusted devices | Device trust is in scope and governed by policy |
| 18 | Sensitive actions | Recent-auth/step-up required |
| 19 | Password reset | Persisted challenges, hashed tokens, single-use, expiring, latest-link-wins |
| 20 | Auditability | Append-only security audit log is required |
| 21 | Side effects | Transactional outbox drives notifications and follow-up actions, drained by a background worker |
| 22 | Production posture | Docker, PostgreSQL, Redis, secure settings, observability, CI, dependency scanning |
| 23 | Enforcement model | A named per-request security middleware re-derives session validity, timeouts, revocation, deactivation, role, and awaiting-2FA state from authoritative storage every request. Nothing security-relevant is trusted from the session cookie alone. |
| 24 | Tenancy model | Shared-schema multi-tenancy. Every tenant-scoped row carries an `organization` FK; access is filtered by org membership at the queryset layer, deny-by-default. |
| 25 | Cache/state tier | Redis (or managed cache) holds session, throttle, and lockout state. Per-process memory is never used for production throttling. |
| 26 | Password hashing | Argon2 (`argon2-cffi`) as the primary hasher; automatic rehash-on-login when the hasher is upgraded. |
| 27 | Breached passwords | Passwords are screened against a known-compromised corpus (HIBP k-anonymity range API) at registration, change, and reset, per NIST 800-63B. |
| 28 | TOTP secret at rest | TOTP shared secrets are encrypted at rest with an env/KMS-held key; key rotation is documented. |
| 29 | API origin posture | Same-origin only by default; CORS is deny-by-default with an explicit allow-list if ever needed. |
| 30 | Privileged-role factors | When 2FA is required for a role, Email OTP cannot be that role's *sole* second factor; a phishing-resistant or device-bound factor (TOTP/passkey) is required. |

---

## 3. Product Boundary — Full Product, Not MVP

This is the full scope for the product being built.

**Included:**
- Public Member registration.
- Admin-created and Admin-invited users.
- Custom user model.
- Unique verified email identity.
- Organizations/workspaces and organization-scoped memberships.
- Global and organization-scoped roles.
- Hierarchical RBAC.
- Session-authenticated web + JSON API.
- TOTP, Email OTP, backup codes, and **fully-implemented WebAuthn/passkeys** behind a common factor interface.
- 2FA enrollment, login, disable, recovery, and admin reset.
- Password reset with persisted challenge semantics.
- Email verification and email-change security.
- Active sessions, device tracking, trusted devices, revocation.
- Idle and absolute session timeouts.
- Session fixation defense.
- A per-request enforcement middleware (the spine that makes revocation/timeouts/role-changes/deactivation take effect immediately).
- Shared-schema multi-tenant isolation enforced at the queryset layer.
- Redis-backed session/throttle/lockout state and a background worker draining the outbox.
- Breached-password screening and Argon2 hashing.
- Recent-auth/step-up requirements.
- Risk events and admin security console.
- Notifications and notification delivery log.
- Audit log and transactional outbox.
- Rate limiting, lockout/recovery, secure cookies, CSRF, production settings.
- Concrete API route contract and HTMX workflows.
- A bootstrap/genesis flow for the first platform admin and default policy.
- Security tests, edge-case tests, an API-parity test matrix, a cross-tenant isolation test, and production CI.

**Explicit non-goals for this product scope:**
- OAuth provider / OpenID Connect server.
- Social login.
- SAML enterprise SSO as a full implementation.
- External JWT developer API.
- Separate identity microservice.
- Native mobile app.
- WebSockets.

The architecture should leave room for SSO/OIDC/SAML later, but the product being built is a hardened first-party Django identity platform.

---

## 4. Actors & Roles

### Platform Level

**Platform Admin**
- Provisions and manages organizations.
- Can create first organization Owner/Admin.
- Can suspend organizations.
- Can inspect global security events through the platform security console.
- Cannot silently impersonate users; any support access requires explicit reason and audit logging.

### Organization Level

A user may belong to multiple organizations.

| Role | Capabilities |
|---|---|
| **Organization Owner/Admin** | Manage organization settings, policies, users, roles, invitations, sessions, 2FA recovery, security events |
| **Staff** | Access staff-only resources and view/edit permitted user records; cannot assign roles or deactivate accounts unless explicitly delegated |
| **Member** | Manage own profile, sessions, security settings, and member-level resources |
| **Auditor / Read-only Security Reviewer** | View security/audit records where granted; cannot mutate users or policies |

### Individual User

Every user can:
- Manage their own profile.
- Verify email.
- Change password.
- Enable/disable 2FA with step-up.
- Manage backup codes.
- View/revoke own active sessions.
- Manage trusted devices.
- Export own account/security data where appropriate.

---

## 5. Data Model Overview

> **Tenancy convention.** Every tenant-scoped model carries an `organization` FK (or is reachable to one through a membership) and is queried only through org-scoped managers (§10a). Models below that are inherently tenant-scoped (memberships, invitations, org policies, org-scoped role assignments, org-scoped risk/audit views) inherit that discipline even where the FK is not re-listed.

### Identity Core

**User** — custom `AbstractUser` extension:
- unique username
- unique email
- email verified flag/timestamp
- status: active / deactivated / locked / pending_activation
- created_at / updated_at
- last_login_at
- security_state metadata where appropriate

**EmailAddress / EmailIdentity**
- user
- email
- is_primary
- verified_at
- created_at
- pending_change metadata

**Organization**
- name
- slug
- status: active / suspended / closed
- security_policy reference
- created_at / updated_at

**OrganizationMembership**
- organization
- user
- role
- status: invited / active / suspended / removed
- created_by
- accepted_at
- removed_at

**Invitation**
- organization
- email
- intended role
- token hash
- expires_at
- accepted_at
- revoked_at
- inviter

### Roles and Policies

**RoleAssignment**
- user
- organization nullable for platform/global role
- group/role
- assigned_by
- assigned_at
- revoked_at

**SecurityPolicy**
- organization nullable for global default
- require_2fa_for_admins
- require_2fa_for_staff
- allowed_2fa_methods
- min_factor_strength_for_privileged_roles (Email OTP excluded as sole factor)
- idle_timeout_minutes
- absolute_timeout_hours
- trusted_device_duration_days
- lockout_threshold
- lockout_duration_minutes
- email_otp_max_verify_attempts
- password_reset_session_invalidation flag
- recent_auth_window_minutes
- recent_auth_scope (global vs per-action)
- policy_version

### MFA and Recovery

**MFADevice**
- user
- type: totp / email_otp / webauthn
- name
- enabled_at
- disabled_at
- last_used_at
- metadata

**TOTPDevice**
- FK MFADevice
- secret **encrypted at rest** (Fernet/`cryptography`, key from env/KMS; never plaintext)
- last_accepted_step (monotonic; rejects any code from a step ≤ this value — enforces single-use/replay resistance)
- confirmed_at

**EmailOTPChallenge**
- user
- target_email
- code_hash (constant-time compared; code length ≥ 6 digits)
- created_at
- expires_at
- used_at
- verify_attempts (challenge invalidated when it exceeds `email_otp_max_verify_attempts`)
- resend_count
- request metadata

**BackupCode**
- user
- code_hash
- batch_id
- created_at
- used_at

**WebAuthnCredential**
- user
- credential_id
- public_key
- sign_count (monotonic; non-increasing counter is a clone-detection risk signal)
- aaguid / transports metadata
- device name
- created_at
- last_used_at
- revoked_at

**WebAuthnChallenge** — ceremony state for registration and assertion (the piece that makes WebAuthn actually implementable):
- user nullable (assertion may precede user resolution for usernameless flows; in this product it is tied to the awaiting-auth user)
- ceremony_type: registration / assertion
- challenge (random, single-use)
- expires_at
- used_at
- expected_rp_id
- expected_origin
- created_at

> **Relying-party configuration** lives in settings: `WEBAUTHN_RP_ID` (registrable domain), `WEBAUTHN_RP_NAME`, and `WEBAUTHN_EXPECTED_ORIGINS`. Registration and assertion both validate challenge freshness, origin, and RP ID, and require user verification where policy demands it. Use an audited Python library (`webauthn` / `py_webauthn`); never hand-roll attestation parsing.

### Sessions and Devices

**ActiveSession**
- user
- session_key hash/reference
- created_at
- last_seen_at
- expires_idle_at
- expires_absolute_at
- revoked_at
- revoked_by
- IP / user-agent metadata
- device reference

**TrustedDevice**
- user
- device identifier hash
- display name
- trusted_until
- created_at
- last_seen_at
- revoked_at
- policy version

**DeviceRiskEvent**
- user
- event type
- severity
- IP/user-agent/device metadata
- created_at
- resolved_at

### Recovery and Security Events

**PasswordResetChallenge**
- user
- token_hash
- created_at
- expires_at
- used_at
- superseded_at
- requester IP/user-agent
- latest-link-wins semantics

**EmailVerificationChallenge**
- user/email
- token_hash
- created_at
- expires_at
- used_at
- superseded_at

**AuditEvent**
- actor
- target user
- organization nullable
- event_type
- timestamp
- request_id
- IP / user-agent
- metadata JSON
- append-only

**SecurityRiskEvent**
- user nullable
- organization nullable
- event_type
- severity
- detection details
- status: open / reviewed / resolved / false_positive
- created_at
- reviewed_by

**OutboxEvent**
- event_type
- aggregate_type
- aggregate_id
- payload JSON
- status: pending / processing / sent / failed / dead_letter
- attempts
- created_at
- processed_at

**NotificationDelivery**
- recipient
- template
- channel: email / in_app
- status
- provider_message_id
- related event
- created_at / sent_at / failed_at

---

## 6. Build/Buy Split

### Lean on audited Django/library behavior

Do not reinvent:
- password hashing
- Django sessions
- Django auth foundation
- CSRF middleware
- `AUTH_PASSWORD_VALIDATORS`
- Django Groups/permissions
- TOTP generation/verification through `django-otp`
- QR provisioning through `qrcode`
- email delivery through a transactional provider abstraction

### Hand-write the product/security work

The system must implement:
- custom user model and lifecycle semantics
- organization/membership model
- role hierarchy and organization-scoped authorization
- security policy engine
- dual 2FA enrollment/login/recovery flows
- backup-code lifecycle
- WebAuthn/passkey factor interface where implemented
- intermediate awaiting-2FA session state
- session fixation defense
- active session and trusted device tracking
- recent-auth/step-up enforcement
- persisted reset and verification challenges
- latest-link-wins reset behavior
- risk-event detection
- lockout/recovery policy
- admin security console
- notification/outbox workflow
- audit log
- HTMX views
- session-authenticated API
- all edge-case tests

---

## 7. Application Architecture

The codebase should make the security model obvious.

Recommended Django apps:

- `accounts` — custom user model, registration, profile, email identity
- `organizations` — organizations, memberships, invitations, scoped roles
- `authorization` — role hierarchy, permission policies, decorators/mixins/services, tenant-scoped querysets
- `mfa` — TOTP, Email OTP, backup codes, WebAuthn/passkey factor implementations behind a common factor interface
- `sessions` — active sessions, revocation, idle/absolute timeout, trusted devices, **the per-request enforcement middleware (§7a)**
- `security_policies` — policy evaluation, policy versioning, enforcement decisions
- `passwords` — password reset and password change challenge flows, breached-password screening
- `notifications` — notification templates, preferences, delivery log
- `worker` — outbox draining tasks, scheduled cleanup, dead-letter handling (Django Tasks framework)
- `security_events` — audit events, risk events, security console selectors
- `api` — session-authenticated JSON endpoints
- `web` — HTMX views, page shells, template composition
- `ops` — health/readiness checks, bootstrap/genesis command, role/policy seeding, security health checks

### Service-layer rule

Security workflows live in explicit services, not scattered through forms/views.

Required services:
- `register_member`
- `invite_user`
- `accept_invitation`
- `assign_role`
- `change_role`
- `deactivate_user`
- `authenticate_password_step`
- `begin_mfa_challenge`
- `verify_mfa_challenge`
- `enable_totp`
- `enable_email_otp`
- `consume_backup_code`
- `regenerate_backup_codes`
- `request_password_reset`
- `complete_password_reset`
- `verify_email`
- `change_primary_email`
- `create_active_session`
- `revoke_session`
- `trust_device`
- `revoke_trusted_device`
- `require_recent_auth`
- `begin_webauthn_registration`
- `complete_webauthn_registration`
- `begin_webauthn_assertion`
- `complete_webauthn_assertion`
- `screen_breached_password`
- `record_audit_event`
- `emit_outbox_event`
- `process_outbox` (worker)
- `detect_risk_event`

### Transaction rules

- One-time token consumption uses `transaction.atomic()` and row locking (`SELECT … FOR UPDATE`).
- Backup-code consumption is atomic.
- TOTP step consumption updates `last_accepted_step` atomically inside the verify transaction.
- Password-reset completion consumes the challenge and invalidates sessions atomically.
- Role changes and session revocations are auditable in the same logical workflow.
- Outbox events are written in the same transaction as the state change they represent; the worker claims them later with `SELECT … FOR UPDATE SKIP LOCKED`. No email or webhook is dispatched inside a request handler.

### Time rules

All expiry-sensitive logic uses injectable/time-freezable helpers so tests can deterministically cover idle timeout, absolute timeout, OTP expiry, reset expiry, lockout expiry, and trusted-device expiry.

---

## 7a. Enforcement Middleware — The Security Spine

This is the component most identity products leave implicit and most reviewers look for first. Almost every "takes effect immediately" promise in this document — session revocation, idle timeout, absolute timeout, deactivation-mid-session, role-change-mid-session, awaiting-2FA gating — is the *same* mechanism: a per-request check that re-derives the truth from authoritative storage rather than trusting the session cookie. It is named, ordered, and budgeted.

**Component:** `SecurityEnforcementMiddleware`, ordered after Django's `SessionMiddleware` and `AuthenticationMiddleware` and before any view dispatch.

**Per-request decision order (first failure wins, fail-closed):**

1. **No session / anonymous** → proceed as anonymous; view-level auth gates apply.
2. **Resolve `ActiveSession`** for the current session key hash. Missing or `revoked_at` set → terminate the Django session and respond login-required (web) / `401` (API).
3. **Idle expiry** (`now > expires_idle_at`) → terminate session, login-required / `401`.
4. **Absolute expiry** (`now > expires_absolute_at`) → terminate session, login-required / `401`.
5. **User state** — deactivated/locked → terminate session, `423`/login-required as appropriate. (This is how "admin deactivates a user with a live session" takes effect on the user's next request.)
6. **Awaiting-2FA** — if the session is in the intermediate state, only the 2FA and logout routes are permitted; everything else returns `401 awaiting_2fa`. The user is **not** `request.user` yet (Django `login()` has not been called).
7. **Role/authorization context** — resolve the requester's current global and org roles **fresh** (never from a role snapshot cached in the session), so a role change applies on the next request.
8. **Recent-auth freshness** — annotate the request with whether recent-auth is satisfied for the policy window; view/route guards consume this for step-up.
9. On success, update `last_seen_at` (write-throttled to avoid a DB write every request) and continue.

**State location & cost.** Hot lookups (ActiveSession validity, user status, role context) are served from Redis with a short TTL and explicit invalidation on revoke/deactivate/role-change, falling back to Postgres. This is what keeps the stated *Session middleware overhead p95 < 20ms* budget honest while still being authoritative. Invalidation is event-driven: `revoke_session`, `deactivate_user`, and `change_role` purge the relevant cache keys in the same transaction that writes the change.

**"Revoke" has one definition now:** mark `ActiveSession.revoked_at`, delete/flush the server-side Django session, and purge the cache entry — all in one transaction. Any one alone is insufficient; the middleware is the thing that denies the *next* request.

**Fail-closed:** if Redis is unavailable the middleware falls back to Postgres; if authoritative state cannot be read at all, the request is denied rather than allowed.

---

## 8. API Layer — Session-Authenticated JSON

The API mirrors the web security model. It is not a separate privilege surface.

Base path: `/api/v1/`.

All session-authenticated write endpoints require CSRF.

Required API routes:

```text
/api/v1/auth/status/
/api/v1/auth/login/
/api/v1/auth/logout/
/api/v1/auth/2fa/challenge/
/api/v1/auth/2fa/verify/
/api/v1/auth/password-reset/request/
/api/v1/auth/password-reset/complete/
/api/v1/auth/email-verification/request/
/api/v1/auth/email-verification/complete/
/api/v1/me/
/api/v1/me/security/
/api/v1/me/sessions/
/api/v1/me/sessions/{id}/revoke/
/api/v1/me/trusted-devices/
/api/v1/me/trusted-devices/{id}/revoke/
/api/v1/me/2fa/
/api/v1/me/2fa/totp/enable/
/api/v1/me/2fa/email/enable/
/api/v1/me/2fa/{factor_id}/disable/
/api/v1/me/backup-codes/regenerate/
/api/v1/organizations/
/api/v1/organizations/{id}/members/
/api/v1/organizations/{id}/invitations/
/api/v1/admin/users/
/api/v1/admin/users/{id}/roles/
/api/v1/admin/users/{id}/sessions/revoke/
/api/v1/admin/users/{id}/2fa/reset/
/api/v1/admin/security-events/
/api/v1/admin/audit-events/
/api/v1/admin/security-policies/
```

### API response contract

All errors use a stable envelope:

```json
{
  "error": {
    "code": "awaiting_2fa",
    "message": "Additional verification is required.",
    "fields": {},
    "request_id": "..."
  }
}
```

Required status behavior:
- `401` unauthenticated
- `401` with `awaiting_2fa` for intermediate auth state
- `403` authenticated but unauthorized
- `403` with `recent_auth_required` when step-up is needed for a sensitive action
- `409` stale/replayed/superseded challenge
- `423` locked account
- `429` throttled

### Origin, CSRF, and CORS posture

- The API is session/cookie authenticated, so every write requires CSRF. Non-HTMX clients send the token via the `X-CSRFToken` header; the CSRF cookie stays `HttpOnly` where possible with the token sourced from a page `<meta>` tag / `django-htmx`.
- **CORS is deny-by-default.** The platform is same-origin only unless an explicit allow-list is configured; credentials are never exposed to unlisted origins. An unspecified/permissive CORS policy on an identity API is treated as a defect.
- `SameSite=Lax` (or `Strict` where flows allow) cookies provide defense-in-depth against cross-site request forgery alongside CSRF tokens.

The API must behave identically to the web layer for RBAC, 2FA gating, recent-auth, lockout, deactivation, and role changes. This parity is proven by a generated test matrix, not asserted (§27).

---

## 9. Web Layer — Django + HTMX

The web app should feel like a secure identity console, not a collection of generic auth pages.

### Public/account screens

- Register Member account
- Login
- 2FA method choice
- 2FA verify
- Password reset request
- Password reset complete
- Email verification
- Invitation acceptance / first password setup

### User security screens

- Profile and email identity
- Change password
- 2FA settings
- TOTP enrollment with QR code
- Email OTP enrollment
- Backup-code display/regeneration
- Active sessions list
- Trusted devices list
- Revoke other sessions
- Security event history

### Organization/admin screens

- Organization members
- Invitations
- Role assignment
- User deactivation/reactivation
- 2FA reset assistance
- Active-session revocation
- Security policy configuration
- Audit log
- Risk events
- Lockout review
- Security dashboard

### HTMX rules

- Every HTMX mutation has a full-page fallback.
- Security-sensitive forms are POST-only.
- Partial responses never leak hidden admin/security data.
- OTP errors remain generic.
- Expired session partials redirect or render a safe login-required state.
- Awaiting-2FA partials do not treat the user as authenticated.
- Recent-auth-required partials render a step-up prompt.
- Role-denied partials return 403 without revealing object existence.
- Browser back after logout/reset must not expose cached sensitive pages.
- All partials include CSRF behavior appropriate to Django.

---

## 10. RBAC and Organization Authorization

### Role hierarchy

Django Groups are flat. Hierarchy must be explicit.

`Admin > Staff > Member`

Implementation may use:
- cumulative group permissions, or
- a role-rank service, or
- organization-scoped role policy helpers.

The hierarchy must be tested and enforced on web and API.

### Global vs organization roles

- Platform Admin is global.
- Organization roles are scoped to one organization.
- A user can be Admin in one organization and Member in another.
- Security-sensitive admin actions check both global/platform role and organization role.

### Required boundaries

- Member cannot view Staff/Admin screens.
- Staff cannot assign roles unless explicitly delegated.
- Staff cannot deactivate users by default.
- Admin can manage organization users.
- Platform Admin can manage organizations.
- Cross-organization access is denied.
- Role changes take effect immediately, without trusting stale role state cached in session (enforced by §7a).

---

## 10a. Multi-Tenant Isolation

Organizations are tenants, and cross-tenant data leakage (IDOR across orgs) is the single most likely catastrophic bug in a SaaS identity platform. Isolation is therefore a **systematic, enforced invariant**, not per-view diligence.

**Model:** shared-schema multi-tenancy. Every tenant-scoped row carries an `organization` FK (directly, or transitively through membership). No separate schema/database per tenant.

**Enforcement at the data layer, deny-by-default:**

- Tenant-scoped models expose a `TenantScopedQuerySet` / manager whose default queryset is filtered to the organizations the requester is a member of. Retrieving "all rows" requires an explicit, audited escalation (platform-admin selectors), never the default path.
- Org-scoped endpoints such as `/api/v1/organizations/{id}/members/` resolve `{id}` against the requester's memberships first; a non-member receives `403`/`404` (existence not revealed) before any row is read.
- Object-level checks confirm the object's `organization` matches the requester's scope for that route — defense-in-depth behind the queryset filter.

**The isolation invariant (single stated property, single test family):**

> For every tenant-scoped route on web and API, a requester authenticated into org A receives identical deny behavior when targeting any object belonging to org B, regardless of their role within org A.

A generated test iterates tenant-scoped routes × (foreign-org object) and asserts denial, so a newly added route cannot silently skip isolation. Recorded as ADR-0017.

---

## 11. Security Policy Engine

Security behavior must be configurable without rewriting flows.

Policies are evaluated through a single service and are versioned/audited.

Policy controls:
- require 2FA for Admins
- require 2FA for Staff
- allowed MFA factors
- trusted-device duration
- idle session timeout
- absolute session timeout
- recent-auth window
- password reset expiry
- email OTP expiry
- email OTP resend throttle
- login failure threshold
- lockout duration
- password reset throttling
- backup-code regeneration step-up requirement
- session invalidation on password reset
- admin-assisted recovery requirements
- minimum factor strength for privileged roles (Email OTP excluded as sole second factor)
- Email OTP per-challenge verification-attempt cap
- breached-password screening toggle (on by default)
- recent-auth scope (global window vs per-action)

Policy decisions should be auditable where they affect security outcomes.

> **Privileged-role factor rule.** When a policy requires 2FA for Admins or Staff, Email OTP may not be that role's *only* enrolled second factor — because email is also the password-reset channel, allowing it as the sole factor collapses two factors into one. Such users must enroll TOTP or a passkey. The policy engine enforces this at enrollment and at login.

---

## 12. Authentication and Login Flow

### Password step

1. User submits username/password.
2. Failure uses generic error messaging and rate limiting.
3. Deactivated/locked users cannot continue.
4. On success, session key rotates (`cycle_key`).
5. If MFA is required/enabled, set intermediate awaiting-2FA state. **Django `login()` is NOT called yet** — the pending user id and a timestamp live in the (rotated) session; `request.user` remains anonymous so `@login_required` views cannot be reached.
6. If no MFA required, complete login (`login()`), create the active-session record, and let §7a take over enforcement.

### Awaiting-2FA state

The user is **not fully authenticated**.

Allowed:
- 2FA challenge/verify pages
- logout/cancel flow

Denied:
- dashboard
- API data endpoints
- admin views
- profile/settings

The intermediate state has its own short expiry (a few minutes, policy-driven). On expiry it clears and the user restarts at the password step. 2FA verification attempts within the window are rate-limited and capped; exceeding the cap clears the intermediate state and emits a risk event. Enforcement of "no protected route while awaiting-2FA" is handled centrally by §7a, not per-view.

### 2FA completion

1. Verify selected factor.
2. Rotate session key again.
3. Create/refresh active session metadata.
4. Record last strong-auth timestamp.
5. Emit audit event and outbox events.
6. Redirect to intended destination safely.

---

## 13. Multi-Factor Authentication

### TOTP

- QR provisioning via `qrcode`; secret encrypted at rest (§5).
- First-code verification before enabling.
- **Single-use / replay resistance is mandatory:** track `last_accepted_step`; reject any code whose time-step is ≤ the last accepted step. Not "where practical."
- Explicit drift window (e.g. ±1 step) documented and tested.
- Constant-time comparison.
- Disable requires recent-auth/step-up.

### Email OTP

- Requires verified primary email.
- Challenge codes are hashed and ≥ 6 digits; constant-time comparison.
- Expiring codes.
- Resend throttling **and a per-challenge verification-attempt cap** (`email_otp_max_verify_attempts`): resend throttling limits how often a code is issued, but the attempt cap is what stops online guessing of a live code. Exceeding it invalidates the challenge and emits a risk event.
- Pending challenges invalidated when email changes.
- User-facing copy clearly states Email OTP is only as secure as the email account.
- May not be a privileged role's sole second factor (§11).

### Backup codes

- Generated when first factor is enabled; fixed-size batch (e.g. 10) of high-entropy codes.
- Shown once, with explicit "I have saved these" confirmation.
- Stored hashed; constant-time comparison; one-time use; verification attempts are rate-limited.
- Regeneration invalidates old unused codes.
- Regeneration requires recent-auth/step-up.

### WebAuthn / passkeys (fully implemented)

WebAuthn is a first-class factor, fully built — not an interface stub.

Required implementation:
- A common factor interface that does not assume OTP-only factors; TOTP, Email OTP, and WebAuthn all implement it.
- `WebAuthnCredential` stores public-key credential metadata only (no secret).
- `WebAuthnChallenge` stores single-use, expiring ceremony challenges for both registration and assertion (§5).
- Registration and assertion validate challenge freshness, `expected_origin`, and `rp_id`, enforce user verification where policy requires, and verify/track the signature `sign_count` (a non-increasing counter is a clone signal → risk event).
- Relying-party config (`WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_EXPECTED_ORIGINS`) in settings.
- Passkeys can satisfy login 2FA and step-up where policy allows.
- Use an audited Python WebAuthn library (`webauthn` / `py_webauthn`); attestation/assertion parsing is never hand-rolled.

### Admin-assisted recovery

- Admin can reset a user's MFA factors only with recent-auth/step-up.
- The reset is audited.
- The target user's active sessions are revoked.
- Recovery does not bypass role boundaries.

---

## 14. Session Management, Fixation, and Devices

### Fixation defense

Session key rotates:
- after password verification
- after MFA completion
- after password reset/login recovery where appropriate

A pre-login session ID must never become a fully authenticated session.

### Active sessions

Track:
- created_at
- last_seen_at
- idle expiry
- absolute expiry
- IP metadata
- user-agent metadata
- device reference
- revocation details

Users can revoke other sessions. Admins can revoke user sessions.

### Timeouts

Both required:
- idle timeout, default ~30 minutes
- absolute timeout, default ~12 hours

Timeouts are policy-driven.

### Trusted devices

Features:
- remember this device if policy allows
- name device
- revoke trusted device
- device trust expires
- new-device login event
- step-up required for unknown/high-risk device where policy requires

### Logout

- POST-only.
- Invalidates server-side session.
- Records audit event.
- Clears intermediate auth state.

---

## 15. Password Reset and Email Verification

### Password reset

- Enumeration-safe request behavior.
- Sent only to verified primary email.
- Persisted challenge with hashed token.
- Single-use.
- Expiring.
- Latest-link-wins.
- Superseded links rejected.
- Used links rejected.
- Malformed links fail safely.
- New password is screened for breach exposure before acceptance (see below).
- Completion invalidates all active sessions (and purges their §7a cache entries).
- Completion records audit event and enqueues a notification via the outbox (the worker sends it).

### Password policy and storage

- Primary hasher is **Argon2** (`argon2-cffi`); Django automatically rehashes on login when the hasher is upgraded.
- `AUTH_PASSWORD_VALIDATORS` configured plus a **breached-password screen**: the candidate password is checked against the HaveIBeenPwned range API using k-anonymity (only a SHA-1 prefix leaves the server) at registration, password change, and reset. This implements the NIST 800-63B "compromised credentials" control the standards baseline (§23) commits to. Failures are screened before the password is ever stored.
- No composition rules that contradict 800-63B (no forced periodic rotation, no arbitrary character-class mandates beyond length + breach screening).

### Email verification

- Persisted challenge with hashed token.
- Expiring.
- Latest-link-wins.
- Verification required for Email OTP and password reset.

### Email change

- Requires recent-auth/step-up.
- New email must be verified before becoming primary.
- Pending Email OTP challenges to old email are invalidated.
- Sends security notifications to old and new addresses where appropriate.

---

## 16. Recent Auth and Step-Up Verification

Sensitive actions require recent authentication or step-up verification.

Actions requiring recent-auth/step-up:
- disable MFA factor
- regenerate backup codes
- change password
- change primary email
- revoke all sessions
- assign/change roles
- deactivate/reactivate users
- change security policy
- admin-assisted 2FA reset
- export audit/security data
- trust a device

Step-up can be satisfied by:
- password confirmation
- successful MFA challenge
- passkey assertion (WebAuthn is fully implemented and allowed by policy)

Recent-auth timestamp is separate from normal session validity.

**Granularity decision.** Recent-auth is governed by `recent_auth_scope`:
- *Global* (default): one recent-auth timestamp per session; satisfying step-up for one sensitive action greenlights others within the policy window. Simpler UX; acceptable for most deployments.
- *Per-action*: high-assurance organizations can require fresh step-up for each sensitive action class (e.g. role changes, policy changes, admin-assisted reset) regardless of other recent step-ups.

Either way, being merely logged in — even recently — is never sufficient; recent-auth is a distinct, re-proven fact, and the choice is explicit per policy rather than incidental.

---

## 17. Rate Limiting, Lockout, and Recovery

Rate limiting must be explicit, tested, and enumeration-safe. All throttle and lockout counters live in Redis (shared across web workers); per-process memory is never used in production. When the cache is unavailable, protected flows fail closed (§7a).

Protected flows:
- login
- password reset request
- 2FA verification (within the awaiting-2FA window)
- Email OTP resend and Email OTP verification attempts
- backup-code attempts
- email verification request
- invitation acceptance
- admin recovery actions

Lockout policy (designed so lockout cannot be weaponized into targeted denial of service):
- Throttle by IP and by (username, IP) — **never by username alone**, since a username-only hard lock lets an attacker lock any victim out with bad-password spam.
- Soft throttle (escalating delay / backoff) before any hard lock.
- A genuine account-wide hard lock is reserved for strong signals, time-bounded, and auto-expiring; configurable duration.
- Unknown and known usernames receive similar timing and messaging (no enumeration via lockout).
- Admin unlock available and audited.
- Lockout events create risk/audit events.

---

## 18. Risk Events and Detection

The system records risk events for security operations.

Risk signals:
- repeated failed logins
- repeated failed OTP attempts
- reset-request storm
- backup-code use
- login from new device
- unusual IP/user-agent change
- role escalation
- admin deactivating/reactivating users
- many sessions revoked
- suspicious API write pattern
- locked account
- superseded/replayed reset token attempt

Risk events are visible in the admin security console and can trigger notifications.

---

## 19. Notifications

Security notifications are required.

Events that should notify users/admins where appropriate:
- account registered
- invitation sent/accepted
- email verification requested/completed
- new login
- new device login
- password reset requested
- password reset completed
- password changed
- email changed
- MFA enabled
- MFA disabled
- backup codes regenerated
- role changed
- account deactivated/reactivated
- sessions revoked
- trusted device added/revoked
- suspicious activity/risk event
- admin-assisted MFA reset

Notifications use:
- templates
- delivery log
- retryable outbox
- user preferences where safe

Security-critical notifications should not be suppressible when doing so would weaken user awareness.

---

## 20. Audit Logging and Domain Events

### Audit log

Append-only security history.

Required audit events:
- login success/failure
- logout
- MFA challenge issued/passed/failed
- MFA enabled/disabled/admin-reset
- backup codes generated/consumed/regenerated
- password reset requested/completed/failed/expired/replayed/superseded
- email verification requested/completed
- primary email changed
- role assigned/changed/removed
- organization created/suspended
- user invited/created/deactivated/reactivated
- session created/revoked/expired
- trusted device added/revoked/expired
- security policy changed
- lockout/rate limit event
- risk event detected/resolved

Never store:
- raw passwords
- OTPs
- backup codes
- reset tokens
- session keys
- TOTP secrets

### Domain events and outbox

The outbox drives reliable side effects.

Events:
- `UserRegistered`
- `InvitationSent`
- `EmailVerificationRequested`
- `EmailVerified`
- `LoginSucceeded`
- `LoginFailed`
- `MFAChallengeIssued`
- `MFAChallengePassed`
- `PasswordResetRequested`
- `PasswordResetCompleted`
- `RoleChanged`
- `SessionRevoked`
- `AccountDeactivated`
- `RiskEventDetected`
- `SecurityPolicyChanged`

Outbox processing must be idempotent and observable.

---

## 21. Admin Security Console

The product includes a custom security console, not just Django admin.

Screens:
- users
- organizations
- memberships
- invitations
- role assignments
- active sessions
- trusted devices
- MFA status
- backup-code batch metadata
- password reset challenges
- email verification state
- locked accounts
- audit timeline
- risk events
- security policies
- notification delivery log
- support access log

Admin actions:
- revoke sessions
- revoke trusted devices
- unlock account
- deactivate/reactivate user
- send invitation
- change role
- reset MFA with step-up
- rotate organization policy
- export audit/security records

All admin actions are audited.

---

## 22. Privacy, Data Retention, and Support Access

Authentication/security metadata is sensitive.

Required controls:
- PII redaction in normal logs
- request-body scrubbing in error tracking
- no secrets in audit metadata
- retention policy for reset/OTP/WebAuthn-ceremony challenges
- retention policy for session metadata
- retention policy for audit logs
- account data export
- account deactivation semantics
- organization offboarding procedure
- support/admin access logging
- no silent impersonation
- sensitive admin views no-cache

**Right-to-erasure vs. append-only audit (reconciled).** A data-subject erasure request must not hard-delete `AuditEvent` rows — that would defeat the append-only guarantee and create a repudiation hole. Erasure instead **tombstones/anonymizes the subject**: identifying fields (email, username, IP/user-agent on related records, device names) are severed or hashed, MFA secrets and credentials are destroyed, while audit events remain as anonymized operational facts referencing an opaque subject id. The export, deactivation, and erasure paths are distinct and individually documented (ADR-0024).

**Organization offboarding (expanded).** When an organization is closed: its memberships move to `removed`; members whose *only* org was this one are handled per policy (retain the user with no active org, or initiate the erasure path on request); the org's tenant-scoped data is retained per the retention schedule then purged; the org's audit trail is preserved (anonymized if erasure applies); and all sessions scoped to that org's privileged actions are revoked.

Support access must require:
- reason
- limited duration where applicable
- audit event
- least-privilege permissions

---

## 23. Security Standards and Verification Baseline

The project must be reviewed against:

- Django deployment/security checklist.
- OWASP ASVS Level 2 controls relevant to authentication, session management, access control, validation, and API security.
- Current NIST digital identity guidance concepts for authenticator lifecycle, replay resistance, session management, and account recovery.

This does not mean every enterprise compliance program is fully implemented. It means the build intentionally maps its security controls to recognized standards and documents exceptions.

---

## 24. Security Requirements

Non-optional:

- `DEBUG=False` in production.
- Real `ALLOWED_HOSTS`.
- Secrets from environment/secret manager only.
- `SECRET_KEY_FALLBACKS` configured for key rotation without instant mass logout.
- HTTPS-only deployment.
- Secure session and CSRF cookies.
- HSTS.
- CSRF on all forms and session-authenticated API writes.
- CORS deny-by-default; same-origin only unless explicitly allow-listed.
- POST-only logout.
- Argon2 password hashing; breached-password screening on registration/change/reset.
- TOTP secrets encrypted at rest; encryption key from env/KMS with documented rotation.
- Rate limiting on auth and recovery flows, with counters in Redis and fail-closed behavior on cache outage.
- Lockout keyed by IP and (username, IP), never username alone.
- Enumeration-safe login/reset messaging.
- Backup codes, Email OTP codes, and reset/verification tokens hashed; constant-time comparison on all secret checks.
- OTPs/tokens/session keys/TOTP secrets never logged.
- Admin/security pages no-cache; browser-back after logout/reset cannot expose cached sensitive pages.
- Secure proxy SSL settings.
- Fail-fast configuration validation: the app refuses to boot on missing/invalid required settings.
- Dependency scanning.
- Cookie flags: `HttpOnly`, `Secure`, `SameSite`.
- User/session invalidation on deactivation and password reset, enforced by §7a on the next request.
- Role changes effective immediately (§7a).
- Multi-tenant isolation enforced at the queryset layer (§10a).
- API parity for all gates (proven by the §27 matrix).

---

## 25. Production Scaffolding

Hard requirements:

- PostgreSQL in dev and prod; no SQLite.
- Redis (or managed cache) in dev and prod for session/throttle/lockout state.
- Dockerfile using Gunicorn, non-root user, collected static.
- A separate **worker** process/container running the outbox drainer and scheduled cleanup (not inside Gunicorn).
- `docker-compose.yml` with web + postgres + redis + worker.
- Environment-driven settings with fail-fast validation at boot.
- `.env.example` committed; real `.env` ignored.
- WhiteNoise or host-native static handling.
- Transactional email provider in production, dispatched only from the worker via the outbox.
- Console email backend in dev (still routed through the outbox/worker, not sent inline).
- Sentry or equivalent error tracking.
- Structured logs with request ID.
- `/healthz` (liveness) and `/readyz` (DB + Redis readiness) endpoints; neither leaks infrastructure detail.
- **Bootstrap/genesis flow:** a management command provisions the first Platform Admin and the global default `SecurityPolicy` idempotently and securely (no hard-coded credentials; first admin is required to enroll a strong second factor on first login). This is the cold-start path before any organization exists.
- Backup/restore documentation.
- Deployment/rollback documentation.
- Management commands for genesis bootstrap, role seeding, policy seeding, inactive challenge/ceremony cleanup, dead-letter inspection/replay, and security health checks.

Recommended production dependencies:
- `django-environ`
- `django-otp`
- `qrcode`
- `webauthn` / `py_webauthn` (passkeys are fully implemented, so this is required, not optional)
- `argon2-cffi`
- `cryptography` (TOTP secret encryption at rest)
- `redis` / `django-redis`
- `django-anymail` or provider SDK
- rate-limit/lockout tooling such as `django-axes` (Redis-backed) plus app-level throttles
- `pytest`, `pytest-django`, `freezegun` or `time-machine`
- `ruff`, `mypy`/`pyright` where practical
- `pip-audit`

---

## 26. Observability and Metrics

Metrics/logs must support security operations.

Track:
- login success/failure count
- MFA challenge pass/fail count (by factor type)
- password reset request/completion count
- reset replay/superseded attempts
- breached-password rejections
- lockouts
- rate-limited requests
- fail-closed rejections (cache unavailable)
- active sessions
- trusted devices
- session revocations
- role changes
- account deactivations
- risky events by severity
- enforcement-middleware overhead and cache hit/miss ratio
- outbox depth, oldest-pending age, dead-letter count
- WebAuthn sign-count anomalies
- cross-tenant access denials
- notification delivery success/failure
- audit event write failures
- API 401/403/409/423/429 counts

Performance targets:

```text
Login page p95 server response: < 250ms
Password verification p95: < 300ms (email is enqueued to the outbox, never sent in-path)
2FA verification p95: < 250ms
Enforcement middleware overhead p95: < 20ms (Redis-served, Postgres fallback)
Audit event write p95: < 50ms
Active session list p95: < 250ms
Password reset request p95: < 300ms (email enqueued, not sent in-path)
Admin security dashboard p95: < 500ms with pagination
Health/ready check p95: < 100ms
```

Security correctness beats performance, but performance must be visible. Note that no request-path target depends on email provider latency, because the outbox + worker remove provider calls from every request path.

---

## 27. Testing and Quality Strategy

Tests run against PostgreSQL.

### Required test categories

- custom user model tests
- registration/invitation tests
- email verification tests
- RBAC hierarchy tests
- organization-scoped authorization tests
- **cross-tenant isolation tests (generated over all tenant-scoped routes, §10a)**
- **enforcement-middleware tests (revoke / idle / absolute / deactivation / role-change / awaiting-2FA all take effect on the next request)**
- login/logout tests
- 2FA enrollment tests
- 2FA login tests
- backup-code tests
- **WebAuthn registration + assertion tests (challenge freshness, origin/RP validation, user verification, sign-count anomaly)**
- session fixation tests
- active-session revocation tests
- idle/absolute timeout tests
- trusted-device tests
- recent-auth/step-up tests (both global and per-action scopes)
- password reset challenge tests
- **breached-password screening tests (registration/change/reset)**
- **TOTP single-use/step-replay tests and drift-window tests**
- **Email-OTP verification-attempt-cap tests**
- **TOTP-secret-encryption-at-rest tests**
- latest-link-wins tests
- lockout/rate-limit tests (incl. fail-closed on cache outage; lockout cannot be weaponized by username alone)
- role changed mid-session tests
- deactivated account/session tests
- **API parity matrix tests (every gate × every protected endpoint, web and API)**
- HTMX partial tests
- audit log tests
- outbox idempotency + worker tests (claim/`SKIP LOCKED`, backoff, dead-letter)
- notification delivery tests
- privacy/log-redaction tests
- **bootstrap/genesis command tests (idempotent, forces first-admin strong factor)**
- **right-to-erasure tests (subject anonymized, audit preserved)**
- settings/security checks

### Edge cases each require tests

1. Login while already logged in.
2. 2FA entry abandoned midway.
3. Password reset while session active.
4. Backup code reuse.
5. TOTP replay/expired window.
6. Email OTP expiry and resend throttling.
7. Admin deactivates user with live session.
8. Concurrent password-reset requests.
9. Role changed mid-session.
10. API parity for all gates.
11. Superseded password reset link.
12. Password reset replay.
13. Email changed during Email OTP flow.
14. Sensitive action without recent auth.
15. Admin-assisted 2FA reset.
16. Deactivated account attempts auth.
17. Audit coverage without secret leakage.
18. Lockout does not enumerate users.
19. Trusted device revoked then reused.
20. Organization role differs across organizations.
21. Cross-tenant object access from a different org (every tenant-scoped route).
22. Session revoked by admin then reused (next request denied by §7a).
23. Two concurrent verifications of the same one-time token/code → exactly one succeeds.
24. WebAuthn assertion replay (used/expired ceremony challenge) rejected.
25. WebAuthn sign-count regression flagged as a clone risk event.
26. TOTP code reused within its time-step window rejected (single-use).
27. Email OTP guessed past the attempt cap → challenge invalidated, risk event.
28. Breached password rejected at registration/change/reset.
29. Redis unavailable → throttled/sensitive flows fail closed.
30. Email OTP offered as sole factor for a privileged role → rejected by policy.
31. Genesis bootstrap run twice → idempotent, no duplicate admin/policy.
32. Erasure request → subject anonymized, audit events retained.

> **API parity is proven, not asserted.** A parametrized matrix enumerates each gate state (anonymous, awaiting-2FA, wrong role, cross-org, locked, deactivated, stale/replayed challenge, missing recent-auth) against each protected endpoint on both the web and API surfaces, and asserts identical decisions. Adding an endpoint without wiring its gates fails the matrix.

### CI gates

- lint/format
- type checking for services/policies where practical
- test suite with coverage threshold appropriate to security product
- migration check
- dependency vulnerability scan
- Docker build
- production settings/security smoke check

---

## 28. Architecture Decision Records

Required ADRs:

```text
ADR-0001: Custom user model from day one.
ADR-0002: Session-authenticated API, not JWT, for this product surface.
ADR-0003: Django Groups are used, but hierarchy/scoping is enforced explicitly.
ADR-0004: Organizations provide scoped enterprise identity boundaries.
ADR-0005: Security policy engine governs role-based MFA/session/lockout behavior.
ADR-0006: Session key rotates on login and MFA completion.
ADR-0007: Awaiting-2FA state is not fully authenticated.
ADR-0008: Password reset challenges are persisted, single-use, expiring, and latest-link-wins.
ADR-0009: Recent-auth/step-up is required for sensitive actions.
ADR-0010: Audit log records facts; outbox drives side effects.
ADR-0011: Email OTP is supported but documented as bounded by email-account security.
ADR-0012: Passkeys/WebAuthn fit behind a general MFA factor interface and are fully implemented (see ADR-0015).
ADR-0013: Trusted devices are policy-governed and revocable.
ADR-0014: Security verification maps to Django deployment checks, OWASP ASVS, and NIST digital identity guidance.
ADR-0015: WebAuthn/passkeys are fully built, including ceremony-challenge storage, relying-party config, origin/RP validation, user verification, and sign-count anomaly detection. (Resolves the v2 "where feasible" hedge against the no-MVP mandate.)
ADR-0016: A named per-request SecurityEnforcementMiddleware is the enforcement spine; session validity, timeouts, revocation, deactivation, role, and awaiting-2FA are re-derived from authoritative state every request, Redis-served with Postgres fallback, fail-closed.
ADR-0017: Shared-schema multi-tenancy with org-scoped querysets, deny-by-default, and a generated cross-tenant isolation test.
ADR-0018: Transactional outbox is drained by a separate background worker (Django Tasks framework) with SKIP LOCKED claiming, backoff, and dead-letter; no provider calls in request handlers.
ADR-0019: OTP hardening is mandatory: TOTP single-use step tracking + drift window + constant-time compare; Email-OTP per-challenge verification-attempt cap.
ADR-0020: TOTP shared secrets are encrypted at rest with an env/KMS key; Argon2 is the password hasher; breached-password screening (HIBP, NIST 800-63B) runs on registration/change/reset.
ADR-0021: When 2FA is required for a role, Email OTP cannot be that role's sole second factor.
ADR-0022: Session-authenticated JSON API is CSRF-protected and CORS deny-by-default (same-origin only unless allow-listed).
ADR-0023: Recent-auth is action-distinct from session validity; scope (global vs per-action) is policy-configurable. Lockout is keyed by IP and (username, IP), never username alone, to prevent targeted DoS. A bootstrap/genesis command provisions the first admin and default policy idempotently.
ADR-0024: Right-to-erasure tombstones/anonymizes the subject while preserving the append-only audit log; export, deactivation, and erasure are distinct paths.
```

---

## 29. Definition of Done

1. Users can register as Members, verify email, log in, log out, reset passwords, and manage their security settings.
2. Admins can create/invite users, assign scoped roles, deactivate/reactivate users, and manage organization memberships.
3. A user can belong to multiple organizations with different roles, and authorization is correctly scoped per organization.
4. Admin, Staff, and Member role boundaries are enforced on web and API.
5. TOTP and Email OTP can be independently enabled, verified, disabled, and used at login.
6. Backup codes are generated once on first MFA enable, stored hashed, consumed once, rejected on reuse, and regenerable with old codes invalidated.
7. Passkey/WebAuthn is fully implemented — registration and assertion with ceremony-challenge validation, origin/RP checks, user verification, and sign-count anomaly detection — and usable as a login factor and for step-up.
8. Session key rotates on password login and MFA completion; session fixation tests prove a fixed pre-login session cannot become authenticated.
9. Awaiting-2FA state is not authenticated, does not call Django `login()`, and expires/clears if abandoned.
10. Sessions enforce idle and absolute timeouts via the enforcement middleware.
11. Users can view/revoke their active sessions and trusted devices; Admins can revoke user sessions; a revoked session is denied on its next request.
12. Recent-auth/step-up is required for sensitive actions on web and API; scope is policy-configurable.
13. Password reset is enumeration-safe, persisted, hashed-token, single-use, expiring, latest-link-wins, replay-safe, breach-screened, and invalidates sessions on completion.
14. Email change requires recent-auth and re-verification; old Email OTP challenges are invalidated.
15. Lockout/rate-limit policy works without enumeration, keyed by IP and (username, IP), and cannot be weaponized into account DoS; counters live in Redis and fail closed on cache outage.
16. Security policy engine can require 2FA by role/org without rewriting login flow, and forbids Email OTP as a privileged role's sole factor.
17. Audit log records required security events without storing secrets.
18. Outbox drives notifications and side effects idempotently, drained by a separate worker with dead-letter handling; no email is sent from a request handler.
19. Notifications exist for security-sensitive events and are delivery-logged.
20. Admin security console supports users, organizations, sessions, MFA, risk events, audit logs, policies, and recovery actions.
21. Risk events are detected, stored, visible, and auditable.
22. API routes under `/api/v1/` follow a stable error contract and match web behavior, proven by the parity matrix.
23. HTMX flows have fallbacks and do not leak sensitive state.
24. Privacy controls cover redaction, retention, support access, account data export/deactivation, and a right-to-erasure path that preserves the append-only audit log.
25. Production settings are verifiable: `DEBUG=False`, secrets in env, `SECRET_KEY_FALLBACKS`, HTTPS, secure cookies, CSRF, CORS deny-by-default, HSTS, no-cache sensitive views, and fail-fast config validation.
26. Observability is live: structured logs, request IDs, Sentry, metrics (incl. middleware/outbox/tenant signals), `/healthz`, and `/readyz`.
27. CI passes lint/format, tests against PostgreSQL, migration check, dependency audit, and Docker build.
28. `docker-compose up` runs the product locally with Postgres, Redis, a worker, and console email (still routed through the outbox).
29. No secret, OTP, backup code, reset token, session key, or TOTP secret is logged or committed; TOTP secrets are encrypted at rest.
30. Every edge case in §27 has an automated test.
31. The enforcement middleware is the single point that makes revocation, timeouts, deactivation, and role changes take effect on the next request; tests prove each.
32. Cross-tenant isolation holds for every tenant-scoped route on web and API.
33. A bootstrap/genesis command provisions the first admin and default policy idempotently and forces a strong second factor on first login.

---

## 30. Suggested Build Order

This is a sequencing guide for the full product, not an MVP. The enforcement spine and tenancy are deliberately front-loaded: everything downstream depends on them being correct.

1. Django 6.0 + PostgreSQL + Redis + Docker + env-driven settings with fail-fast validation.
2. Custom user model and base app boundaries; Argon2 hasher.
3. Organizations, memberships, invitations, groups, role hierarchy.
4. **Multi-tenant isolation: org-scoped querysets/managers, deny-by-default, and the cross-tenant isolation test (§10a) — before any tenant data flows.**
5. Security event/audit model and event-writing helper.
6. **Active-session model + the SecurityEnforcementMiddleware (§7a) as a first-class component — the spine the rest relies on.**
7. Bootstrap/genesis command (first platform admin + default policy, idempotent).
8. Public registration (with breached-password screening), invitation acceptance, email verification.
9. Login/logout with secure session rotation; active-session creation wired into the middleware.
10. Role-gated web views and API endpoints; prove RBAC/organization boundaries via the parity matrix scaffold.
11. Security policy model and policy evaluation service.
12. Idle and absolute session timeouts (enforced in the middleware).
13. Active-session console and revocation (revoke = flag + flush + cache purge).
14. Recent-auth/step-up foundation (global and per-action scopes).
15. TOTP enrollment/login flow (encrypted secret, single-use step tracking, drift window).
16. Email OTP enrollment/login flow (hashed codes, verification-attempt cap).
17. Backup codes.
18. Awaiting-2FA state hardening and expiry (no `login()` until 2FA passes).
19. Password reset challenge model, breach screening, and latest-link-wins flow.
20. Email change flow and challenge invalidation.
21. Trusted devices and device management.
22. **WebAuthn/passkeys — full registration + assertion, ceremony challenges, RP config, sign-count handling.**
23. Privileged-role factor policy (Email OTP not sole factor).
24. Rate limiting, lockout (IP / username+IP, fail-closed), recovery, and risk events.
25. Notifications, transactional outbox, and the **background worker** (Tasks framework, SKIP LOCKED, backoff, dead-letter); compose worker + redis services.
26. Admin security console.
27. Session-authenticated API route contract; CSRF/CORS posture; complete the parity matrix.
28. HTMX quality pass and full-page fallbacks.
29. Privacy/data-retention/support-access pass, including the right-to-erasure path.
30. Full edge-case test sweep (incl. concurrency, tenant isolation, fail-closed, WebAuthn replay).
31. CI, dependency scan, Docker build.
32. Production hardening: secure settings, `SECRET_KEY_FALLBACKS`, TOTP-secret key management, email provider, Sentry, structured logs, metrics, `/healthz` + `/readyz`.
33. Deployment/rollback/backup documentation and runbook (incl. worker/outbox recovery, key rotation, genesis).
34. Walk the full Definition of Done as a security reviewer.

---

**End of revised scope.**
