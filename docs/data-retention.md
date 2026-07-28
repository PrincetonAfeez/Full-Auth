# Data Retention & Residency

## Residency
- Single-region deployment (accepted limitation). All data lives in the configured PostgreSQL
  region; Redis (cache) is co-located. No cross-border replication by default.

## Retention schedule
| Data | Retention | Enforced by |
|---|---|---|
| Password-reset challenges | 30 days after creation | `cleanup_expired` command |
| Email-verification challenges | 30 days | `cleanup_expired` |
| Email-OTP / WebAuthn ceremony challenges | 30 days | `cleanup_expired` |
| Revoked `ActiveSession` rows | 90 days after revocation | `cleanup_expired` |
| Sent `OutboxEvent` rows | 30 days after send | `cleanup_expired` |
| **Audit log (`AuditEvent`)** | Retained indefinitely; **append-only, never deleted** | model contract |
| Security risk events | Retained; resolved via console | manual review |

Run `python manage.py cleanup_expired` daily (see `runbooks/deployment.md`). Thresholds are
tunable via command flags.

## Subject rights
- **Export:** `GET /api/v1/me/export/` (recent-auth) returns the user's account/security data.
- **Erasure:** `erase_user` anonymizes identifiers and destroys credentials + PII in challenges,
  sessions, device and risk records, while preserving the append-only audit trail against an
  opaque subject id (ADR-0013). Platform-admin or self-service only.
- **Deactivation:** distinct from erasure; disables login and revokes sessions without destroying data.

## Organization offboarding
`close_organization` marks the org closed, removes memberships, revokes pending invitations,
revokes org role assignments, and deletes the org's security policy; the org's audit trail is
preserved.
