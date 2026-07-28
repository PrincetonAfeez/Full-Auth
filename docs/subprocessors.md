# Subprocessors & Third-Party Services

Operators must maintain this list for GDPR/SOC 2 customer disclosures. The reference
deployment may use additional providers configured via environment variables.

| Vendor | Purpose | Data shared | Region | Notes |
|--------|---------|-------------|--------|-------|
| Have I Been Pwned (HIBP) | Password breach screening (k-anonymity range API) | SHA-1 prefix of password (5 chars) | Global | Optional; circuit breaker on outage |
| Email provider (SMTP) | Transactional email via Django `send_mail` | Recipient address, notification body | Operator-chosen | Console backend in dev |
| OIDC identity provider | Enterprise SSO (operator-configured) | Auth tokens, profile claims | IdP-dependent | Reference connector only |
| Sentry (optional) | Error tracking | Stack traces, request metadata (no PII by default) | Operator-chosen | Set `SENTRY_DSN` |
| PostgreSQL host | Primary database | All application data | Operator-chosen | Required in production |
| Redis host | Cache, throttles, session acceleration | Ephemeral session/throttle keys | Operator-chosen | Required in production |

Update this document when adding integrations or changing data flows.
