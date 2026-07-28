# Runbook: Incident Response & On-Call

## On-call
- A single primary on-call engineer holds the pager each week; a secondary is the escalation.
- Rotation and contacts live in the paging tool (PagerDuty/Opsgenie); the schedule is owned by
  the platform lead. Handoff happens Monday; the outgoing on-call summarizes open issues.
- Escalation: primary → secondary (15 min no-ack) → platform lead → engineering manager.

## Severity
- **SEV1** — data exposure, cross-tenant access, auth bypass, or full outage. Page immediately.
- **SEV2** — core workflow broken for many users (login/2FA/reset), or DB/Redis degraded.
- **SEV3** — partial/degraded feature, elevated errors, worker backlog.

## Response loop
1. **Acknowledge** the page; declare severity and open an incident channel.
2. **Mitigate first** — roll back the last deploy (`deployment.md`) or disable the offending path
   via a feature flag (`FLAG_<name>=false`) before root-causing.
3. **Communicate** — post status to the incident channel every 30 min; for customer-facing SEV1/2,
   update the status page.
4. **Verify** — `/readyz` green, `/metrics` normal, affected flow smoke-tested.
5. **Resolve & follow up** — write a blameless postmortem within 3 business days for SEV1/2
   (timeline, root cause, action items).

## Security incidents
- Suspected credential compromise: revoke sessions (`revoke_all_user_sessions` / admin console),
  bump `security_stamp`, force password reset.
- Review the append-only audit log (`/console/audit/`) and open risk events (`/console/risk/`).
- Preserve evidence — audit rows are immutable by design.
