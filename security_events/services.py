"""Business logic and service layer for security_events."""
SENSITIVE_KEYS = {"password", "token", "otp", "code", "secret", "session_key", "backup_code"}


def _redact(value):
    if isinstance(value, dict):
        return {key: ("[redacted]" if key.lower() in SENSITIVE_KEYS else _redact(val)) for key, val in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def record_audit_event(
    *,
    actor=None,
    target_user=None,
    organization=None,
    event_type: str,
    metadata: dict | None = None,
    request=None,
):
    from .models import AuditEvent

    request_meta = {}
    if request is not None:
        from accounts.client_ip import client_ip

        request_meta = {
            "request_id": getattr(request, "request_id", ""),
            "ip_address": client_ip(request),
            "user_agent": request.META.get("HTTP_USER_AGENT", ""),
        }
    return AuditEvent.objects.create(
        actor=actor,
        target_user=target_user,
        organization=organization,
        event_type=event_type,
        metadata=_redact(metadata or {}),
        **request_meta,
    )


def detect_risk_event(*, user=None, organization=None, event_type: str, severity: str = "info", details: dict | None = None):
    from .models import SecurityRiskEvent

    return SecurityRiskEvent.objects.create(
        user=user,
        organization=organization,
        event_type=event_type,
        severity=severity,
        detection_details=_redact(details or {}),
    )


def resolve_risk_event(*, actor, event_id: int, status: str = "resolved"):
    from django.utils import timezone

    from .models import SecurityRiskEvent

    valid = {SecurityRiskEvent.Status.REVIEWED, SecurityRiskEvent.Status.RESOLVED, SecurityRiskEvent.Status.FALSE_POSITIVE}
    if status not in valid:
        raise ValueError(f"Invalid risk event status: {status}")
    event = SecurityRiskEvent.objects.filter(pk=event_id).first()
    if not event:
        return None
    event.status = status
    event.reviewed_by = actor
    event.resolved_at = timezone.now()
    event.save(update_fields=["status", "reviewed_by", "resolved_at"])
    record_audit_event(actor=actor, event_type="risk_event.resolved", metadata={"event": event_id, "status": status})
    return event
