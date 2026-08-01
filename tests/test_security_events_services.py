"""Pytest coverage for security events services."""
import pytest

from security_events.models import AuditEvent, SecurityRiskEvent
from security_events.services import detect_risk_event, record_audit_event, resolve_risk_event


@pytest.mark.django_db
class TestRecordAuditEvent:
    def test_basic_event(self, verified_user):
        event = record_audit_event(
            actor=verified_user,
            target_user=verified_user,
            event_type="test.event",
            metadata={"password": "secret123", "note": "ok"},
        )
        assert event.event_type == "test.event"
        assert event.metadata["password"] == "[redacted]"
        assert event.metadata["note"] == "ok"

    def test_with_request(self, verified_user):
        from django.test import RequestFactory

        request = RequestFactory().get("/", REMOTE_ADDR="203.0.113.5")
        event = record_audit_event(
            actor=verified_user, event_type="test.with_request", request=request
        )
        assert event.ip_address == "203.0.113.5"


@pytest.mark.django_db
class TestDetectRiskEvent:
    def test_creates_risk_event(self, verified_user):
        event = detect_risk_event(
            user=verified_user,
            event_type="test.risk",
            severity="low",
            details={"token": "abc"},
        )
        assert event.severity == "low"
        assert event.detection_details["token"] == "[redacted]"


@pytest.mark.django_db
class TestResolveRiskEvent:
    def test_resolve(self, verified_user, superuser):
        risk = detect_risk_event(user=verified_user, event_type="test.resolve", severity="medium")
        resolved = resolve_risk_event(actor=superuser, event_id=risk.pk, status="resolved")
        assert resolved.status == SecurityRiskEvent.Status.RESOLVED
        assert resolved.reviewed_by_id == superuser.pk

    def test_invalid_status(self, verified_user, superuser):
        risk = detect_risk_event(user=verified_user, event_type="test.bad", severity="low")
        with pytest.raises(ValueError):
            resolve_risk_event(actor=superuser, event_id=risk.pk, status="invalid")

    def test_missing_event(self, superuser):
        assert resolve_risk_event(actor=superuser, event_id=99999) is None
