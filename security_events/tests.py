"""Django unit tests for the security_events app."""
from django.test import TestCase

from accounts.models import User

from .models import AuditEvent
from .services import record_audit_event


class AppendOnlyAuditTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="a", email="a@example.test", password="CorrectHorse123!", status=User.Status.ACTIVE
        )

    def test_instance_delete_blocked(self):
        record_audit_event(actor=self.user, target_user=self.user, event_type="probe")
        with self.assertRaises(RuntimeError):
            AuditEvent.objects.first().delete()

    def test_queryset_delete_blocked(self):
        """Regression: QuerySet.delete() no longer bypasses append-only (finding #4)."""
        record_audit_event(actor=self.user, target_user=self.user, event_type="probe")
        with self.assertRaises(RuntimeError):
            AuditEvent.objects.filter(event_type="probe").delete()
        self.assertTrue(AuditEvent.objects.filter(event_type="probe").exists())

    def test_redaction_still_applies(self):
        event = record_audit_event(actor=self.user, event_type="probe", metadata={"password": "hunter2", "ok": 1})
        self.assertEqual(event.metadata["password"], "[redacted]")
        self.assertEqual(event.metadata["ok"], 1)
