"""Django unit tests for the notifications app."""
from django.core import mail
from django.test import TestCase
from django.utils import timezone

from accounts.models import User

from .models import NotificationCategory, NotificationDelivery, OutboxEvent
from .services import emit_outbox_event, process_outbox, requeue_stuck_processing, set_preference


class NotificationPreferenceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="pref", email="pref@example.test", password="CorrectHorse123!", status=User.Status.ACTIVE
        )

    def _emit(self, event_type):
        emit_outbox_event(event_type=event_type, aggregate_type="user",
                          aggregate_id=str(self.user.pk), payload={"user_id": self.user.pk})

    def test_suppressible_category_is_muted(self):
        set_preference(user=self.user, category=NotificationCategory.ACCOUNT_ACTIVITY, email_enabled=False)
        self._emit("login.new_device")
        process_outbox()
        self.assertEqual(len(mail.outbox), 0)
        self.assertTrue(NotificationDelivery.objects.filter(status=NotificationDelivery.Status.SUPPRESSED).exists())

    def test_security_critical_cannot_be_muted(self):
        # Even trying to mute a critical category is rejected; and the email still sends.
        with self.assertRaises(ValueError):
            set_preference(user=self.user, category=NotificationCategory.SECURITY_CRITICAL, email_enabled=False)
        self._emit("password.changed")
        process_outbox()
        self.assertEqual(len(mail.outbox), 1)


class OutboxTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="n", email="n@example.test", password="CorrectHorse123!", status=User.Status.ACTIVE
        )

    def test_token_scrubbed_after_send(self):
        """Regression: transient reset token is removed from the row post-send (finding #9)."""
        emit_outbox_event(
            event_type="password_reset.requested", aggregate_type="user",
            aggregate_id=str(self.user.pk), payload={"user_id": self.user.pk, "token": "secret-token"},
        )
        process_outbox()
        event = OutboxEvent.objects.get()
        self.assertEqual(event.status, OutboxEvent.Status.SENT)
        self.assertNotIn("token", event.payload)
        self.assertTrue(NotificationDelivery.objects.filter(status="sent").exists())

    def test_reaper_requeues_stuck_processing(self):
        """Regression: events stranded in PROCESSING are recovered, keyed on processing start."""
        event = OutboxEvent.objects.create(
            event_type="x", aggregate_type="user", aggregate_id="1",
            payload={"user_id": self.user.pk}, status=OutboxEvent.Status.PROCESSING,
            processing_started_at=timezone.now() - timezone.timedelta(hours=1),
        )
        self.assertEqual(requeue_stuck_processing(), 1)
        event.refresh_from_db()
        self.assertEqual(event.status, OutboxEvent.Status.FAILED)

    def test_reaper_leaves_fresh_inflight_event(self):
        """An event that just entered PROCESSING (old created_at) must NOT be reaped."""
        event = OutboxEvent.objects.create(
            event_type="x", aggregate_type="user", aggregate_id="1",
            payload={"user_id": self.user.pk}, status=OutboxEvent.Status.PROCESSING,
            processing_started_at=timezone.now(),
        )
        OutboxEvent.objects.filter(pk=event.pk).update(created_at=timezone.now() - timezone.timedelta(days=1))
        self.assertEqual(requeue_stuck_processing(), 0)
        event.refresh_from_db()
        self.assertEqual(event.status, OutboxEvent.Status.PROCESSING)
