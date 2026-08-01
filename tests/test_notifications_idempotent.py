"""Pytest coverage for notifications idempotent."""
import pytest
from unittest.mock import patch

from notifications.models import NotificationDelivery, OutboxEvent
from notifications.services import _deliver


@pytest.mark.django_db
class TestOutboxIdempotency:
    def test_skips_resend_when_already_sent(self, verified_user):
        event = OutboxEvent.objects.create(
            event_type="password.changed",
            aggregate_type="user",
            aggregate_id=str(verified_user.pk),
            payload={"user_id": verified_user.pk},
        )
        NotificationDelivery.objects.create(
            related_event=event,
            recipient=verified_user,
            channel=NotificationDelivery.Channel.EMAIL,
            template=event.event_type,
            status=NotificationDelivery.Status.SENT,
        )
        with patch("notifications.services.send_mail") as mock_send:
            _deliver(event)
            mock_send.assert_not_called()
