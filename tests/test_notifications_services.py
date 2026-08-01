"""Pytest coverage for notifications services."""
import pytest

from notifications.models import NotificationCategory, OutboxEvent
from notifications.services import (
    category_for,
    emit_outbox_event,
    get_preferences,
    is_suppressed,
    set_preference,
)


@pytest.mark.django_db
class TestCategoryFor:
    def test_known_event(self):
        assert category_for("password.changed") == NotificationCategory.SECURITY_CRITICAL

    def test_unknown_defaults_critical(self):
        assert category_for("unknown.event") == NotificationCategory.SECURITY_CRITICAL


@pytest.mark.django_db
class TestPreferences:
    def test_default_all_enabled(self, verified_user):
        prefs = get_preferences(verified_user)
        assert all(prefs.values())

    def test_set_and_check_suppression(self, verified_user):
        set_preference(
            user=verified_user,
            category=NotificationCategory.ACCOUNT_ACTIVITY,
            email_enabled=False,
        )
        assert is_suppressed(verified_user, "login.new_device")

    def test_non_suppressible_never_suppressed(self, verified_user):
        assert not is_suppressed(verified_user, "password.changed")

    def test_invalid_category_raises(self, verified_user):
        with pytest.raises(ValueError):
            set_preference(user=verified_user, category="invalid", email_enabled=False)


@pytest.mark.django_db
class TestEmitOutboxEvent:
    def test_creates_event(self, verified_user):
        event = emit_outbox_event(
            event_type="test.outbox",
            aggregate_type="user",
            aggregate_id=str(verified_user.pk),
            payload={"user_id": verified_user.pk},
        )
        assert OutboxEvent.objects.filter(pk=event.pk).exists()
