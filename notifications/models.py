"""Database models for the notifications app."""
from django.conf import settings
from django.db import models


class OutboxEvent(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        PROCESSING = "processing", "Processing"
        SENT = "sent", "Sent"
        FAILED = "failed", "Failed"
        DEAD_LETTER = "dead_letter", "Dead letter"

    event_type = models.CharField(max_length=120, db_index=True)
    aggregate_type = models.CharField(max_length=80)
    aggregate_id = models.CharField(max_length=80)
    payload = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=24, choices=Status, default=Status.PENDING, db_index=True)
    attempts = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    next_attempt_at = models.DateTimeField(null=True, blank=True)
    processing_started_at = models.DateTimeField(null=True, blank=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)

    class Meta:
        ordering = ["created_at"]


class NotificationDelivery(models.Model):
    class Channel(models.TextChoices):
        EMAIL = "email", "Email"
        IN_APP = "in_app", "In app"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        SENT = "sent", "Sent"
        FAILED = "failed", "Failed"
        SUPPRESSED = "suppressed", "Suppressed"

    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    template = models.CharField(max_length=120)
    channel = models.CharField(max_length=24, choices=Channel)
    status = models.CharField(max_length=24, choices=Status, default=Status.PENDING)
    provider_message_id = models.CharField(max_length=160, blank=True)
    related_event = models.ForeignKey(OutboxEvent, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    failed_at = models.DateTimeField(null=True, blank=True)
    error = models.TextField(blank=True)


class NotificationCategory(models.TextChoices):
    SECURITY_CRITICAL = "security_critical", "Security critical"  # never suppressible
    TRANSACTIONAL = "transactional", "Transactional"  # verification/invite links -- never suppressible
    ACCOUNT_ACTIVITY = "account_activity", "Account activity"  # new device/login -- suppressible
    ORG_ACTIVITY = "org_activity", "Organization activity"  # role changes -- suppressible


# Categories the user is allowed to mute. Everything else is always delivered.
SUPPRESSIBLE_CATEGORIES = {
    NotificationCategory.ACCOUNT_ACTIVITY,
    NotificationCategory.ORG_ACTIVITY,
}


class NotificationPreference(models.Model):
    """Per-user opt-out for suppressible notification categories (security-critical can't be muted)."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notification_preferences")
    category = models.CharField(max_length=32, choices=NotificationCategory)
    email_enabled = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "category"], name="one_pref_per_user_category")
        ]
