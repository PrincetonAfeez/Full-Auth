"""Database models for the security_events app."""
from django.conf import settings
from django.db import models


class AppendOnlyQuerySet(models.QuerySet):
    def delete(self):
        raise RuntimeError("Audit events are append-only")

    def _raw_delete(self, *args, **kwargs):
        raise RuntimeError("Audit events are append-only")


class AppendOnlyManager(models.Manager.from_queryset(AppendOnlyQuerySet)):
    pass


class AuditEvent(models.Model):
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="audit_events_as_actor"
    )
    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="audit_events_as_target"
    )
    organization = models.ForeignKey("organizations.Organization", null=True, blank=True, on_delete=models.SET_NULL)
    event_type = models.CharField(max_length=120, db_index=True)
    request_id = models.CharField(max_length=64, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    objects = AppendOnlyManager()

    class Meta:
        ordering = ["-timestamp"]

    def delete(self, *args, **kwargs):
        raise RuntimeError("Audit events are append-only")


class SecurityRiskEvent(models.Model):
    class Severity(models.TextChoices):
        INFO = "info", "Info"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        REVIEWED = "reviewed", "Reviewed"
        RESOLVED = "resolved", "Resolved"
        FALSE_POSITIVE = "false_positive", "False positive"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    organization = models.ForeignKey("organizations.Organization", null=True, blank=True, on_delete=models.SET_NULL)
    event_type = models.CharField(max_length=120, db_index=True)
    severity = models.CharField(max_length=16, choices=Severity, default=Severity.INFO)
    detection_details = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=24, choices=Status, default=Status.OPEN)
    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="reviewed_risk_events"
    )
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    objects = AppendOnlyManager()

    def delete(self, *args, **kwargs):
        raise RuntimeError("Security risk events are append-only")
