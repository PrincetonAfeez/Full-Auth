"""Database models for the sessions app."""
import hashlib
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone


def hash_session_key(session_key: str) -> str:
    return hashlib.sha256(session_key.encode()).hexdigest()


class ActiveSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="active_sessions")
    session_key_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now_add=True)
    expires_idle_at = models.DateTimeField()
    expires_absolute_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="revoked_sessions"
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    device_label = models.CharField(max_length=120, blank=True)
    security_stamp = models.PositiveBigIntegerField(default=1)
    policy_version = models.PositiveBigIntegerField(default=1)

    class Meta:
        ordering = ["-last_seen_at"]

    @classmethod
    def create_for_request(cls, request, user, policy):
        from accounts.client_ip import client_ip

        now = timezone.now()
        return cls.objects.update_or_create(
            session_key_hash=hash_session_key(request.session.session_key),
            defaults={
                "user": user,
                "last_seen_at": now,
                "expires_idle_at": now + timedelta(minutes=policy.idle_timeout_minutes),
                "expires_absolute_at": now + timedelta(hours=policy.absolute_timeout_hours),
                "ip_address": client_ip(request),
                "user_agent": request.META.get("HTTP_USER_AGENT", ""),
                "security_stamp": user.security_stamp,
                "policy_version": policy.policy_version,
            },
        )[0]

    def is_expired(self) -> bool:
        now = timezone.now()
        return self.revoked_at is not None or self.expires_idle_at <= now or self.expires_absolute_at <= now

    def extend_idle(self, policy) -> None:
        self.last_seen_at = timezone.now()
        self.expires_idle_at = self.last_seen_at + timedelta(minutes=policy.idle_timeout_minutes)


class TrustedDevice(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="trusted_devices")
    device_identifier_hash = models.CharField(max_length=64)
    display_name = models.CharField(max_length=120)
    trusted_until = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    policy_version = models.PositiveBigIntegerField(default=1)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "device_identifier_hash"], name="one_trusted_device_per_hash")
        ]


class DeviceRiskEvent(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="device_risk_events")
    event_type = models.CharField(max_length=80)
    severity = models.CharField(max_length=16, default="info")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

# Create your models here.
