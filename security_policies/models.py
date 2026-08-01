"""Database models for the security_policies app."""
from django.db import models


def default_allowed_2fa_methods() -> list[str]:
    return ["totp", "email_otp", "webauthn", "backup_code"]


class SecurityPolicy(models.Model):
    class RecentAuthScope(models.TextChoices):
        GLOBAL = "global", "Global"
        PER_ACTION = "per_action", "Per action"

    organization = models.OneToOneField(
        "organizations.Organization", null=True, blank=True, on_delete=models.CASCADE, related_name="security_policy"
    )
    require_2fa_for_admins = models.BooleanField(default=True)
    require_2fa_for_staff = models.BooleanField(default=False)
    allowed_2fa_methods = models.JSONField(default=default_allowed_2fa_methods)
    min_factor_strength_for_privileged_roles = models.CharField(max_length=32, default="device_bound")
    idle_timeout_minutes = models.PositiveIntegerField(default=30)
    absolute_timeout_hours = models.PositiveIntegerField(default=12)
    trusted_device_duration_days = models.PositiveIntegerField(default=30)
    # When enabled, a login from a policy-trusted device may skip the second factor.
    trusted_device_skips_2fa = models.BooleanField(default=False)
    lockout_threshold = models.PositiveIntegerField(default=10)
    lockout_duration_minutes = models.PositiveIntegerField(default=15)
    email_otp_max_verify_attempts = models.PositiveIntegerField(default=5)
    password_reset_session_invalidation = models.BooleanField(default=True)
    recent_auth_window_minutes = models.PositiveIntegerField(default=15)
    recent_auth_scope = models.CharField(max_length=24, choices=RecentAuthScope, default=RecentAuthScope.GLOBAL)
    policy_version = models.PositiveBigIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization"],
                condition=models.Q(organization__isnull=True),
                name="one_global_security_policy",
            )
        ]

    def __str__(self) -> str:
        return f"Security policy #{self.pk or 'new'}"

# Create your models here.
