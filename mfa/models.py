"""Database models for the mfa app."""
from django.conf import settings
from django.db import models


class MFADevice(models.Model):
    class Type(models.TextChoices):
        TOTP = "totp", "TOTP"
        EMAIL_OTP = "email_otp", "Email OTP"
        WEBAUTHN = "webauthn", "WebAuthn"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="mfa_devices")
    type = models.CharField(max_length=24, choices=Type)
    name = models.CharField(max_length=120)
    enabled_at = models.DateTimeField(null=True, blank=True)
    disabled_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    @property
    def enabled(self) -> bool:
        return self.enabled_at is not None and self.disabled_at is None


class TOTPDevice(models.Model):
    device = models.OneToOneField(MFADevice, on_delete=models.CASCADE, related_name="totp")
    encrypted_secret = models.TextField()
    last_accepted_step = models.BigIntegerField(default=-1)
    confirmed_at = models.DateTimeField(null=True, blank=True)


class EmailOTPChallenge(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="email_otp_challenges")
    target_email = models.EmailField()
    code_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    verify_attempts = models.PositiveIntegerField(default=0)
    resend_count = models.PositiveIntegerField(default=0)
    request_metadata = models.JSONField(default=dict, blank=True)


class BackupCode(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="backup_codes")
    code_hash = models.CharField(max_length=128, unique=True)
    batch_id = models.CharField(max_length=36)
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)


class WebAuthnCredential(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="webauthn_credentials")
    credential_id = models.TextField(unique=True)
    public_key = models.TextField()
    sign_count = models.PositiveBigIntegerField(default=0)
    aaguid = models.CharField(max_length=64, blank=True)
    transports = models.JSONField(default=list, blank=True)
    device_name = models.CharField(max_length=120)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)


class WebAuthnChallenge(models.Model):
    class CeremonyType(models.TextChoices):
        REGISTRATION = "registration", "Registration"
        ASSERTION = "assertion", "Assertion"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.CASCADE)
    ceremony_type = models.CharField(max_length=24, choices=CeremonyType)
    challenge = models.CharField(max_length=160, unique=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    expected_rp_id = models.CharField(max_length=255)
    expected_origin = models.URLField()
    created_at = models.DateTimeField(auto_now_add=True)

# Create your models here.
