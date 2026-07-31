"""Database models for the accounts app."""
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class User(AbstractUser):
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        DEACTIVATED = "deactivated", "Deactivated"
        LOCKED = "locked", "Locked"
        PENDING_ACTIVATION = "pending_activation", "Pending activation"

    email = models.EmailField(unique=True)
    email_verified_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=32, choices=Status, default=Status.PENDING_ACTIVATION)
    force_strong_mfa = models.BooleanField(default=False)
    security_stamp = models.PositiveBigIntegerField(default=1)
    last_login_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def email_verified(self) -> bool:
        return self.email_verified_at is not None

    @property
    def is_security_active(self) -> bool:
        return self.is_active and self.status == self.Status.ACTIVE

    def mark_email_verified(self) -> None:
        self.email_verified_at = timezone.now()
        if self.status == self.Status.PENDING_ACTIVATION:
            self.status = self.Status.ACTIVE

    def bump_security_stamp(self) -> None:
        self.security_stamp += 1


class EmailAddress(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="email_addresses")
    email = models.EmailField(unique=True)
    is_primary = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)
    pending_change_to = models.EmailField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user"],
                condition=models.Q(is_primary=True),
                name="one_primary_email_per_user",
            )
        ]

    def __str__(self) -> str:
        return self.email

# Create your models here.
