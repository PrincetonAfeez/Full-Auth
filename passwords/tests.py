"""Django unit tests for the passwords app."""
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from accounts.models import User
from sessions.models import ActiveSession

from .models import PasswordResetChallenge
from .services import complete_password_reset, request_password_reset


class PasswordResetTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="reset", email="reset@example.test", password="OldPassword123!", status=User.Status.ACTIVE
        )

    @patch("passwords.services.screen_breached_password", return_value=None)
    def test_latest_reset_link_wins(self, _screen):
        _first, first_token = request_password_reset(user=self.user)
        _second, second_token = request_password_reset(user=self.user)

        self.assertFalse(complete_password_reset(token=first_token, new_password="NewPassword123!"))
        self.assertTrue(complete_password_reset(token=second_token, new_password="NewPassword123!"))
        self.assertTrue(PasswordResetChallenge.objects.filter(user=self.user, used_at__isnull=False).exists())

    @patch("passwords.services.screen_breached_password", return_value=None)
    def test_password_reset_bumps_security_stamp_and_revokes_sessions(self, _screen):
        ActiveSession.objects.create(
            user=self.user,
            session_key_hash="x" * 64,
            expires_idle_at=timezone.now() + timezone.timedelta(hours=1),
            expires_absolute_at=timezone.now() + timezone.timedelta(hours=12),
            security_stamp=self.user.security_stamp,
        )
        old_stamp = self.user.security_stamp
        _challenge, token = request_password_reset(user=self.user)

        self.assertTrue(complete_password_reset(token=token, new_password="NewPassword123!"))
        self.user.refresh_from_db()
        self.assertGreater(self.user.security_stamp, old_stamp)
        self.assertTrue(ActiveSession.objects.get(user=self.user).revoked_at)

# Create your tests here.
