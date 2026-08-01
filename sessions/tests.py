"""Django unit tests for the sessions app."""
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from accounts.models import User
from security_policies.services import get_policy

from .models import ActiveSession, hash_session_key


class SecurityEnforcementMiddlewareTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="active", email="active@example.test", password="CorrectHorse123!", status=User.Status.ACTIVE
        )

    def _login_with_active_session(self):
        """force_login + an authoritative ActiveSession row, as a real login would create."""
        self.client.force_login(self.user)
        session_key = self.client.session.session_key
        policy = get_policy()
        now = timezone.now()
        return ActiveSession.objects.create(
            user=self.user,
            session_key_hash=hash_session_key(session_key),
            expires_idle_at=now + timezone.timedelta(minutes=policy.idle_timeout_minutes),
            expires_absolute_at=now + timezone.timedelta(hours=policy.absolute_timeout_hours),
            security_stamp=self.user.security_stamp,
            policy_version=policy.policy_version,
        )

    def test_missing_active_session_fails_closed(self):
        """No authoritative ActiveSession -> request denied (spec 7a step 2, fail-closed)."""
        self.client.force_login(self.user)
        response = self.client.get(reverse("web:dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("web:login"), response["Location"])

    def test_revoked_session_denied_on_next_request(self):
        active_session = self._login_with_active_session()
        self.assertEqual(self.client.get(reverse("web:dashboard")).status_code, 200)
        active_session.revoked_at = timezone.now()
        active_session.save(update_fields=["revoked_at"])

        response = self.client.get(reverse("web:dashboard"))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("web:login"), response["Location"])

    def test_security_stamp_change_denies_live_session(self):
        self._login_with_active_session()
        self.assertEqual(self.client.get(reverse("web:dashboard")).status_code, 200)
        self.user.bump_security_stamp()
        self.user.save(update_fields=["security_stamp"])

        response = self.client.get(reverse("web:dashboard"))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("web:login"), response["Location"])
