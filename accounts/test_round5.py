"""Regression tests for accounts (security audit round)."""
import json

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from accounts.models import EmailAddress, User
from organizations.models import Organization, OrganizationMembership
from security_policies.services import get_effective_policy
from sessions.models import ActiveSession, hash_session_key


class StepUpBeginApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="stepupapi",
            email="stepup@example.test",
            password="CorrectHorse123!",
            status=User.Status.ACTIVE,
            email_verified_at=timezone.now(),
        )
        EmailAddress.objects.create(user=self.user, email=self.user.email, is_primary=True)
        self.client.force_login(self.user)
        policy = get_effective_policy(self.user)
        now = timezone.now()
        ActiveSession.objects.create(
            user=self.user,
            session_key_hash=hash_session_key(self.client.session.session_key),
            expires_idle_at=now + timezone.timedelta(hours=1),
            expires_absolute_at=now + timezone.timedelta(hours=12),
            security_stamp=self.user.security_stamp,
            policy_version=policy.policy_version,
        )

    def test_step_up_begin_returns_token(self):
        r = self.client.post(
            reverse("api:step_up_begin"),
            data=json.dumps({"action": "manage_mfa", "next": "/security/"}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body.get("token"))
        self.assertEqual(body["action"], "manage_mfa")

    def test_step_up_begin_rejects_external_next(self):
        r = self.client.post(
            reverse("api:step_up_begin"),
            data=json.dumps({"action": "manage_mfa", "next": "https://evil.example/phish"}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("evil.example", r.json()["next"])
