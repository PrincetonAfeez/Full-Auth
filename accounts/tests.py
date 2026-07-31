"""Django unit tests for the accounts app."""
from django.contrib.sessions.backends.db import SessionStore
from django.core.cache import cache
from django.test import RequestFactory, TestCase
from django.urls import reverse

from accounts.models import User
from accounts.services import authenticate_password_step
from accounts.throttle import AccountThrottled
from security_policies.models import SecurityPolicy


class LockoutTests(TestCase):
    def setUp(self):
        cache.clear()
        SecurityPolicy.objects.create(organization=None, lockout_threshold=3, lockout_duration_minutes=15)
        self.user = User.objects.create_user(
            username="lock", email="lock@example.test", password="CorrectHorse123!", status=User.Status.ACTIVE
        )

    def _attempt(self, password):
        rf = RequestFactory()
        request = rf.post("/login/", REMOTE_ADDR="203.0.113.7")
        request.session = SessionStore()
        return authenticate_password_step(request=request, username="lock", password=password)

    def test_lockout_after_threshold(self):
        """Regression: repeated bad logins engage a lockout (finding #6)."""
        for _ in range(3):
            self.assertIsNone(self._attempt("wrong-password"))
        with self.assertRaises(AccountThrottled):
            self._attempt("CorrectHorse123!")  # correct password, but the pair is now locked


class ApiParityTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            username="api", email="api@example.test", password="CorrectHorse123!", status=User.Status.ACTIVE
        )

    def test_api_login_and_status(self):
        r = self.client.post(
            reverse("api:auth_login"), data={"username": "api", "password": "CorrectHorse123!"},
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["authenticated"])
        status = self.client.get(reverse("api:auth_status")).json()
        self.assertTrue(status["authenticated"])

    def test_api_unauthenticated(self):
        r = self.client.get(reverse("api:me"))
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"]["code"], "unauthenticated")

    def test_api_bad_credentials_envelope(self):
        r = self.client.post(
            reverse("api:auth_login"), data={"username": "api", "password": "nope"},
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"]["code"], "invalid_credentials")
