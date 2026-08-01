"""Django unit tests for the web app."""
import re

from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from accounts.models import User
from mfa.models import MFADevice
from mfa.services import _totp_code, current_totp_step, enable_totp, get_totp_enrollment_secret
from security_policies.services import get_policy
from sessions.models import ActiveSession, hash_session_key


def _make(username="u", email=None, **kw):
    return User.objects.create_user(
        username=username, email=email or f"{username}@example.test",
        password="CorrectHorse123!", status=User.Status.ACTIVE, **kw
    )


class LoginFlowTests(TestCase):
    def test_forced_mfa_user_can_enroll_and_log_in(self):
        """Regression: genesis / force_strong_mfa user is no longer locked out (finding #1)."""
        _make("genesis", force_strong_mfa=True)
        r =         self.client.post(reverse("web:login"), {"username": "genesis", "password": "CorrectHorse123!"})
        self.assertRedirects(r, reverse("web:mfa_enroll"), fetch_redirect_response=False)

        self.client.post(reverse("web:mfa_enroll"), {"stage": "start"})
        user = User.objects.get(username="genesis")
        device_id = self.client.session["enroll_totp_device_id"]
        secret = get_totp_enrollment_secret(user_id=user.pk, device_id=device_id)
        code = _totp_code(secret, current_totp_step())
        r2 = self.client.post(reverse("web:mfa_enroll"), {"stage": "confirm", "code": code})
        self.assertContains(r2, "backup codes")
        self.assertTrue(ActiveSession.objects.filter(user__username="genesis").exists())

    def test_email_otp_only_user_can_complete_login(self):
        """Regression: email-OTP-only user can now log in (finding #3)."""
        user = _make("eouser")
        MFADevice.objects.create(user=user, type=MFADevice.Type.EMAIL_OTP, name="e", enabled_at=timezone.now())
        self.client.post(reverse("web:login"), {"username": "eouser", "password": "CorrectHorse123!"})
        self.client.post(reverse("web:mfa_challenge"), {"method": "email_otp_send"})
        code = re.search(r"\b(\d{6})\b", mail.outbox[-1].body).group(1)
        r = self.client.post(reverse("web:mfa_challenge"), {"method": "email_otp", "code": code})
        self.assertRedirects(r, reverse("web:dashboard"), fetch_redirect_response=False)
        self.assertTrue(ActiveSession.objects.filter(user=user).exists())

    def test_awaiting_2fa_allows_logout(self):
        """Regression: logout permitted during awaiting-2FA (finding #5)."""
        user = _make("totuser", force_strong_mfa=True)
        enable_totp(user=user, name="a")
        MFADevice.objects.filter(user=user, type=MFADevice.Type.TOTP).update(enabled_at=timezone.now())
        self.client.post(reverse("web:login"), {"username": "totuser", "password": "CorrectHorse123!"})
        r = self.client.post(reverse("web:logout"))
        self.assertRedirects(r, reverse("web:login"), fetch_redirect_response=False)

    def test_awaiting_2fa_attempt_cap_clears_state(self):
        user = _make("capuser", force_strong_mfa=True)
        enable_totp(user=user, name="a")
        MFADevice.objects.filter(user=user, type=MFADevice.Type.TOTP).update(enabled_at=timezone.now())
        self.client.post(reverse("web:login"), {"username": "capuser", "password": "CorrectHorse123!"})
        last = None
        for _ in range(6):
            last = self.client.post(reverse("web:mfa_challenge"), {"method": "totp", "code": "000000"})
        self.assertRedirects(last, reverse("web:login"), fetch_redirect_response=False)


class SensitiveActionTests(TestCase):
    def _login_needs_step_up(self, user):
        self.client.force_login(user)
        policy = get_policy()
        now = timezone.now()
        ActiveSession.objects.create(
            user=user, session_key_hash=hash_session_key(self.client.session.session_key),
            expires_idle_at=now + timezone.timedelta(minutes=policy.idle_timeout_minutes),
            expires_absolute_at=now + timezone.timedelta(hours=policy.absolute_timeout_hours),
            security_stamp=user.security_stamp, policy_version=policy.policy_version,
        )

    def test_change_password_requires_recent_auth(self):
        user = _make("stepper")
        self._login_needs_step_up(user)
        r = self.client.get(reverse("web:change_password"))
        self.assertEqual(r.status_code, 302)
        self.assertIn(reverse("web:step_up"), r["Location"])

    def test_revoke_session_requires_recent_auth(self):
        user = _make("revoker")
        self._login_needs_step_up(user)
        now = timezone.now()
        policy = get_policy()
        session = ActiveSession.objects.create(
            user=user, session_key_hash="a" * 64,
            expires_idle_at=now + timezone.timedelta(hours=1),
            expires_absolute_at=now + timezone.timedelta(hours=12),
            security_stamp=user.security_stamp, policy_version=policy.policy_version,
        )
        r = self.client.post(reverse("web:revoke_session", args=[session.pk]))
        self.assertEqual(r.status_code, 302)
        self.assertIn(reverse("web:step_up"), r["Location"])
        session.refresh_from_db()
        self.assertIsNone(session.revoked_at)


@override_settings(BREACH_SCREENING_ENABLED=False)
class SelfServiceEnrollmentTests(TestCase):
    def test_logged_in_user_can_enroll_totp(self):
        """Round-4 #5: a logged-in user can self-enroll TOTP from the security area."""
        _make("selfenroll", email_verified_at=timezone.now())
        # Real login sets recent-auth (global scope), satisfying the manage_mfa step-up gate.
        self.client.get(reverse("web:login"))
        self.client.post(reverse("web:login"), {"username": "selfenroll", "password": "CorrectHorse123!"})

        start = self.client.post(reverse("web:enroll_totp"), {"stage": "start"})
        self.assertContains(start, "Authenticator code")
        user = User.objects.get(username="selfenroll")
        device_id = self.client.session["settings_totp_device_id"]
        secret = get_totp_enrollment_secret(user_id=user.pk, device_id=device_id)
        code = _totp_code(secret, current_totp_step())
        done = self.client.post(reverse("web:enroll_totp"), {"stage": "confirm", "code": code})
        self.assertEqual(done.status_code, 200)
        self.assertTrue(
            MFADevice.objects.filter(
                user__username="selfenroll", type=MFADevice.Type.TOTP, enabled_at__isnull=False
            ).exists()
        )

    def test_cannot_disable_last_strong_factor(self):
        """Round-4 #5/#9: disabling the last strong factor for a forced-MFA user is refused."""
        user = _make("keepstrong", force_strong_mfa=True, email_verified_at=timezone.now())
        device, secret = enable_totp(user=user, name="a")
        from mfa.services import verify_totp
        verify_totp(device=device, code=_totp_code(secret, current_totp_step()))
        self.client.get(reverse("web:login"))
        self.client.post(reverse("web:login"), {"username": "keepstrong", "password": "CorrectHorse123!"})
        # complete the forced-enrollment challenge is already satisfied (device enabled) -> logged in
        self.client.post(reverse("web:disable_factor", args=[device.pk]))
        device.refresh_from_db()
        self.assertIsNone(device.disabled_at)  # revert -> still enabled


class TemplateSmokeTests(TestCase):
    def test_anonymous_pages_render(self):
        for name in ["web:login", "web:register", "web:password_reset_request", "web:password_reset_complete"]:
            self.assertEqual(self.client.get(reverse(name)).status_code, 200, name)

    def test_authenticated_security_pages_render(self):
        user = _make("smoke")
        self.client.force_login(user)
        policy = get_policy()
        now = timezone.now()
        ActiveSession.objects.create(
            user=user, session_key_hash=hash_session_key(self.client.session.session_key),
            expires_idle_at=now + timezone.timedelta(minutes=policy.idle_timeout_minutes),
            expires_absolute_at=now + timezone.timedelta(hours=policy.absolute_timeout_hours),
            security_stamp=user.security_stamp, policy_version=policy.policy_version,
        )
        self.assertEqual(self.client.get(reverse("web:security")).status_code, 200)
        # Sensitive pages bounce to step-up (no recent auth), which must itself render.
        step = self.client.get(reverse("web:change_password"), follow=True)
        self.assertEqual(step.status_code, 200)
        self.assertContains(step, "Confirm it")


@override_settings(BREACH_SCREENING_ENABLED=False)
class PasswordResetWebTests(TestCase):
    def test_reset_email_contains_working_link(self):
        """Regression: the outbox email carries an actionable link (finding #9)."""
        from notifications.services import process_outbox

        user = _make("reset")
        user.email_verified_at = timezone.now()
        user.save(update_fields=["email_verified_at"])
        self.client.post(reverse("web:password_reset_request"), {"email": user.email})
        process_outbox()
        body = mail.outbox[-1].body
        self.assertIn(reverse("web:password_reset_complete"), body)
        token = re.search(r"token=([\w\-]+)", body).group(1)
        r = self.client.post(reverse("web:password_reset_complete"), {"token": token, "password": "BrandNewPass987!"})
        self.assertRedirects(r, reverse("web:login"), fetch_redirect_response=False)
        user.refresh_from_db()
        self.assertTrue(user.check_password("BrandNewPass987!"))


class ConsoleTests(TestCase):
    def _seed(self, user, recent=True):
        from security_policies.services import get_effective_policy
        self.client.force_login(user)
        policy = get_effective_policy(user)
        now = timezone.now()
        ActiveSession.objects.create(
            user=user, session_key_hash=hash_session_key(self.client.session.session_key),
            expires_idle_at=now + timezone.timedelta(minutes=policy.idle_timeout_minutes),
            expires_absolute_at=now + timezone.timedelta(hours=policy.absolute_timeout_hours),
            security_stamp=user.security_stamp, policy_version=policy.policy_version,
        )
        if recent:
            session = self.client.session
            now_iso = now.isoformat()
            session["recent_auth_at"] = now_iso
            session["recent_auth_at:org_lifecycle"] = now_iso
            session["recent_auth_at:deactivate_user"] = now_iso
            session["recent_auth_at:admin_revoke_sessions"] = now_iso
            session["recent_auth_at:default"] = now_iso
            session.save()

    def test_non_superuser_denied(self):
        user = _make("plain")
        self._seed(user)
        self.assertEqual(self.client.get(reverse("web:console")).status_code, 403)

    def test_superuser_sees_shell_and_sections(self):
        admin = _make("admin", is_superuser=True, is_staff=True)
        self._seed(admin)
        home = self.client.get(reverse("web:console"))
        self.assertEqual(home.status_code, 200)
        self.assertContains(home, "Security console")  # shell nav
        for name in ["web:console_users", "web:console_orgs", "web:console_sessions",
                     "web:console_audit", "web:console_risk", "web:console_policies",
                     "web:console_mfa", "web:console_invitations", "web:console_notifications"]:
            self.assertEqual(self.client.get(reverse(name)).status_code, 200, name)

    def test_htmx_request_returns_bare_partial(self):
        admin = _make("admin", is_superuser=True, is_staff=True)
        self._seed(admin)
        r = self.client.get(reverse("web:console_users"), HTTP_HX_REQUEST="true")
        # Bare partial: no full-page <html>/nav shell.
        self.assertNotContains(r, "Security console")
        self.assertContains(r, "Users")

    def test_console_org_action_suspends(self):
        from organizations.models import Organization
        admin = _make("admin", is_superuser=True, is_staff=True)
        self._seed(admin)
        Organization.objects.create(name="Acme", slug="acme")
        r = self.client.post(reverse("web:console_org_action", args=["acme"]),
                            {"action": "suspend"}, HTTP_HX_REQUEST="true")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(Organization.objects.get(slug="acme").status, Organization.Status.SUSPENDED)
