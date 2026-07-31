"""Django unit tests for the ops app."""
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from accounts.models import EmailAddress, User
from accounts.services import erase_user, export_user_data
from mfa.models import MFADevice
from organizations.models import Organization, OrganizationMembership
from passwords.models import PasswordResetChallenge
from passwords.services import request_email_verification, verify_email
from security_events.models import AuditEvent, SecurityRiskEvent
from sessions.models import ActiveSession, hash_session_key


def _mk(username="u", email=None, **kw):
    kw.setdefault("email_verified_at", timezone.now())
    user = User.objects.create_user(
        username=username, email=email or f"{username}@example.test",
        password="CorrectHorse123!", status=User.Status.ACTIVE, **kw
    )
    EmailAddress.objects.create(user=user, email=user.email, is_primary=True)
    return user


# ---- Round 2 regressions (restored) -----------------------------------------

class Round2RegressionTests(TestCase):
    def test_email_change_verify_succeeds(self):
        user = _mk()
        _c, token = request_email_verification(user=user, email="new@example.test")
        self.assertTrue(verify_email(token=token))
        self.assertEqual(EmailAddress.objects.filter(user=user, is_primary=True).count(), 1)
        user.refresh_from_db()
        self.assertEqual(user.email, "new@example.test")

    def test_api_csrf_envelope_and_bootstrap(self):
        c = Client(enforce_csrf_checks=True)
        bad = c.post(reverse("api:auth_login"), data="{}", content_type="application/json")
        self.assertEqual(bad.status_code, 403)
        self.assertEqual(bad.json()["error"]["code"], "csrf_failed")
        c.get(reverse("api:auth_status"))
        token = c.cookies["csrftoken"].value
        ok = c.post(reverse("api:auth_login"), data="{}", content_type="application/json", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(ok.status_code, 401)

    def test_request_id_header_present(self):
        self.assertTrue(self.client.get(reverse("web:login")).get("X-Request-ID"))

    def test_cross_tenant_members_denied(self):
        user = _mk("tenant")
        org_a = Organization.objects.create(name="A", slug="aa")
        Organization.objects.create(name="B", slug="bb")
        OrganizationMembership.objects.create(
            organization=org_a, user=user, role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        self.client.force_login(user)
        from security_policies.services import get_policy
        policy = get_policy()
        now = timezone.now()
        ActiveSession.objects.create(
            user=user, session_key_hash=hash_session_key(self.client.session.session_key),
            expires_idle_at=now + timezone.timedelta(minutes=policy.idle_timeout_minutes),
            expires_absolute_at=now + timezone.timedelta(hours=policy.absolute_timeout_hours),
            security_stamp=user.security_stamp, policy_version=policy.policy_version,
        )
        self.assertEqual(self.client.get(reverse("api:organization_members", args=["aa"])).status_code, 200)
        self.assertEqual(self.client.get(reverse("api:organization_members", args=["bb"])).status_code, 404)

    def test_erasure_anonymizes_but_preserves_audit(self):
        admin = _mk("admin1", is_superuser=True, is_staff=True)
        user = _mk("victim")
        MFADevice.objects.create(user=user, type=MFADevice.Type.TOTP, name="a", enabled_at=timezone.now())
        before = AuditEvent.objects.count()
        erase_user(actor=admin, user=user)
        user.refresh_from_db()
        self.assertEqual(user.email, f"erased_{user.pk}@erased.invalid")
        self.assertFalse(MFADevice.objects.filter(user=user).exists())
        self.assertFalse(user.has_usable_password())
        self.assertGreater(AuditEvent.objects.count(), before)

    def test_export_contains_account_data(self):
        user = _mk("exporter")
        data = export_user_data(user)
        self.assertEqual(data["user"]["username"], "exporter")
        self.assertIn("sessions", data)


# ---- Round 3 regressions -----------------------------------------------------

class Round3RegressionTests(TestCase):
    def test_same_device_emits_single_new_device_risk_event(self):
        """Fix #1: a returning (same) device does not re-fire the new-device risk event."""
        _mk("flood")
        c = Client()
        c.get(reverse("web:login"))  # establishes the device cookie
        c.post(reverse("web:login"), {"username": "flood", "password": "CorrectHorse123!"})
        c.post(reverse("web:logout"))
        c.post(reverse("web:login"), {"username": "flood", "password": "CorrectHorse123!"})
        self.assertEqual(
            SecurityRiskEvent.objects.filter(user__username="flood", event_type="login.new_device").count(), 1
        )

    def test_erasure_scrubs_challenge_pii(self):
        """Fix #2: erase removes/scrubs PII in reset challenges."""
        admin = _mk("admin2", is_superuser=True, is_staff=True)
        user = _mk("victim2")
        PasswordResetChallenge.objects.create(
            user=user, token_hash="h" * 40, expires_at=timezone.now() + timezone.timedelta(hours=1),
            requester_ip="203.0.113.9", requester_user_agent="secret-device",
        )
        erase_user(actor=admin, user=user)
        self.assertFalse(PasswordResetChallenge.objects.filter(user=user).exists())

    def test_erasure_requires_superuser(self):
        """Fix #8: an org admin can no longer erase; only platform admin (or self)."""
        from django.core.exceptions import PermissionDenied
        org = Organization.objects.create(name="O", slug="o")
        admin = _mk("orgadmin")
        target = _mk("member1")
        for u, role in [(admin, OrganizationMembership.Role.ADMIN), (target, OrganizationMembership.Role.MEMBER)]:
            OrganizationMembership.objects.create(
                organization=org, user=u, role=role,
                status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
            )
        with self.assertRaises(PermissionDenied):
            erase_user(actor=admin, user=target)

    @override_settings(BREACH_SCREENING_ENABLED=False)
    def test_register_does_not_leak_db_error(self):
        """Fix #3: duplicate registration shows a generic message, not raw SQL."""
        _mk("dupe", email="dupe@example.test")
        r = self.client.post(
            reverse("web:register"),
            {"username": "dupe", "email": "other@example.test", "password": "Zx9!qwerty12"},
        )
        self.assertNotIn("UNIQUE", r.content.decode().upper())


class Round4RegressionTests(TestCase):
    def _seed_session(self, user):
        self.client.force_login(user)
        from security_policies.services import get_policy
        policy = get_policy()
        now = timezone.now()
        ActiveSession.objects.create(
            user=user, session_key_hash=hash_session_key(self.client.session.session_key),
            expires_idle_at=now + timezone.timedelta(minutes=policy.idle_timeout_minutes),
            expires_absolute_at=now + timezone.timedelta(hours=policy.absolute_timeout_hours),
            security_stamp=user.security_stamp, policy_version=policy.policy_version,
        )

    def test_suspended_org_denies_member_access(self):
        """Fix #1: a member of a suspended org is denied (403)."""
        from organizations.services import suspend_organization
        superadmin = _mk("super", is_superuser=True, is_staff=True)
        user = _mk("member")
        org = Organization.objects.create(name="Acme", slug="acme")
        OrganizationMembership.objects.create(
            organization=org, user=user, role=OrganizationMembership.Role.STAFF,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        suspend_organization(actor=superadmin, organization=org)
        self._seed_session(user)
        r = self.client.get(reverse("api:organization_members", args=["acme"]))
        self.assertEqual(r.status_code, 403)

    def test_suspend_requires_platform_admin(self):
        """Fix #2: org lifecycle requires superuser."""
        from django.core.exceptions import PermissionDenied

        from organizations.services import suspend_organization
        org = Organization.objects.create(name="Acme", slug="acme")
        actor = _mk("nobody")
        with self.assertRaises(PermissionDenied):
            suspend_organization(actor=actor, organization=org)

    def test_close_org_removes_memberships(self):
        from organizations.services import close_organization
        superadmin = _mk("super", is_superuser=True, is_staff=True)
        user = _mk("m")
        org = Organization.objects.create(name="Acme", slug="acme")
        OrganizationMembership.objects.create(
            organization=org, user=user, role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        close_organization(actor=superadmin, organization=org)
        m = OrganizationMembership.objects.get(user=user, organization=org)
        self.assertEqual(m.status, OrganizationMembership.Status.REMOVED)

    def test_email_otp_enrollment_makes_it_a_login_factor(self):
        """Fix #3: email OTP can be enrolled and then appears as an available login factor."""
        from accounts.services import available_factor_types
        from mfa.services import enable_email_otp
        user = _mk("eo")
        self.assertNotIn("email_otp", available_factor_types(user))
        enable_email_otp(user=user)
        self.assertIn("email_otp", available_factor_types(user))

    def test_privileged_user_cannot_complete_login_with_email_otp(self):
        """Fix #4: a strong-factor-required user may not use email OTP to complete login."""
        from accounts.services import allowed_login_methods
        from mfa.services import _totp_code, current_totp_step, enable_email_otp, enable_totp, verify_totp
        user = _mk("adminx", force_strong_mfa=True)
        enable_email_otp(user=user)
        device, secret = enable_totp(user=user, name="a")
        verify_totp(device=device, code=_totp_code(secret, current_totp_step()))
        methods = allowed_login_methods(user)
        self.assertIn("totp", methods)
        self.assertNotIn("email_otp", methods)

    def test_complete_login_rejects_inactive_account(self):
        """Fix #8: a user deactivated during awaiting-2FA cannot complete login."""
        from django.contrib.sessions.backends.db import SessionStore
        from django.test import RequestFactory

        from accounts.services import AccountInactive, complete_login
        user = _mk("mid")
        user.status = User.Status.DEACTIVATED
        user.is_active = False
        user.save(update_fields=["status", "is_active"])
        request = RequestFactory().post("/login/2fa/")
        request.session = SessionStore()
        with self.assertRaises(AccountInactive):
            complete_login(request=request, user=user)


class Round5RegressionTests(TestCase):
    def _org(self, user, role, status=Organization.Status.ACTIVE, **policy):
        org = Organization.objects.create(name="Acme", slug="acme", status=status)
        OrganizationMembership.objects.create(
            organization=org, user=user, role=role,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        if policy:
            from security_policies.models import SecurityPolicy
            SecurityPolicy.objects.create(organization=org, **policy)
        return org

    def _session_for(self, user):
        from django.contrib.sessions.backends.db import SessionStore
        from django.test import RequestFactory

        from sessions.services import create_active_session
        req = RequestFactory().get("/")
        req.session = SessionStore()
        req.session.create()
        return create_active_session(req, user)

    def test_org_policy_idle_timeout_is_applied(self):
        """Fix #1: a user's org policy idle timeout is honored at session creation."""
        user = _mk("m")
        self._org(user, OrganizationMembership.Role.MEMBER, idle_timeout_minutes=5)
        session = self._session_for(user)
        window = (session.expires_idle_at - session.created_at).total_seconds() / 60
        self.assertAlmostEqual(window, 5, delta=1)

    def test_suspended_org_does_not_force_mfa(self):
        """Fix #6: a suspended org's admin role no longer imposes MFA requirements."""
        from accounts.services import user_mfa_required
        user = _mk("adm")
        self._org(user, OrganizationMembership.Role.ADMIN, status=Organization.Status.SUSPENDED)
        # require_2fa_for_admins defaults True on the global policy, but the org is suspended.
        self.assertFalse(user_mfa_required(user))

    def test_resend_verification_endpoint_exists_and_is_enumeration_safe(self):
        """Fix #3: an unverified user can request a fresh link; response is generic."""
        User.objects.create_user(username="pending", email="p@example.test",
                                 password="CorrectHorse123!", status=User.Status.PENDING_ACTIVATION)
        r = self.client.post(reverse("web:resend_verification"), {"email": "p@example.test"})
        self.assertRedirects(r, reverse("web:login"), fetch_redirect_response=False)

    def test_pending_login_raises_email_verification_required(self):
        """Fix #4: correct password on a pending account signals verification, not bad creds."""
        from django.contrib.sessions.backends.db import SessionStore
        from django.test import RequestFactory

        from accounts.services import EmailVerificationRequired, authenticate_password_step
        User.objects.create_user(username="pend2", email="pend2@example.test",
                                 password="CorrectHorse123!", status=User.Status.PENDING_ACTIVATION)
        req = RequestFactory().post("/login/", REMOTE_ADDR="10.0.0.1")
        req.session = SessionStore()
        with self.assertRaises(EmailVerificationRequired):
            authenticate_password_step(request=req, username="pend2", password="CorrectHorse123!")

    def test_invite_and_accept_flow(self):
        """Fix #2: invite + accept membership works end-to-end through the services."""
        from organizations.services import accept_invitation, invite_user
        owner = _mk("owner")
        invitee = _mk("invitee", email="invitee@example.test")
        org = Organization.objects.create(name="Acme", slug="acme")
        OrganizationMembership.objects.create(
            organization=org, user=owner, role=OrganizationMembership.Role.OWNER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        _inv, token = invite_user(actor=owner, organization=org, email="invitee@example.test", role="member")
        membership = accept_invitation(user=invitee, token=token)
        self.assertEqual(membership.role, OrganizationMembership.Role.MEMBER)
        self.assertEqual(membership.status, OrganizationMembership.Status.ACTIVE)


class HardeningTests(TestCase):
    @override_settings(BREACH_SCREENING_ENABLED=True, ENVIRONMENT="production", HIBP_BREAKER_THRESHOLD=3)
    def test_hibp_circuit_breaker_degrades_gracefully(self):
        """Fix #7: a sustained HIBP outage trips the breaker and fails OPEN (with alert)."""
        from unittest.mock import patch

        from django.core.cache import cache

        from passwords.services import screen_breached_password
        from security_events.models import SecurityRiskEvent
        cache.clear()
        with patch("passwords.services.urlopen", side_effect=OSError("down")):
            # First (threshold-1) failures still fail closed in production.
            for _ in range(2):
                with self.assertRaises(ValueError):
                    screen_breached_password("anything")
            # Breaker now open -> subsequent calls degrade (no raise) + emit a high-severity alert.
            screen_breached_password("anything")
            screen_breached_password("anything")
        self.assertTrue(SecurityRiskEvent.objects.filter(event_type="hibp.circuit_open", severity="high").exists())

    @override_settings(API_RATE_LIMIT_PER_MINUTE=2)
    def test_api_rate_limit(self):
        """Fix #6: the /api surface has a per-principal ceiling returning 429."""
        from django.core.cache import cache
        cache.clear()
        codes = [self.client.get(reverse("api:auth_status")).status_code for _ in range(3)]
        self.assertEqual(codes[-1], 429)

    def test_metrics_endpoint(self):
        r = self.client.get("/metrics")
        self.assertEqual(r.status_code, 200)
        self.assertIn("fa_active_sessions", r.content.decode())

    @override_settings(METRICS_TOKEN="secret")
    def test_metrics_token_guard(self):
        self.assertEqual(self.client.get("/metrics").status_code, 403)
        self.assertEqual(self.client.get("/metrics", HTTP_AUTHORIZATION="Bearer secret").status_code, 200)

    def test_cleanup_expired_removes_old_challenges(self):
        from django.core.management import call_command

        from passwords.models import PasswordResetChallenge
        user = _mk("cu")
        ch = PasswordResetChallenge.objects.create(
            user=user, token_hash="h" * 40, expires_at=timezone.now() - timezone.timedelta(days=40),
        )
        PasswordResetChallenge.objects.filter(pk=ch.pk).update(created_at=timezone.now() - timezone.timedelta(days=40))
        call_command("cleanup_expired")
        self.assertFalse(PasswordResetChallenge.objects.filter(pk=ch.pk).exists())

    def test_close_org_purges_tenant_data(self):
        from organizations.models import Invitation
        from organizations.services import close_organization
        from security_policies.models import SecurityPolicy
        admin = _mk("super5", is_superuser=True, is_staff=True)
        org = Organization.objects.create(name="Acme", slug="acme")
        SecurityPolicy.objects.create(organization=org, idle_timeout_minutes=5)
        inv = Invitation.objects.create(
            organization=org, email="x@example.test", intended_role="member",
            token_hash="t" * 40, expires_at=timezone.now() + timezone.timedelta(days=7),
        )
        close_organization(actor=admin, organization=org)
        self.assertFalse(SecurityPolicy.objects.filter(organization=org).exists())
        self.assertFalse(Invitation.objects.filter(pk=inv.pk).exists())

    @override_settings(FEATURE_FLAGS={"new_thing": True})
    def test_feature_flags(self):
        from config.flags import feature_enabled
        self.assertTrue(feature_enabled("new_thing"))
        self.assertFalse(feature_enabled("missing"))

    def test_legal_pages_render(self):
        self.assertEqual(self.client.get(reverse("web:terms")).status_code, 200)
        self.assertEqual(self.client.get(reverse("web:privacy")).status_code, 200)


class EffectivePolicyMemoTests(TestCase):
    def test_effective_policy_is_memoized_per_user_instance(self):
        from security_policies.services import get_effective_policy
        user = _mk("memo")
        get_effective_policy(user)  # warms the per-instance cache
        # Repeat calls on the same user instance hit the memo -> zero DB queries.
        with self.assertNumQueries(0):
            get_effective_policy(user)
            get_effective_policy(user)


class AlertWebhookTests(TestCase):
    def _payload(self):
        import json
        return json.dumps({"status": "firing", "alerts": [
            {"status": "firing", "labels": {"alertname": "ReadinessDown", "severity": "page"},
             "annotations": {"summary": "readyz failing"}}]})

    def test_webhook_accepts_alertmanager_payload(self):
        r = self.client.post("/internal/alerts", data=self._payload(), content_type="application/json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["received"], 1)

    @override_settings(ALERT_WEBHOOK_TOKEN="s3cret")
    def test_webhook_token_guard(self):
        self.assertEqual(self.client.post("/internal/alerts", data=self._payload(),
                                          content_type="application/json").status_code, 403)
        ok = self.client.post("/internal/alerts", data=self._payload(),
                              content_type="application/json", HTTP_AUTHORIZATION="Bearer s3cret")
        self.assertEqual(ok.status_code, 200)
