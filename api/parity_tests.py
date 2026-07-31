"""Parametrized web/API parity checks for sensitive actions and tenant isolation."""
import json

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from accounts.models import EmailAddress, User
from organizations.models import Organization, OrganizationMembership
from security_policies.services import get_effective_policy
from sessions.models import ActiveSession, hash_session_key


def _mk(username, **kw):
    kw.setdefault("email_verified_at", timezone.now())
    email = kw.pop("email", f"{username}@example.test")
    user = User.objects.create_user(
        username=username, email=email, password="CorrectHorse123!",
        status=User.Status.ACTIVE, **kw
    )
    EmailAddress.objects.create(user=user, email=user.email, is_primary=True)
    return user


class ApiParityMatrixTests(TestCase):
    def _auth(self, user, recent=False):
        self.client.force_login(user)
        policy = get_effective_policy(user)
        now = timezone.now()
        ActiveSession.objects.update_or_create(
            session_key_hash=hash_session_key(self.client.session.session_key),
            defaults=dict(
                user=user,
                expires_idle_at=now + timezone.timedelta(minutes=policy.idle_timeout_minutes),
                expires_absolute_at=now + timezone.timedelta(hours=policy.absolute_timeout_hours),
                security_stamp=user.security_stamp,
                policy_version=policy.policy_version,
                revoked_at=None,
            ),
        )
        if recent:
            session = self.client.session
            session["recent_auth_at"] = now.isoformat()
            session["recent_auth_at:change_password"] = now.isoformat()
            session["recent_auth_at:change_email"] = now.isoformat()
            session.save()

    def test_password_change_endpoints_require_recent_auth(self):
        user = _mk("paritypw")
        self._auth(user, recent=False)
        api_r = self.client.post(
            reverse("api:me_password_change"),
            data=json.dumps({"current_password": "CorrectHorse123!", "password": "NewPass987!"}),
            content_type="application/json",
        )
        self.assertEqual(api_r.status_code, 403)
        web_r = self.client.get(reverse("web:change_password"))
        self.assertEqual(web_r.status_code, 302)
        self.assertIn(reverse("web:step_up"), web_r["Location"])

    def test_non_member_invite_returns_404(self):
        org = Organization.objects.create(name="Hidden", slug="hidden")
        insider = _mk("insider")
        outsider = _mk("outsider")
        OrganizationMembership.objects.create(
            organization=org, user=insider, role=OrganizationMembership.Role.ADMIN,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        self._auth(outsider, recent=True)
        r = self.client.post(
            reverse("api:org_invite", kwargs={"slug": "hidden"}),
            data=json.dumps({"email": "new@example.test", "role": "member"}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 404)

    def test_non_member_change_role_returns_404(self):
        org = Organization.objects.create(name="Hidden", slug="hidden2")
        insider = _mk("insider2")
        outsider = _mk("outsider2")
        target = _mk("target2", email="target2@example.test")
        OrganizationMembership.objects.create(
            organization=org, user=insider, role=OrganizationMembership.Role.ADMIN,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        OrganizationMembership.objects.create(
            organization=org, user=target, role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        self._auth(outsider, recent=True)
        r = self.client.post(
            reverse("api:org_change_member_role", kwargs={"slug": "hidden2", "user_id": target.pk}),
            data=json.dumps({"role": "staff"}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 404)

    def test_webauthn_register_requires_recent_auth(self):
        user = _mk("paritywa")
        self._auth(user, recent=False)
        r = self.client.post(reverse("api:webauthn_register_options"), content_type="application/json")
        self.assertEqual(r.status_code, 403)

    def test_security_risk_events_are_append_only(self):
        from security_events.models import SecurityRiskEvent

        user = _mk("risky")
        event = SecurityRiskEvent.objects.create(user=user, event_type="test.append_only", severity="low")
        with self.assertRaises(RuntimeError):
            SecurityRiskEvent.objects.filter(pk=event.pk).delete()
        with self.assertRaises(RuntimeError):
            event.delete()

    def test_auth_scoped_passkey_register_blocked_when_enrolled(self):
        from mfa.models import MFADevice

        user = _mk("enrolledwa", force_strong_mfa=False)
        MFADevice.objects.create(
            user=user, type=MFADevice.Type.TOTP, name="a", enabled_at=timezone.now()
        )
        self.client.post(
            reverse("api:auth_login"),
            data=json.dumps({"username": user.username, "password": "CorrectHorse123!"}),
            content_type="application/json",
        )
        r = self.client.post(reverse("api:auth_webauthn_register_options"), content_type="application/json")
        self.assertEqual(r.status_code, 403)

    def test_revoke_session_requires_recent_auth(self):
        user = _mk("parityrevoke")
        self._auth(user, recent=False)
        session = self.client.session
        from sessions.models import hash_session_key

        active = ActiveSession.objects.get(session_key_hash=hash_session_key(session.session_key))
        r = self.client.post(reverse("api:revoke_session", kwargs={"session_id": active.pk}), content_type="application/json")
        self.assertEqual(r.status_code, 403)
