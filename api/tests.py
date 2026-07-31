"""Django unit tests for the api app."""
import json

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from accounts.models import EmailAddress, User
from mfa.models import MFADevice
from mfa.services import _totp_code, current_totp_step, enable_totp, verify_totp
from organizations.models import Organization, OrganizationMembership
from security_policies.services import get_effective_policy
from sessions.models import ActiveSession, TrustedDevice, hash_session_key


def _mk(username, superuser=False, email=None, **kw):
    kw.setdefault("email_verified_at", timezone.now())
    user = User.objects.create_user(
        username=username, email=email or f"{username}@example.test", password="CorrectHorse123!",
        status=User.Status.ACTIVE, is_superuser=superuser, is_staff=superuser, **kw
    )
    EmailAddress.objects.create(user=user, email=user.email, is_primary=True)
    return user


class ApiTestBase(TestCase):
    def auth(self, user, recent=True):
        """Log in with a valid ActiveSession (+ optional recent-auth) so the middleware allows it."""
        self.client.force_login(user)
        policy = get_effective_policy(user)
        now = timezone.now()
        ActiveSession.objects.update_or_create(
            session_key_hash=hash_session_key(self.client.session.session_key),
            defaults=dict(
                user=user,
                expires_idle_at=now + timezone.timedelta(minutes=policy.idle_timeout_minutes),
                expires_absolute_at=now + timezone.timedelta(hours=policy.absolute_timeout_hours),
                security_stamp=user.security_stamp, policy_version=policy.policy_version, revoked_at=None,
            ),
        )
        if recent:
            session = self.client.session
            session["recent_auth_at"] = now.isoformat()
            session.save()
        else:
            session = self.client.session
            session.pop("recent_auth_at", None)
            for key in list(session.keys()):
                if key.startswith("recent_auth_at:"):
                    session.pop(key, None)
            session.save()

    def post(self, name, payload=None, **kwargs):
        return self.client.post(reverse(name, kwargs=kwargs), data=json.dumps(payload or {}),
                                content_type="application/json")


class MeEndpointsTests(ApiTestBase):
    def test_me_and_security_and_sessions(self):
        user = _mk("u")
        self.auth(user)
        self.assertEqual(self.client.get(reverse("api:me")).json()["username"], "u")
        self.assertIn("factors", self.client.get(reverse("api:me_security")).json())
        self.assertIn("sessions", self.client.get(reverse("api:sessions")).json())

    def test_export_requires_recent_auth(self):
        user = _mk("u")
        self.auth(user, recent=False)
        self.assertEqual(self.client.get(reverse("api:me_export")).status_code, 403)
        self.auth(user, recent=True)
        self.assertEqual(self.client.get(reverse("api:me_export")).status_code, 200)

    def test_revoke_own_session_only(self):
        user = _mk("u")
        other = _mk("other")
        other_session = ActiveSession.objects.create(
            user=other, session_key_hash="z" * 64,
            expires_idle_at=timezone.now() + timezone.timedelta(hours=1),
            expires_absolute_at=timezone.now() + timezone.timedelta(hours=12),
        )
        self.auth(user)
        # IDOR check: cannot revoke another user's session.
        r = self.post("api:revoke_session", session_id=other_session.pk)
        self.assertEqual(r.status_code, 404)
        other_session.refresh_from_db()
        self.assertIsNone(other_session.revoked_at)


class MfaEnrollmentApiTests(ApiTestBase):
    def test_totp_enable_confirm_returns_backup_codes(self):
        user = _mk("u")
        self.auth(user)
        r = self.post("api:totp_enable")
        self.assertEqual(r.status_code, 200)
        secret = r.json()["secret"]
        device_id = r.json()["device_id"]
        code = _totp_code(secret, current_totp_step())
        confirm = self.post("api:totp_confirm", {"device_id": device_id, "code": code})
        self.assertEqual(confirm.status_code, 200)
        self.assertTrue(confirm.json()["backup_codes"])  # recovery codes minted
        self.assertTrue(MFADevice.objects.filter(user=user, type=MFADevice.Type.TOTP, enabled_at__isnull=False).exists())

    def test_email_otp_enable_requires_verified_email(self):
        user = _mk("u", email_verified_at=None)
        self.auth(user)
        self.assertEqual(self.post("api:email_otp_enable").status_code, 400)
        user.email_verified_at = timezone.now()
        user.save(update_fields=["email_verified_at"])
        self.assertEqual(self.post("api:email_otp_enable").status_code, 200)

    def test_disable_last_strong_factor_refused(self):
        user = _mk("u", force_strong_mfa=True)
        device, secret = enable_totp(user=user, name="a")
        verify_totp(device=device, code=_totp_code(secret, current_totp_step()))
        self.auth(user)
        r = self.post("api:disable_factor", factor_id=device.pk)
        self.assertEqual(r.status_code, 409)
        device.refresh_from_db()
        self.assertIsNone(device.disabled_at)


class TrustedDeviceApiTests(ApiTestBase):
    def test_trust_and_revoke(self):
        user = _mk("u")
        self.auth(user, recent=True)
        r = self.post("api:trust_current_device", {"name": "Laptop"})
        self.assertEqual(r.status_code, 200)
        did = r.json()["id"]
        self.assertTrue(TrustedDevice.objects.filter(pk=did, user=user).exists())
        self.auth(user, recent=False)
        self.assertEqual(self.post("api:revoke_trusted_device", device_id=did).status_code, 403)
        self.auth(user, recent=True)
        self.assertEqual(self.post("api:revoke_trusted_device", device_id=did).status_code, 200)


class OrgManagementApiTests(ApiTestBase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.owner = _mk("owner")
        OrganizationMembership.objects.create(
            organization=self.org, user=self.owner, role=OrganizationMembership.Role.OWNER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )

    def test_invite_change_role_remove(self):
        member = _mk("member", email="member@example.test")
        OrganizationMembership.objects.create(
            organization=self.org, user=member, role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        self.auth(self.owner)
        self.assertEqual(self.post("api:org_invite", {"email": "x@example.test", "role": "member"}, slug="acme").status_code, 200)
        self.assertEqual(self.post("api:org_change_member_role", {"role": "staff"}, slug="acme", user_id=member.pk).status_code, 200)
        member_m = OrganizationMembership.objects.get(user=member, organization=self.org)
        self.assertEqual(member_m.role, "staff")
        self.assertEqual(self.post("api:org_remove_member", slug="acme", user_id=member.pk).status_code, 200)
        member_m.refresh_from_db()
        self.assertEqual(member_m.status, OrganizationMembership.Status.REMOVED)

    def test_non_admin_cannot_invite(self):
        member = _mk("member")
        OrganizationMembership.objects.create(
            organization=self.org, user=member, role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        self.auth(member)
        self.assertEqual(self.post("api:org_invite", {"email": "x@example.test", "role": "member"}, slug="acme").status_code, 403)

    def test_org_policy_update_bumps_version(self):
        self.auth(self.owner)
        r = self.post("api:org_update_policy", {"idle_timeout_minutes": 10}, slug="acme")
        self.assertEqual(r.status_code, 200)
        self.assertGreater(r.json()["policy_version"], 1)


class AdminApiTests(ApiTestBase):
    def test_admin_endpoints_require_superuser(self):
        user = _mk("plain")
        self.auth(user)
        self.assertEqual(self.client.get(reverse("api:admin_users")).status_code, 403)
        self.assertEqual(self.client.get(reverse("api:admin_audit_events")).status_code, 403)

    def test_superuser_lists_and_org_lifecycle(self):
        admin = _mk("admin", superuser=True)
        Organization.objects.create(name="Acme", slug="acme")
        self.auth(admin)
        self.assertIn("users", self.client.get(reverse("api:admin_users")).json())
        self.assertIn("page", self.client.get(reverse("api:admin_audit_events")).json())
        self.assertEqual(self.post("api:admin_org_suspend", {"action": "suspend"}, slug="acme").status_code, 200)
        self.assertEqual(Organization.objects.get(slug="acme").status, Organization.Status.SUSPENDED)

    def test_admin_deactivate_requires_management_rights(self):
        admin = _mk("admin", superuser=True)
        target = _mk("target")
        self.auth(admin)
        self.assertEqual(self.post("api:admin_deactivate_user", {"reason": "x"}, user_id=target.pk).status_code, 200)
        target.refresh_from_db()
        self.assertEqual(target.status, User.Status.DEACTIVATED)


class AuthEndpointsTests(ApiTestBase):
    def test_status_and_login(self):
        _mk("u")
        r = self.client.post(reverse("api:auth_login"),
                             data=json.dumps({"username": "u", "password": "CorrectHorse123!"}),
                             content_type="application/json")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(self.client.get(reverse("api:auth_status")).json()["authenticated"])

    def test_pending_user_login_signals_verification(self):
        u = User.objects.create_user(username="pend", email="pend@example.test",
                                     password="CorrectHorse123!", status=User.Status.PENDING_ACTIVATION)
        EmailAddress.objects.create(user=u, email=u.email, is_primary=True)
        r = self.client.post(reverse("api:auth_login"),
                             data=json.dumps({"username": "pend", "password": "CorrectHorse123!"}),
                             content_type="application/json")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["error"]["code"], "email_verification_required")


class CrossTenantIsolationMatrixTests(ApiTestBase):
    """
    §10a/§27 invariant: a requester authenticated into org A gets identical DENY behavior on
    every tenant-scoped route when targeting org B, regardless of their role in A. Parametrized
    so a newly added tenant route can't silently skip isolation.
    """

    def setUp(self):
        # Requester is OWNER of A (max rights in their own org) but has no membership in B.
        self.actor = _mk("owner_a")
        self.org_a = Organization.objects.create(name="A", slug="orga")
        OrganizationMembership.objects.create(
            organization=self.org_a, user=self.actor, role=OrganizationMembership.Role.OWNER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        # A real member of org A (positive-control target for role/remove).
        self.a_member = _mk("member_a", email="member_a@example.test")
        OrganizationMembership.objects.create(
            organization=self.org_a, user=self.a_member, role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        # Foreign org B with its own member (a plausible IDOR target).
        self.org_b = Organization.objects.create(name="B", slug="orgb")
        self.b_member = _mk("member_b", email="member_b@example.test")
        OrganizationMembership.objects.create(
            organization=self.org_b, user=self.b_member, role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        self.auth(self.actor)

    def _routes(self, slug, uid):
        return [
            ("GET", reverse("api:organization_members", kwargs={"slug": slug}), None),
            ("POST", reverse("api:org_invite", kwargs={"slug": slug}), {"email": "x@example.test", "role": "member"}),
            ("POST", reverse("api:org_change_member_role", kwargs={"slug": slug, "user_id": uid}), {"role": "staff"}),
            ("POST", reverse("api:org_remove_member", kwargs={"slug": slug, "user_id": uid}), {"role": "member"}),
            ("POST", reverse("api:org_update_policy", kwargs={"slug": slug}), {"idle_timeout_minutes": 10}),
        ]

    def _call(self, method, url, body):
        if method == "GET":
            return self.client.get(url)
        return self.client.post(url, data=json.dumps(body or {}), content_type="application/json")

    def test_foreign_org_routes_all_deny(self):
        for method, url, body in self._routes("orgb", self.b_member.pk):
            with self.subTest(route=url):
                r = self._call(method, url, body)
                self.assertIn(r.status_code, (403, 404), f"{method} {url} -> {r.status_code} (expected deny)")

    def test_own_org_routes_are_reachable(self):
        # Positive control: the same routes on the requester's OWN org are not denied.
        for method, url, body in self._routes("orga", self.a_member.pk):
            with self.subTest(route=url):
                r = self._call(method, url, body)
                self.assertNotIn(r.status_code, (403, 404), f"{method} {url} -> {r.status_code} (should be reachable)")
