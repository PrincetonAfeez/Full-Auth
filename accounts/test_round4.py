"""Regression tests for accounts (security audit round)."""
import json

from django.test import TestCase
from django.urls import reverse

from accounts.models import User
from mfa.models import BackupCode
from mfa.services import generate_backup_codes, verify_login_factor
from organizations.models import Organization, OrganizationMembership
from security_policies.models import SecurityPolicy
from security_policies.services import get_effective_policy


class _StubConnector:
    def validate_config(self, config):
        return None

    def authorization_url(self, request, provider, state):
        return reverse("sso:callback", args=[provider.slug]) + f"?state={state}"

    def complete(self, request, provider):
        from sso.connectors import ExternalIdentity

        return ExternalIdentity(subject="ext-123", email="ssouser@example.test", email_verified=True)


class Round4SecurityTests(TestCase):
    def setUp(self):
        from accounts.models import EmailAddress
        from django.utils import timezone

        self.user = User.objects.create_user(
            username="r4user",
            email="r4@example.test",
            password="CorrectHorse123!",
            status=User.Status.ACTIVE,
            email_verified_at=timezone.now(),
        )
        EmailAddress.objects.create(user=self.user, email=self.user.email, is_primary=True, verified_at=timezone.now())
        self.codes = generate_backup_codes(user=self.user)
        org_a = Organization.objects.create(name="Org A", slug="org-a")
        org_b = Organization.objects.create(name="Org B", slug="org-b")
        SecurityPolicy.objects.create(organization=org_a, allowed_2fa_methods=["webauthn"])
        SecurityPolicy.objects.create(organization=org_b, allowed_2fa_methods=["totp"])
        for org in (org_a, org_b):
            OrganizationMembership.objects.create(
                organization=org,
                user=self.user,
                role=OrganizationMembership.Role.MEMBER,
                status=OrganizationMembership.Status.ACTIVE,
            )

    def test_backup_code_bypass_via_webauthn_method_blocked(self):
        request = self.client.request()
        request.session = self.client.session
        ok = verify_login_factor(
            request=request, user=self.user, method="webauthn", code=self.codes[0]
        )
        self.assertFalse(ok)
        self.assertTrue(BackupCode.objects.filter(user=self.user, used_at__isnull=True).exists())

    def test_empty_2fa_intersection_falls_back_to_global(self):
        policy = get_effective_policy(self.user)
        self.assertIn("totp", policy.allowed_2fa_methods)
        self.assertIn("webauthn", policy.allowed_2fa_methods)

    def test_sso_unconfigured_redirects_to_login(self):
        from sso.models import IdentityProvider

        provider = IdentityProvider.objects.create(
            slug="broken-oidc", name="Broken", protocol=IdentityProvider.Protocol.OIDC, enabled=True, config={}
        )
        r = self.client.get(reverse("sso:begin", args=[provider.slug]))
        self.assertRedirects(r, reverse("web:login"), fetch_redirect_response=False)


class Round4ApiTests(TestCase):
    def test_auth_2fa_rejects_webauthn_method_with_backup_code(self):
        from accounts.models import EmailAddress
        from django.utils import timezone
        from mfa.models import MFADevice

        user = User.objects.create_user(
            username="api2fa",
            email="api2fa@example.test",
            password="CorrectHorse123!",
            status=User.Status.ACTIVE,
            email_verified_at=timezone.now(),
        )
        EmailAddress.objects.create(user=user, email=user.email, is_primary=True, verified_at=timezone.now())
        MFADevice.objects.create(
            user=user, type=MFADevice.Type.WEBAUTHN, name="k", enabled_at=timezone.now()
        )
        codes = generate_backup_codes(user=user)
        from security_policies.services import get_policy

        global_policy = get_policy()
        global_policy.allowed_2fa_methods = ["webauthn"]
        global_policy.save(update_fields=["allowed_2fa_methods"])

        self.client.post(
            reverse("api:auth_login"),
            data=json.dumps({"username": user.username, "password": "CorrectHorse123!"}),
            content_type="application/json",
        )
        r = self.client.post(
            reverse("api:auth_2fa_verify"),
            data=json.dumps({"method": "webauthn", "code": codes[0]}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 401)
        self.assertTrue(BackupCode.objects.filter(user=user, used_at__isnull=True).exists())
