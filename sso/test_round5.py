"""Regression tests for sso (security audit round)."""
import json
from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings
from django.urls import reverse

from accounts.models import User
from organizations.models import Organization, OrganizationMembership
from sso.connectors import _REGISTRY, ExternalIdentity, SSOConnector, register_connector
from sso.models import FederatedIdentity, IdentityProvider
from sso.oidc_connector import ReferenceOIDCConnector, _merge_userinfo


class _StubConnector(SSOConnector):
    def validate_config(self, config):
        return None

    def authorization_url(self, request, provider, state):
        return reverse("sso:callback", args=[provider.slug]) + f"?state={state}"

    def complete(self, request, provider):
        return ExternalIdentity(subject="ext-org", email="orguser@example.test", email_verified=True)


class OrgScopedSSOTests(TestCase):
    def setUp(self):
        register_connector("oidc", _StubConnector())
        self.org = Organization.objects.create(name="Tenant", slug="tenant")
        self.provider = IdentityProvider.objects.create(
            slug="tenant-oidc",
            name="Tenant OIDC",
            protocol=IdentityProvider.Protocol.OIDC,
            enabled=True,
            organization=self.org,
            auto_provision=False,
        )

    def tearDown(self):
        _REGISTRY.pop("oidc", None)

    def test_sso_denied_without_membership_when_provision_disabled(self):
        self.client.get(reverse("sso:begin", args=[self.provider.slug]))
        r = self.client.get(reverse("sso:callback", args=[self.provider.slug]) + f"?state={self.client.session['sso_state']}")
        self.assertRedirects(r, reverse("web:login"), fetch_redirect_response=False)
        self.assertFalse(User.objects.filter(email="orguser@example.test").exists())

    def test_sso_auto_adds_membership_when_provision_enabled(self):
        self.provider.auto_provision = True
        self.provider.save(update_fields=["auto_provision"])
        self.client.get(reverse("sso:begin", args=[self.provider.slug]))
        r = self.client.get(reverse("sso:callback", args=[self.provider.slug]) + f"?state={self.client.session['sso_state']}")
        self.assertRedirects(r, reverse("web:dashboard"), fetch_redirect_response=False)
        user = User.objects.get(email="orguser@example.test")
        self.assertTrue(
            OrganizationMembership.objects.active().filter(organization=self.org, user=user).exists()
        )


class UserinfoMergeTests(TestCase):
    def test_userinfo_cannot_override_id_token_subject(self):
        claims = {"sub": "from-token", "email": "a@test", "email_verified": True}
        profile = {"sub": "from-userinfo", "email": "b@test", "email_verified": False}
        subject, email, verified = _merge_userinfo(claims=claims, profile=profile)
        self.assertEqual(subject, "from-token")
        self.assertEqual(email, "a@test")
        self.assertTrue(verified)


@override_settings(PUBLIC_BASE_URL="https://auth.example.com")
class OIDCRedirectUriTests(TestCase):
    def test_redirect_uri_uses_public_base_url(self):
        from sso.oidc_connector import oidc_redirect_uri

        provider = IdentityProvider.objects.create(
            slug="uri-test",
            name="URI",
            protocol=IdentityProvider.Protocol.OIDC,
            enabled=True,
        )
        self.assertEqual(
            oidc_redirect_uri(provider),
            "https://auth.example.com/sso/uri-test/callback/",
        )

    def test_authorization_url_contains_public_redirect_uri(self):
        from sso.oidc_connector import ReferenceOIDCConnector

        provider = IdentityProvider.objects.create(
            slug="uri-test2",
            name="URI2",
            protocol=IdentityProvider.Protocol.OIDC,
            enabled=True,
            config={
                "client_id": "cid",
                "client_secret": "sec",
                "authorization_endpoint": "https://idp.example/authorize",
                "token_endpoint": "https://idp.example/token",
                "issuer": "https://idp.example",
                "jwks_uri": "https://idp.example/jwks",
            },
        )
        request = MagicMock()
        request.session = {}
        url = ReferenceOIDCConnector().authorization_url(request, provider, "state-1")
        self.assertIn("redirect_uri=https%3A%2F%2Fauth.example.com%2Fsso%2Furi-test2%2Fcallback%2F", url)
