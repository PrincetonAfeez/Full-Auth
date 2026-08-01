"""Django unit tests for the sso app."""
import json

from django.test import TestCase
from django.urls import reverse

from accounts.models import User
from sessions.models import ActiveSession

from .connectors import _REGISTRY, ExternalIdentity, SSOConnector, register_connector
from .models import FederatedIdentity, IdentityProvider


class _StubConnector(SSOConnector):
    """A minimal connector standing in for a real OIDC/SAML implementation, for tests."""

    def validate_config(self, config):
        return None

    def authorization_url(self, request, provider, state):
        return reverse("sso:callback", args=[provider.slug]) + f"?state={state}"

    def complete(self, request, provider):
        return ExternalIdentity(subject="ext-123", email="ssouser@example.test", email_verified=True)


class SSOExtensionTests(TestCase):
    def setUp(self):
        register_connector("oidc", _StubConnector())
        self.provider = IdentityProvider.objects.create(
            slug="acme-oidc", name="Acme OIDC", protocol=IdentityProvider.Protocol.OIDC, enabled=True
        )

    def tearDown(self):
        _REGISTRY.pop("oidc", None)

    def _begin(self):
        return self.client.get(reverse("sso:begin", args=["acme-oidc"]))

    def _callback(self, state=None):
        state = state or self.client.session.get("sso_state", "")
        return self.client.get(reverse("sso:callback", args=["acme-oidc"]) + f"?state={state}")

    def test_begin_redirects_when_configured(self):
        r = self._begin()
        self.assertEqual(r.status_code, 302)
        self.assertIn("state=", r["Location"])

    def test_unconfigured_provider_is_safe_default(self):
        _REGISTRY.pop("oidc", None)
        r = self.client.get(reverse("sso:begin", args=["acme-oidc"]))
        self.assertRedirects(r, reverse("web:login"), fetch_redirect_response=False)

    def test_callback_rejects_missing_state(self):
        r = self._callback(state="wrong-state")
        self.assertRedirects(r, reverse("web:login"), fetch_redirect_response=False)
        self.assertFalse(User.objects.filter(email="ssouser@example.test").exists())

    def test_callback_provisions_user_and_logs_in(self):
        self._begin()
        r = self._callback()
        self.assertRedirects(r, reverse("web:dashboard"), fetch_redirect_response=False)
        user = User.objects.get(email="ssouser@example.test")
        self.assertTrue(FederatedIdentity.objects.filter(user=user, provider=self.provider, subject="ext-123").exists())
        self.assertFalse(user.has_usable_password())
        self.assertTrue(ActiveSession.objects.filter(user=user).exists())

    def test_second_callback_reuses_same_user(self):
        self._begin()
        self._callback()
        self.client.post(reverse("web:logout"))
        self._begin()
        self._callback()
        self.assertEqual(User.objects.filter(email="ssouser@example.test").count(), 1)

    def test_refuses_takeover_of_existing_unlinked_email(self):
        from accounts.models import EmailAddress

        existing = User.objects.create_user(
            username="local", email="ssouser@example.test", password="CorrectHorse123!", status=User.Status.ACTIVE
        )
        EmailAddress.objects.create(user=existing, email=existing.email, is_primary=True)
        self._begin()
        r = self._callback()
        self.assertRedirects(r, reverse("web:login"), fetch_redirect_response=False)
        self.assertFalse(FederatedIdentity.objects.filter(user=existing).exists())


class ReferenceOIDCConnectorTests(TestCase):
    def test_reads_provider_config_not_metadata(self):
        from unittest.mock import MagicMock, patch

        from .oidc_connector import ReferenceOIDCConnector

        provider = IdentityProvider.objects.create(
            slug="ref-oidc",
            name="Ref OIDC",
            protocol=IdentityProvider.Protocol.OIDC,
            enabled=True,
            config={
                "client_id": "cid",
                "client_secret": "sec",
                "authorization_endpoint": "https://idp.example/authorize",
                "token_endpoint": "https://idp.example/token",
                "userinfo_endpoint": "https://idp.example/userinfo",
                "issuer": "https://idp.example",
                "jwks_uri": "https://idp.example/jwks",
            },
        )
        request = MagicMock()
        request.build_absolute_uri.return_value = "https://app.example/sso/callback/ref-oidc/"
        request.session = {}
        connector = ReferenceOIDCConnector()
        url = connector.authorization_url(request, provider, "state-123")
        self.assertIn("client_id=cid", url)
        self.assertIn("code_challenge=", url)
        self.assertIn("nonce=", url)
        self.assertIn(f"oidc_pkce_{provider.slug}", request.session)
        self.assertIn(f"oidc_nonce_{provider.slug}", request.session)

        token_payload = json.dumps({"access_token": "at", "id_token": "test.id.token"}).encode()
        userinfo_payload = json.dumps({"sub": "ext-1", "email": "oidc@test", "email_verified": True}).encode()
        id_claims = {"sub": "ext-1", "email": "oidc@test", "email_verified": True, "nonce": "nonce-1"}

        def fake_urlopen(req, timeout=10):
            url = getattr(req, "full_url", "")
            if "token" in url:
                return MagicMock(read=lambda: token_payload, __enter__=lambda s: s, __exit__=lambda *a: None)
            return MagicMock(read=lambda: userinfo_payload, __enter__=lambda s: s, __exit__=lambda *a: None)

        request.GET = {"code": "auth-code"}
        request.session[f"oidc_pkce_{provider.slug}"] = "test-verifier"
        request.session[f"oidc_nonce_{provider.slug}"] = "nonce-1"
        with patch("sso.oidc_connector.urlopen", side_effect=fake_urlopen), patch(
            "sso.oidc_connector.verify_id_token", return_value=id_claims
        ):
            identity = connector.complete(request, provider)
        self.assertEqual(identity.subject, "ext-1")
        self.assertEqual(identity.email, "oidc@test")
        self.assertTrue(identity.email_verified)
