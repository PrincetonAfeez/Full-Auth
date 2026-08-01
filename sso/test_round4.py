"""Regression tests for sso (security audit round)."""
import json
from unittest.mock import MagicMock, patch

from django.test import TestCase

from sso.connectors import ExternalIdentity
from sso.oidc_connector import ReferenceOIDCConnector
from sso.services import SSOError


class OIDCIdTokenRequiredTests(TestCase):
    def test_userinfo_only_token_response_rejected(self):
        provider = MagicMock()
        provider.slug = "ref-oidc"
        provider.config = {
            "client_id": "cid",
            "client_secret": "sec",
            "authorization_endpoint": "https://idp.example/authorize",
            "token_endpoint": "https://idp.example/token",
            "userinfo_endpoint": "https://idp.example/userinfo",
            "issuer": "https://idp.example",
            "jwks_uri": "https://idp.example/jwks",
        }
        token_payload = json.dumps({"access_token": "at"}).encode()
        userinfo_payload = json.dumps({"sub": "ext-1", "email": "oidc@test", "email_verified": True}).encode()

        def fake_urlopen(req, timeout=10):
            url = getattr(req, "full_url", "")
            if "token" in url:
                return MagicMock(read=lambda: token_payload, __enter__=lambda s: s, __exit__=lambda *a: None)
            return MagicMock(read=lambda: userinfo_payload, __enter__=lambda s: s, __exit__=lambda *a: None)

        request = MagicMock()
        request.GET = {"code": "auth-code"}
        request.session = {f"oidc_pkce_{provider.slug}": "test-verifier", f"oidc_nonce_{provider.slug}": "nonce-1"}
        request.build_absolute_uri.return_value = "https://app.example/sso/callback/ref-oidc/"
        connector = ReferenceOIDCConnector()
        with patch("sso.oidc_connector.urlopen", side_effect=fake_urlopen):
            with self.assertRaises(SSOError):
                connector.complete(request, provider)

    def test_validate_config_requires_issuer_and_jwks(self):
        connector = ReferenceOIDCConnector()
        with self.assertRaises(ValueError):
            connector.validate_config({"client_id": "x", "client_secret": "y"})
