"""Pytest coverage for sso jwt verify."""
import time

import pytest

from sso.jwt_verify import verify_id_token
from sso.services import SSOError


def _make_unsigned_token(*, sub="user1", aud="client", iss="https://issuer.test", nonce=None, exp=None):
    import jwt

    payload = {"sub": sub, "aud": aud, "iss": iss, "exp": exp or int(time.time()) + 3600}
    if nonce:
        payload["nonce"] = nonce
    return jwt.encode(payload, "secret", algorithm="HS256")


@pytest.mark.django_db
class TestVerifyIdToken:
    def test_unverified_in_testing_mode(self, settings):
        settings.TESTING = True
        token = _make_unsigned_token(nonce="n1")
        claims = verify_id_token(
            token=token,
            jwks_uri="",
            audience="client",
            issuer="https://issuer.test",
            nonce="n1",
        )
        assert claims["sub"] == "user1"

    def test_nonce_mismatch(self, settings):
        settings.TESTING = True
        token = _make_unsigned_token(nonce="n1")
        with pytest.raises(SSOError, match="nonce"):
            verify_id_token(
                token=token,
                jwks_uri="",
                audience="client",
                issuer="https://issuer.test",
                nonce="wrong",
            )

    def test_missing_issuer(self, settings):
        settings.TESTING = True
        token = _make_unsigned_token()
        with pytest.raises(SSOError, match="issuer"):
            verify_id_token(token=token, jwks_uri="", audience="client", issuer="")

    def test_requires_jwks_when_not_testing(self, settings):
        settings.TESTING = False
        token = _make_unsigned_token()
        with pytest.raises(SSOError, match="jwks_uri"):
            verify_id_token(
                token=token,
                jwks_uri="",
                audience="client",
                issuer="https://issuer.test",
            )

    def test_expired_token(self, settings):
        settings.TESTING = True
        token = _make_unsigned_token(exp=int(time.time()) - 10)
        with pytest.raises(SSOError, match="expired"):
            verify_id_token(
                token=token,
                jwks_uri="",
                audience="client",
                issuer="https://issuer.test",
            )
