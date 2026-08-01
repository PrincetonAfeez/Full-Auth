"""Minimal OIDC id_token validation against JWKS."""
import time

from django.conf import settings

from .services import SSOError


def verify_id_token(*, token: str, jwks_uri: str, audience: str, issuer: str, nonce: str | None = None) -> dict:
    try:
        import jwt
        from jwt import PyJWKClient
    except ImportError as exc:
        raise SSOError("PyJWT is required for id_token validation.") from exc

    if not issuer:
        raise SSOError("OIDC provider config must include a non-empty issuer.")

    algorithms = list(getattr(settings, "OIDC_JWT_ALGORITHMS", ["RS256", "ES256", "PS256"]))

    if settings.TESTING and not jwks_uri:
        # Hermetic unit tests may use unsigned tokens when explicitly configured off-JWKS.
        return _decode_unverified_payload(token, audience, issuer, nonce)

    if not jwks_uri:
        raise SSOError("id_token validation requires jwks_uri in provider config.")
    client = PyJWKClient(jwks_uri)
    signing_key = client.get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=algorithms,
        audience=audience,
        issuer=issuer,
        options={"require": ["exp", "sub"]},
    )
    if nonce is not None and claims.get("nonce") != nonce:
        raise SSOError("OIDC nonce mismatch.")
    return claims


def _decode_unverified_payload(token: str, audience: str, issuer: str, nonce: str | None) -> dict:
    try:
        import jwt
    except ImportError as exc:
        raise SSOError("PyJWT is required for id_token validation.") from exc

    claims = jwt.decode(token, options={"verify_signature": False})
    now = int(time.time())
    if claims.get("exp") and int(claims["exp"]) < now:
        raise SSOError("id_token expired.")
    if audience and claims.get("aud") not in (audience, [audience]):
        aud = claims.get("aud")
        if aud != audience and (not isinstance(aud, list) or audience not in aud):
            raise SSOError("id_token audience mismatch.")
    if issuer and claims.get("iss") != issuer:
        raise SSOError("id_token issuer mismatch.")
    if nonce is not None and claims.get("nonce") != nonce:
        raise SSOError("OIDC nonce mismatch.")
    return claims
