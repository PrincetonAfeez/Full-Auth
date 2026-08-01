"""
Reference OIDC connector (authorization-code flow with PKCE and id_token validation).

Register at startup (sso.apps.SsoConfig.ready):

    register_connector("oidc", ReferenceOIDCConnector())

Expected IdentityProvider.config keys:
  client_id, client_secret, authorization_endpoint, token_endpoint,
  userinfo_endpoint (optional), scope (optional), issuer, jwks_uri
"""
import base64
import hashlib
import json
import secrets
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from django.conf import settings
from django.urls import reverse

from .connectors import ExternalIdentity, SSOConnector
from .jwt_verify import verify_id_token
from .services import SSOError

_REQUIRED_OIDC_KEYS = (
    "client_id",
    "client_secret",
    "authorization_endpoint",
    "token_endpoint",
    "issuer",
    "jwks_uri",
)


def _provider_config(provider) -> dict:
    return provider.config or {}


def oidc_redirect_uri(provider) -> str:
    """Canonical redirect URI from PUBLIC_BASE_URL (stable behind reverse proxies)."""
    path = reverse("sso:callback", args=[provider.slug])
    return f"{settings.PUBLIC_BASE_URL.rstrip('/')}{path}"


def _merge_userinfo(*, claims: dict, profile: dict) -> tuple[str, str, bool]:
    """Userinfo may supplement missing fields only; id_token claims stay authoritative."""
    subject = claims.get("sub", "")
    email = claims.get("email") or profile.get("email") or ""
    email_verified = bool(claims.get("email_verified"))
    if not email and profile.get("email"):
        email = profile.get("email", "")
    if "email_verified" not in claims and profile.get("email_verified") is not None:
        email_verified = bool(profile.get("email_verified"))
    return subject, email, email_verified


class ReferenceOIDCConnector(SSOConnector):
    def validate_config(self, config: dict) -> None:
        missing = [key for key in _REQUIRED_OIDC_KEYS if not config.get(key)]
        if missing:
            raise ValueError(f"OIDC provider missing config keys: {', '.join(missing)}")

    def authorization_url(self, request, provider, state: str) -> str:
        meta = _provider_config(provider)
        self.validate_config(meta)
        code_verifier = secrets.token_urlsafe(48)
        nonce = secrets.token_urlsafe(24)
        request.session[f"oidc_pkce_{provider.slug}"] = code_verifier
        request.session[f"oidc_nonce_{provider.slug}"] = nonce
        challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip("=")
        params = urlencode(
            {
                "client_id": meta["client_id"],
                "response_type": "code",
                "scope": meta.get("scope", "openid email profile"),
                "redirect_uri": oidc_redirect_uri(provider),
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{meta['authorization_endpoint']}?{params}"

    def complete(self, request, provider) -> ExternalIdentity:
        meta = _provider_config(provider)
        self.validate_config(meta)
        code = request.GET.get("code")
        if not code:
            raise SSOError("Missing authorization code.")
        verifier = request.session.pop(f"oidc_pkce_{provider.slug}", None)
        if not verifier:
            raise SSOError("Missing PKCE verifier.")
        nonce = request.session.pop(f"oidc_nonce_{provider.slug}", None)
        redirect_uri = oidc_redirect_uri(provider)
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": meta["client_id"],
            "client_secret": meta["client_secret"],
            "code_verifier": verifier,
        }
        token_body = urlencode(token_data).encode()
        token_req = Request(meta["token_endpoint"], data=token_body, method="POST")
        token_req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urlopen(token_req, timeout=10) as resp:  # nosec B310 - operator-configured endpoint
            token_payload = json.loads(resp.read().decode())
        id_token = token_payload.get("id_token", "")
        if not id_token:
            raise SSOError("OIDC token response did not include an id_token.")
        claims = verify_id_token(
            token=id_token,
            jwks_uri=meta["jwks_uri"],
            audience=meta["client_id"],
            issuer=meta["issuer"],
            nonce=nonce,
        )
        subject = claims.get("sub", "")
        email = claims.get("email", "")
        email_verified = bool(claims.get("email_verified"))
        if meta.get("userinfo_endpoint") and token_payload.get("access_token"):
            ui_req = Request(
                meta["userinfo_endpoint"],
                headers={"Authorization": f"Bearer {token_payload['access_token']}"},
            )
            with urlopen(ui_req, timeout=10) as resp:  # nosec B310
                profile = json.loads(resp.read().decode())
            subject, email, email_verified = _merge_userinfo(claims=claims, profile=profile)
        if not subject:
            raise SSOError("OIDC response did not include a subject.")
        return ExternalIdentity(
            subject=subject, email=email, email_verified=email_verified, raw={"id_token_present": True}
        )
