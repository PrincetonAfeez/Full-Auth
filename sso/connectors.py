"""
Pluggable SSO connector interface + registry. The reference OIDC connector is registered
at startup (sso.apps.SsoConfig.ready); operators may replace it with a custom implementation.
"""
from dataclasses import dataclass, field


@dataclass
class ExternalIdentity:
    """Normalized identity returned by a connector after a successful external authentication."""

    subject: str
    email: str = ""
    email_verified: bool = False
    display_name: str = ""
    raw: dict = field(default_factory=dict)


class SSOConnector:
    """Implement this for a concrete protocol (OIDC/SAML). Both methods receive the request."""

    def validate_config(self, config: dict) -> None:
        """Raise ValueError when required provider config keys are missing or invalid."""
        raise NotImplementedError

    def authorization_url(self, request, provider, state: str) -> str:
        """Return the URL to redirect the browser to, to begin authentication at the IdP."""
        raise NotImplementedError

    def complete(self, request, provider) -> ExternalIdentity:
        """Validate the IdP callback and return the authenticated ExternalIdentity."""
        raise NotImplementedError


_REGISTRY: dict[str, SSOConnector] = {}


def register_connector(protocol: str, connector: SSOConnector) -> None:
    _REGISTRY[protocol] = connector


def get_connector(provider) -> SSOConnector | None:
    return _REGISTRY.get(provider.protocol)


def is_configured(provider) -> bool:
    connector = get_connector(provider)
    if not provider.enabled or connector is None:
        return False
    try:
        connector.validate_config(provider.config or {})
    except (ValueError, TypeError):
        return False
    return True
