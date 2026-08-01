"""Database models for the sso app."""
from django.conf import settings
from django.db import models


class IdentityProvider(models.Model):
    """
    A configured external identity provider (extension point for SSO). OIDC/SAML are explicit
    product non-goals (§3), so this platform ships the *architecture* (models, connector
    interface, begin/callback views) with no protocol connector registered by default -- an
    operator plugs one in later without touching core auth.
    """

    class Protocol(models.TextChoices):
        OIDC = "oidc", "OpenID Connect"
        SAML = "saml", "SAML 2.0"

    slug = models.SlugField(unique=True)
    name = models.CharField(max_length=120)
    protocol = models.CharField(max_length=16, choices=Protocol)
    # Nullable = platform-wide provider; otherwise scoped to a single organization.
    organization = models.ForeignKey(
        "organizations.Organization", null=True, blank=True, on_delete=models.CASCADE, related_name="identity_providers"
    )
    config = models.JSONField(default=dict, blank=True)
    # Only auto-link to an existing local account when the IdP asserts a verified email match.
    auto_link_verified_email = models.BooleanField(default=False)
    auto_provision = models.BooleanField(default=True)
    enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"{self.name} ({self.protocol})"


class FederatedIdentity(models.Model):
    """Link between a local user and an external subject at a provider."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="federated_identities")
    provider = models.ForeignKey(IdentityProvider, on_delete=models.CASCADE, related_name="identities")
    subject = models.CharField(max_length=255)
    email = models.EmailField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_login_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["provider", "subject"], name="one_identity_per_provider_subject")
        ]
