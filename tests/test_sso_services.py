"""Pytest coverage for sso services."""
import pytest
from django.utils import timezone

from organizations.models import Organization, OrganizationMembership
from sso.connectors import ExternalIdentity
from sso.models import FederatedIdentity, IdentityProvider
from sso.services import SSOError, ensure_org_sso_access, resolve_user


def _provider(**kwargs):
    defaults = {
        "slug": "test-idp",
        "name": "Test IdP",
        "protocol": IdentityProvider.Protocol.OIDC,
        "enabled": True,
    }
    defaults.update(kwargs)
    return IdentityProvider.objects.create(**defaults)


@pytest.mark.django_db
class TestResolveUser:
    def test_existing_federated_identity(self, verified_user):
        provider = _provider(slug="okta")
        FederatedIdentity.objects.create(
            user=verified_user, provider=provider, subject="sub123", email=verified_user.email
        )
        external = ExternalIdentity(subject="sub123", email=verified_user.email, email_verified=True)
        user = resolve_user(provider=provider, external=external)
        assert user.pk == verified_user.pk

    def test_auto_link_verified_email(self, verified_user):
        provider = _provider(slug="google", auto_link_verified_email=True)
        external = ExternalIdentity(
            subject="newsub", email=verified_user.email, email_verified=True
        )
        user = resolve_user(provider=provider, external=external)
        assert user.pk == verified_user.pk
        assert FederatedIdentity.objects.filter(user=verified_user, provider=provider).exists()

    def test_refuses_when_no_provision(self):
        provider = _provider(slug="locked", auto_provision=False)
        external = ExternalIdentity(subject="unknown", email="nobody@example.test", email_verified=True)
        with pytest.raises(SSOError, match="provisioning is disabled"):
            resolve_user(provider=provider, external=external)

    def test_auto_provision_creates_user(self):
        provider = _provider(slug="azure", auto_provision=True)
        external = ExternalIdentity(subject="azure-sub", email="newsso@example.test", email_verified=True)
        user = resolve_user(provider=provider, external=external)
        assert user.email == "newsso@example.test"
        assert not user.has_usable_password()


@pytest.mark.django_db
class TestEnsureOrgSsoAccess:
    def test_global_provider_noop(self, verified_user):
        provider = _provider(slug="global")
        ensure_org_sso_access(provider=provider, user=verified_user)

    def test_auto_provision_adds_membership(self, verified_user):
        org = Organization.objects.create(name="SSO Org", slug="ssoorg")
        provider = _provider(slug="orgidp", organization=org, auto_provision=True)
        ensure_org_sso_access(provider=provider, user=verified_user)
        assert OrganizationMembership.objects.active().filter(organization=org, user=verified_user).exists()

    def test_denies_non_member_without_provision(self, verified_user):
        org = Organization.objects.create(name="Strict SSO", slug="strictsso")
        provider = _provider(slug="strictidp", organization=org, auto_provision=False)
        with pytest.raises(SSOError, match="not a member"):
            ensure_org_sso_access(provider=provider, user=verified_user)

    def test_existing_member_passes(self, verified_user):
        org = Organization.objects.create(name="Member Org", slug="memberorg")
        OrganizationMembership.objects.create(
            organization=org,
            user=verified_user,
            role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE,
            accepted_at=timezone.now(),
        )
        provider = _provider(slug="memberidp", organization=org, auto_provision=False)
        ensure_org_sso_access(provider=provider, user=verified_user)
