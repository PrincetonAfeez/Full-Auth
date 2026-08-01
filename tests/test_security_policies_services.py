"""Pytest coverage for security policies services."""
import pytest
from django.core.exceptions import PermissionDenied
from django.utils import timezone

from organizations.models import Organization, OrganizationMembership
from security_policies.models import SecurityPolicy
from security_policies.services import (
    get_effective_policy,
    get_policy,
    role_requires_mfa,
    update_org_policy,
    validate_factor_policy_for_role,
)


@pytest.mark.django_db
class TestGetPolicy:
    def test_global_default(self):
        policy = get_policy()
        assert policy.organization_id is None
        assert policy.idle_timeout_minutes > 0

    def test_org_policy(self):
        org = Organization.objects.create(name="PolicyOrg", slug="policyorg")
        SecurityPolicy.objects.create(organization=org, idle_timeout_minutes=15)
        policy = get_policy(org)
        assert policy.idle_timeout_minutes == 15


@pytest.mark.django_db
class TestEffectivePolicy:
    def test_global_only(self, verified_user):
        ep = get_effective_policy(verified_user)
        assert ep.idle_timeout_minutes > 0
        assert isinstance(ep.allowed_2fa_methods, tuple)

    def test_strictest_org_wins(self, user_factory):
        user = user_factory("multipolicy")
        org1 = Organization.objects.create(name="Strict", slug="strict")
        org2 = Organization.objects.create(name="Loose", slug="loose")
        SecurityPolicy.objects.create(organization=org1, idle_timeout_minutes=10)
        SecurityPolicy.objects.create(organization=org2, idle_timeout_minutes=60)
        now = timezone.now()
        for org in (org1, org2):
            OrganizationMembership.objects.create(
                organization=org,
                user=user,
                role=OrganizationMembership.Role.MEMBER,
                status=OrganizationMembership.Status.ACTIVE,
                accepted_at=now,
            )
        ep = get_effective_policy(user)
        assert ep.idle_timeout_minutes == 10

    def test_cached_on_user(self, verified_user):
        ep1 = get_effective_policy(verified_user)
        ep2 = get_effective_policy(verified_user)
        assert ep1 is ep2


@pytest.mark.django_db
class TestRoleRequiresMfa:
    def test_admin_requires_mfa(self, global_policy):
        global_policy.require_2fa_for_admins = True
        global_policy.save()
        assert role_requires_mfa(OrganizationMembership.Role.ADMIN, global_policy)

    def test_member_does_not(self, global_policy):
        assert not role_requires_mfa(OrganizationMembership.Role.MEMBER, global_policy)


@pytest.mark.django_db
class TestValidateFactorPolicy:
    def test_privileged_without_strong_factor(self, global_policy):
        global_policy.require_2fa_for_admins = True
        global_policy.save()
        with pytest.raises(ValueError, match="TOTP or WebAuthn"):
            validate_factor_policy_for_role(
                role=OrganizationMembership.Role.ADMIN,
                enabled_factor_types={"email_otp"},
                policy=global_policy,
            )


@pytest.mark.django_db
class TestUpdateOrgPolicy:
    def test_admin_can_update(self, user_factory):
        admin = user_factory("orgadmin")
        org = Organization.objects.create(name="Updatable", slug="updatable")
        OrganizationMembership.objects.create(
            organization=org,
            user=admin,
            role=OrganizationMembership.Role.ADMIN,
            status=OrganizationMembership.Status.ACTIVE,
            accepted_at=timezone.now(),
        )
        policy = update_org_policy(
            actor=admin,
            organization=org,
            changes={"idle_timeout_minutes": 20},
        )
        assert policy.idle_timeout_minutes == 20

    def test_non_admin_denied(self, user_factory):
        member = user_factory("member")
        org = Organization.objects.create(name="Locked", slug="locked")
        OrganizationMembership.objects.create(
            organization=org,
            user=member,
            role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE,
            accepted_at=timezone.now(),
        )
        with pytest.raises(PermissionDenied):
            update_org_policy(actor=member, organization=org, changes={"idle_timeout_minutes": 20})
