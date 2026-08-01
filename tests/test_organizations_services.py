"""Pytest coverage for organizations services."""
import pytest
from django.core.exceptions import PermissionDenied
from django.utils import timezone

from organizations.models import Invitation, Organization, OrganizationMembership
from organizations.services import (
    accept_invitation,
    can_manage_user,
    change_membership_role,
    close_organization,
    has_role_at_least,
    invite_user,
    organization_active,
    reactivate_organization,
    remove_membership,
    role_rank,
    suspend_organization,
    verify_tenant_scope,
)


@pytest.mark.django_db
class TestRoleRank:
    def test_owner_highest(self):
        assert role_rank(OrganizationMembership.Role.OWNER) > role_rank(OrganizationMembership.Role.ADMIN)

    def test_invalid_role(self):
        assert role_rank("invalid") == 0


@pytest.mark.django_db
class TestOrganizationLifecycle:
    def test_suspend_and_reactivate(self, superuser):
        org = Organization.objects.create(name="Life", slug="life")
        suspend_organization(actor=superuser, organization=org)
        org.refresh_from_db()
        assert org.status == Organization.Status.SUSPENDED
        reactivate_organization(actor=superuser, organization=org)
        org.refresh_from_db()
        assert organization_active(org)

    def test_suspend_denied_for_non_superuser(self, user_factory):
        org = Organization.objects.create(name="NoSuspend", slug="nosuspend")
        user = user_factory("regular")
        with pytest.raises(PermissionDenied):
            suspend_organization(actor=user, organization=org)

    def test_close_organization(self, superuser, user_factory):
        from organizations.models import Invitation

        org = Organization.objects.create(name="Close", slug="close")
        member = user_factory("closemember")
        OrganizationMembership.objects.create(
            organization=org,
            user=member,
            role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE,
            accepted_at=timezone.now(),
        )
        inv = Invitation.objects.create(
            organization=org,
            email="gone@example.test",
            intended_role=OrganizationMembership.Role.MEMBER,
            token_hash="a" * 64,
            expires_at=timezone.now(),
        )
        close_organization(actor=superuser, organization=org)
        org.refresh_from_db()
        assert org.status == Organization.Status.CLOSED
        assert not OrganizationMembership.objects.active().filter(organization=org).exists()
        assert not Invitation.objects.filter(pk=inv.pk).exists()


@pytest.mark.django_db
class TestTenantScope:
    def test_superuser_always_scoped(self, superuser):
        org = Organization.objects.create(name="Scope", slug="scope")
        assert verify_tenant_scope(superuser, org)

    def test_member_scoped(self, user_factory):
        user = user_factory("scoped")
        org = Organization.objects.create(name="MemberScope", slug="memberscope")
        OrganizationMembership.objects.create(
            organization=org,
            user=user,
            role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE,
            accepted_at=timezone.now(),
        )
        assert verify_tenant_scope(user, org)

    def test_non_member_not_scoped(self, user_factory):
        user = user_factory("outsider")
        org = Organization.objects.create(name="Out", slug="out")
        assert not verify_tenant_scope(user, org)


@pytest.mark.django_db
class TestHasRoleAtLeast:
    def test_admin_has_staff(self, user_factory):
        user = user_factory("hasrole")
        org = Organization.objects.create(name="Roles", slug="roles")
        OrganizationMembership.objects.create(
            organization=org,
            user=user,
            role=OrganizationMembership.Role.ADMIN,
            status=OrganizationMembership.Status.ACTIVE,
            accepted_at=timezone.now(),
        )
        assert has_role_at_least(user, org, OrganizationMembership.Role.STAFF)


@pytest.mark.django_db
class TestInvitationFlow:
    def test_invite_and_accept(self, user_factory):
        admin = user_factory("inviter")
        invitee = user_factory("invitee", email="invitee@example.test")
        org = Organization.objects.create(name="Invite", slug="invite")
        OrganizationMembership.objects.create(
            organization=org,
            user=admin,
            role=OrganizationMembership.Role.ADMIN,
            status=OrganizationMembership.Status.ACTIVE,
            accepted_at=timezone.now(),
        )
        _invitation, token = invite_user(
            actor=admin, organization=org, email="invitee@example.test", role=OrganizationMembership.Role.MEMBER
        )
        membership = accept_invitation(user=invitee, token=token)
        assert membership.organization_id == org.pk

    def test_wrong_email_denied(self, user_factory):
        admin = user_factory("inviter2")
        wrong_user = user_factory("wrong", email="wrong@example.test")
        org = Organization.objects.create(name="Invite2", slug="invite2")
        OrganizationMembership.objects.create(
            organization=org,
            user=admin,
            role=OrganizationMembership.Role.ADMIN,
            status=OrganizationMembership.Status.ACTIVE,
            accepted_at=timezone.now(),
        )
        _invitation, token = invite_user(
            actor=admin, organization=org, email="target@example.test", role=OrganizationMembership.Role.MEMBER
        )
        with pytest.raises(PermissionDenied):
            accept_invitation(user=wrong_user, token=token)


@pytest.mark.django_db
class TestCanManageUser:
    def test_superuser_can_manage(self, superuser, user_factory):
        target = user_factory("target")
        assert can_manage_user(superuser, target)

    def test_admin_can_manage_lower_rank(self, user_factory):
        admin = user_factory("orgadmin2")
        member = user_factory("orgmember")
        org = Organization.objects.create(name="Manage", slug="manage")
        now = timezone.now()
        OrganizationMembership.objects.create(
            organization=org, user=admin, role=OrganizationMembership.Role.ADMIN,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=now,
        )
        OrganizationMembership.objects.create(
            organization=org, user=member, role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=now,
        )
        assert can_manage_user(admin, member)


@pytest.mark.django_db
class TestMembershipChanges:
    def test_change_role(self, user_factory):
        admin = user_factory("roleadmin")
        member = user_factory("rolemember")
        org = Organization.objects.create(name="RoleChange", slug="rolechange")
        now = timezone.now()
        OrganizationMembership.objects.create(
            organization=org, user=admin, role=OrganizationMembership.Role.ADMIN,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=now,
        )
        membership = OrganizationMembership.objects.create(
            organization=org, user=member, role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=now,
        )
        updated = change_membership_role(
            actor=admin, membership=membership, role=OrganizationMembership.Role.STAFF
        )
        assert updated.role == OrganizationMembership.Role.STAFF

    def test_remove_membership(self, user_factory):
        admin = user_factory("removeadmin")
        member = user_factory("removemember")
        org = Organization.objects.create(name="Remove", slug="remove")
        now = timezone.now()
        OrganizationMembership.objects.create(
            organization=org, user=admin, role=OrganizationMembership.Role.ADMIN,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=now,
        )
        membership = OrganizationMembership.objects.create(
            organization=org, user=member, role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=now,
        )
        remove_membership(actor=admin, membership=membership)
        membership.refresh_from_db()
        assert membership.status == OrganizationMembership.Status.REMOVED
