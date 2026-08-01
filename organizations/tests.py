"""Django unit tests for the organizations app."""
from django.core.exceptions import PermissionDenied
from django.test import TestCase
from django.utils import timezone

from accounts.models import User

from .models import Invitation, Organization, OrganizationMembership
from .services import accept_invitation, assign_role, change_membership_role, invite_user


def _mk(username, email=None, **kw):
    return User.objects.create_user(
        username=username, email=email or f"{username}@example.test", password="CorrectHorse123!",
        status=User.Status.ACTIVE, email_verified_at=timezone.now(), **kw
    )


class InvitationSecurityTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.owner = _mk("owner")
        OrganizationMembership.objects.create(
            organization=self.org, user=self.owner, role=OrganizationMembership.Role.OWNER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )

    def test_invitation_bound_to_email(self):
        """Regression: an invite can't be accepted by a different email (finding #14)."""
        _invite, token = invite_user(actor=self.owner, organization=self.org, email="invitee@example.test", role="member")
        wrong = _mk("wrong")  # wrong@example.test != invitee@example.test
        with self.assertRaises(PermissionDenied):
            accept_invitation(user=wrong, token=token)

    def test_accept_does_not_downgrade_existing_role(self):
        admin = _mk("adminuser", email="invitee@example.test")
        OrganizationMembership.objects.create(
            organization=self.org, user=admin, role=OrganizationMembership.Role.ADMIN,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        _invite, token = invite_user(actor=self.owner, organization=self.org, email="invitee@example.test", role="member")
        membership = accept_invitation(user=admin, token=token)
        self.assertEqual(membership.role, OrganizationMembership.Role.ADMIN)

    def test_non_admin_cannot_invite(self):
        member = _mk("member")
        OrganizationMembership.objects.create(
            organization=self.org, user=member, role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        with self.assertRaises(PermissionDenied):
            invite_user(actor=member, organization=self.org, email="x@example.test", role="member")

    def test_cannot_demote_last_owner(self):
        with self.assertRaises(PermissionDenied):
            membership = OrganizationMembership.objects.get(user=self.owner, organization=self.org)
            change_membership_role(actor=self.owner, membership=membership, role="member")

    def test_invalid_invitation_token_is_value_error(self):
        user = _mk("invitee", email="invitee@example.test")
        with self.assertRaises(ValueError):
            accept_invitation(user=user, token="not-a-real-token")

    def test_invalid_role_rejected(self):
        with self.assertRaises(ValueError):
            invite_user(actor=self.owner, organization=self.org, email="x@example.test", role="superadmin")


class HierarchyEnforcementTests(TestCase):
    """Security-review regressions: destructive cross-user actions must respect role rank."""

    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.owner = _mk("owner")
        self.admin = _mk("admin")
        # A second owner so the 'last owner' guard isn't what's blocking.
        self.owner2 = _mk("owner2")
        for u, role in [
            (self.owner, OrganizationMembership.Role.OWNER),
            (self.owner2, OrganizationMembership.Role.OWNER),
            (self.admin, OrganizationMembership.Role.ADMIN),
        ]:
            OrganizationMembership.objects.create(
                organization=self.org, user=u, role=role,
                status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
            )

    def test_admin_cannot_remove_owner(self):
        from organizations.services import remove_membership
        owner_m = OrganizationMembership.objects.get(user=self.owner, organization=self.org)
        with self.assertRaises(PermissionDenied):
            remove_membership(actor=self.admin, membership=owner_m)
        owner_m.refresh_from_db()
        self.assertEqual(owner_m.status, OrganizationMembership.Status.ACTIVE)

    def test_owner_can_remove_admin(self):
        from organizations.services import remove_membership
        admin_m = OrganizationMembership.objects.get(user=self.admin, organization=self.org)
        remove_membership(actor=self.owner, membership=admin_m)
        admin_m.refresh_from_db()
        self.assertEqual(admin_m.status, OrganizationMembership.Status.REMOVED)

    def test_admin_cannot_manage_owner(self):
        from organizations.services import can_manage_user
        # admin (rank 30) must not be able to deactivate/revoke an owner (rank 40)
        self.assertFalse(can_manage_user(self.admin, self.owner))
        # but an owner can manage an admin
        self.assertTrue(can_manage_user(self.owner, self.admin))


class AssignRoleAllowlistTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.admin = _mk("admin")
        self.target = _mk("target")
        OrganizationMembership.objects.create(
            organization=self.org, user=self.admin, role=OrganizationMembership.Role.ADMIN,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )

    def test_org_admin_cannot_assign_non_allowlisted_group(self):
        with self.assertRaises(PermissionDenied):
            assign_role(actor=self.admin, user=self.target, organization=self.org, group_name="supersecret")

    def test_org_admin_can_assign_allowlisted_group(self):
        OrganizationMembership.objects.create(
            organization=self.org, user=self.target, role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        assignment = assign_role(actor=self.admin, user=self.target, organization=self.org, group_name="staff")
        self.assertEqual(assignment.group.name, "staff")


class TenantIsolationTests(TestCase):
    def test_tenant_queryset_visible_to_filters_by_active_membership(self):
        user = User.objects.create_user(username="u", email="u@example.test", password="CorrectHorse123!", status=User.Status.ACTIVE)
        org_a = Organization.objects.create(name="A", slug="a")
        org_b = Organization.objects.create(name="B", slug="b")
        OrganizationMembership.objects.create(
            organization=org_a,
            user=user,
            role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE,
            accepted_at=timezone.now(),
        )
        Invitation.objects.create(
            organization=org_a,
            email="a@example.test",
            intended_role=OrganizationMembership.Role.MEMBER,
            token_hash="a",
            expires_at=timezone.now() + timezone.timedelta(days=1),
        )
        Invitation.objects.create(
            organization=org_b,
            email="b@example.test",
            intended_role=OrganizationMembership.Role.MEMBER,
            token_hash="b",
            expires_at=timezone.now() + timezone.timedelta(days=1),
        )

        visible = Invitation.objects.visible_to(user)

        self.assertEqual(list(visible.values_list("organization__slug", flat=True)), ["a"])

# Create your tests here.
