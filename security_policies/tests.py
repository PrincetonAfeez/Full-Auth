"""Django unit tests for the security_policies app."""
from django.test import TestCase
from django.utils import timezone

from accounts.models import User
from organizations.models import Organization, OrganizationMembership
from security_policies.models import SecurityPolicy
from security_policies.services import get_effective_policy, role_requires_mfa, update_org_policy


class EffectivePolicyTests(TestCase):
    def setUp(self):
        SecurityPolicy.objects.get_or_create(organization=None, defaults={"lockout_threshold": 10})
        self.user = User.objects.create_user(
            username="policyuser", email="policy@example.test", password="x", status=User.Status.ACTIVE
        )
        self.org = Organization.objects.create(name="Strict", slug="strict")
        OrganizationMembership.objects.create(
            organization=self.org, user=self.user, role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        SecurityPolicy.objects.create(
            organization=self.org, lockout_threshold=3, email_otp_max_verify_attempts=2,
            lockout_duration_minutes=30,
        )

    def test_effective_policy_uses_strictest_org_values(self):
        policy = get_effective_policy(self.user)
        self.assertEqual(policy.lockout_threshold, 3)
        self.assertEqual(policy.email_otp_max_verify_attempts, 2)
        self.assertEqual(policy.lockout_duration_minutes, 30)

    def test_update_org_policy_bumps_version(self):
        admin = User.objects.create_user(
            username="admin", email="admin@example.test", password="x", status=User.Status.ACTIVE
        )
        OrganizationMembership.objects.create(
            organization=self.org, user=admin, role=OrganizationMembership.Role.ADMIN,
            status=OrganizationMembership.Status.ACTIVE, accepted_at=timezone.now(),
        )
        before = get_effective_policy(self.user).policy_version
        update_org_policy(actor=admin, organization=self.org, changes={"lockout_threshold": 5})
        self.user = User.objects.get(pk=self.user.pk)
        after = get_effective_policy(self.user).policy_version
        self.assertGreater(after, before)

    def test_role_requires_mfa_for_admin_when_enabled(self):
        policy = SecurityPolicy.objects.get(organization=self.org)
        policy.require_2fa_for_admins = True
        policy.save(update_fields=["require_2fa_for_admins"])
        self.assertTrue(role_requires_mfa(OrganizationMembership.Role.ADMIN, policy))
