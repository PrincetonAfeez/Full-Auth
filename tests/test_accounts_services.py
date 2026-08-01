"""Pytest coverage for accounts services."""
import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone

from accounts.models import EmailAddress, User
from accounts.services import (
    EmailVerificationRequired,
    StrongFactorRequired,
    allowed_login_methods,
    authenticate_password_step,
    deactivate_user,
    enabled_factor_types,
    enforce_privileged_factor_policy,
    export_user_data,
    has_strong_factor,
    is_privileged,
    needs_strong_factor_enrollment,
    register_member,
    trusted_device_skips_mfa,
    user_mfa_required,
)
from mfa.models import MFADevice
from organizations.models import Organization, OrganizationMembership
from security_policies.models import SecurityPolicy


@pytest.mark.django_db
class TestRegisterMember:
    def test_creates_pending_user(self):
        user = register_member(username="newbie", email="new@example.test", password="CorrectHorse123!")
        assert user.status == User.Status.PENDING_ACTIVATION
        assert EmailAddress.objects.filter(user=user, is_primary=True).exists()

    def test_with_organization_membership(self):
        org = Organization.objects.create(name="Co", slug="co")
        user = register_member(
            username="orguser", email="org@example.test", password="CorrectHorse123!", organization=org
        )
        assert OrganizationMembership.objects.filter(user=user, organization=org).exists()

    def test_weak_password_rejected(self):
        with pytest.raises(ValidationError):
            register_member(username="weak", email="w@example.test", password="123")


@pytest.mark.django_db
class TestMfaHelpers:
    def test_user_mfa_required_force_flag(self, user_factory):
        user = user_factory("forced", force_strong_mfa=True)
        assert user_mfa_required(user) is True

    def test_user_mfa_required_admin_role(self, user_factory):
        user = user_factory("adminrole")
        org = Organization.objects.create(name="O", slug="o")
        SecurityPolicy.objects.create(organization=org, require_2fa_for_admins=True)
        OrganizationMembership.objects.create(
            organization=org,
            user=user,
            role=OrganizationMembership.Role.ADMIN,
            status=OrganizationMembership.Status.ACTIVE,
            accepted_at=timezone.now(),
        )
        assert user_mfa_required(user) is True

    def test_has_strong_factor(self, user_factory):
        user = user_factory("strong")
        MFADevice.objects.create(user=user, type=MFADevice.Type.TOTP, name="t", enabled_at=timezone.now())
        assert has_strong_factor(user) is True

    def test_is_privileged(self, user_factory):
        user = user_factory("priv")
        org = Organization.objects.create(name="P", slug="p")
        OrganizationMembership.objects.create(
            organization=org,
            user=user,
            role=OrganizationMembership.Role.ADMIN,
            status=OrganizationMembership.Status.ACTIVE,
            accepted_at=timezone.now(),
        )
        assert is_privileged(user) is True

    def test_needs_strong_factor_enrollment(self, user_factory):
        user = user_factory("needenroll", force_strong_mfa=True)
        assert needs_strong_factor_enrollment(user) is True

    def test_enforce_privileged_factor_policy_raises(self, user_factory):
        from organizations.models import Organization, OrganizationMembership
        from security_policies.models import SecurityPolicy

        user = user_factory("noprivfactor")
        org = Organization.objects.create(name="PrivOrg", slug="privorg")
        SecurityPolicy.objects.create(organization=org, require_2fa_for_admins=True)
        OrganizationMembership.objects.create(
            organization=org,
            user=user,
            role=OrganizationMembership.Role.ADMIN,
            status=OrganizationMembership.Status.ACTIVE,
            accepted_at=timezone.now(),
        )
        with pytest.raises(StrongFactorRequired):
            enforce_privileged_factor_policy(user)

    def test_enabled_factor_types(self, user_factory):
        user = user_factory("factors")
        MFADevice.objects.create(user=user, type=MFADevice.Type.EMAIL_OTP, name="e", enabled_at=timezone.now())
        assert "email_otp" in enabled_factor_types(user)


@pytest.mark.django_db
class TestAuthenticatePasswordStep:
    def test_success_no_mfa(self, user_factory):
        from django.contrib.sessions.backends.db import SessionStore
        from django.test import RequestFactory

        user = user_factory("plain")
        rf = RequestFactory()
        request = rf.post("/login/")
        request.session = SessionStore()
        result = authenticate_password_step(request=request, username="plain", password="CorrectHorse123!")
        assert result.pk == user.pk

    def test_pending_email_raises(self, user_factory):
        from django.contrib.sessions.backends.db import SessionStore
        from django.test import RequestFactory

        user_factory("pending", status=User.Status.PENDING_ACTIVATION, email_verified=False)
        rf = RequestFactory()
        request = rf.post("/login/")
        request.session = SessionStore()
        with pytest.raises(EmailVerificationRequired):
            authenticate_password_step(request=request, username="pending", password="CorrectHorse123!")


@pytest.mark.django_db
class TestDeactivateAndExport:
    def test_deactivate_by_superuser(self, user_factory, superuser):
        target = user_factory("target")
        deactivate_user(actor=superuser, user=target, reason="test")
        target.refresh_from_db()
        assert target.status == User.Status.DEACTIVATED

    def test_deactivate_denied_for_non_manager(self, user_factory):
        actor = user_factory("actor")
        target = user_factory("victim")
        with pytest.raises(PermissionDenied):
            deactivate_user(actor=actor, user=target)

    def test_export_user_data(self, user_factory):
        user = user_factory("exportme")
        data = export_user_data(user)
        assert data["user"]["username"] == "exportme"
        assert "sessions" in data


@pytest.mark.django_db
class TestAllowedLoginMethods:
    def test_includes_totp_when_enrolled(self, user_factory):
        user = user_factory("totplogin")
        MFADevice.objects.create(user=user, type=MFADevice.Type.TOTP, name="t", enabled_at=timezone.now())
        methods = allowed_login_methods(user)
        assert "totp" in methods


@pytest.mark.django_db
class TestTrustedDeviceSkip:
    def test_returns_false_without_policy(self, user_factory):
        from django.test import RequestFactory

        user = user_factory("nodevice")
        request = RequestFactory().get("/")
        assert trusted_device_skips_mfa(request, user) is False
