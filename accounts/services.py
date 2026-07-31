"""Business logic and service layer for accounts."""
from django.contrib.auth import authenticate, login
from django.contrib.auth.password_validation import validate_password
from django.db import transaction
from django.utils import timezone

from mfa.models import MFADevice
from notifications.services import emit_outbox_event
from organizations.models import Organization, OrganizationMembership
from passwords.services import request_email_verification, screen_breached_password
from security_events.services import detect_risk_event, record_audit_event
from security_policies.services import (
    PRIVILEGED_ROLES,
    STRONG_FACTORS,
    get_effective_policy,
    get_policy,
    role_requires_mfa,
    validate_factor_policy_for_role,
)
from sessions.services import create_active_session, note_login_device, revoke_all_user_sessions

from .models import EmailAddress, User
from .recent_auth import mark_recent_auth
from .throttle import check_allowed, client_ip, record_failure, record_success


class StrongFactorRequired(Exception):
    """A privileged user finished auth but has no phishing-resistant/device-bound factor."""


class AccountInactive(Exception):
    """The account became deactivated/locked between the password step and 2FA completion."""


class EmailVerificationRequired(Exception):
    """Correct password, but the account is still pending email verification."""


@transaction.atomic
def register_member(*, username: str, email: str, password: str, organization: Organization | None = None) -> User:
    validate_password(password)
    screen_breached_password(password)
    user = User.objects.create_user(
        username=username,
        email=email.lower(),
        password=password,
        status=User.Status.PENDING_ACTIVATION,
    )
    EmailAddress.objects.create(user=user, email=user.email, is_primary=True)
    if organization:
        OrganizationMembership.objects.create(
            organization=organization,
            user=user,
            role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE,
            accepted_at=timezone.now(),
        )
    request_email_verification(user=user)
    record_audit_event(actor=user, target_user=user, organization=organization, event_type="account.registered")
    return user


def _active_org_memberships(user: User):
    # Only memberships in ACTIVE organizations impose or grant anything -- a suspended/closed
    # org must not force MFA/strong-factor requirements (matches has_role_at_least).
    return (
        OrganizationMembership.objects.active()
        .filter(user=user, organization__status=Organization.Status.ACTIVE)
        .select_related("organization")
    )


def user_mfa_required(user: User) -> bool:
    memberships = list(_active_org_memberships(user))
    if not memberships:
        return user.force_strong_mfa
    for membership in memberships:
        if role_requires_mfa(membership.role, get_policy(membership.organization)):
            return True
    return user.force_strong_mfa


def enabled_factor_types(user: User) -> set[str]:
    return set(MFADevice.objects.filter(user=user, enabled_at__isnull=False, disabled_at__isnull=True).values_list("type", flat=True))


def has_strong_factor(user: User) -> bool:
    return bool(enabled_factor_types(user) & STRONG_FACTORS)


def is_privileged(user: User) -> bool:
    return OrganizationMembership.objects.active().filter(user=user, role__in=PRIVILEGED_ROLES).exists()


def needs_strong_factor_enrollment(user: User) -> bool:
    """A privileged/2FA-required user who must enroll a strong factor before completing login."""
    if has_strong_factor(user):
        return False
    if user.force_strong_mfa:
        return True
    for membership in _active_org_memberships(user):
        policy = get_policy(membership.organization)
        if role_requires_mfa(membership.role, policy) and membership.role in PRIVILEGED_ROLES:
            return True
    return False


def enforce_privileged_factor_policy(user: User) -> None:
    factor_types = enabled_factor_types(user)
    for membership in _active_org_memberships(user):
        try:
            validate_factor_policy_for_role(
                role=membership.role, enabled_factor_types=factor_types, policy=get_policy(membership.organization)
            )
        except ValueError as exc:
            raise StrongFactorRequired(str(exc)) from exc


def _login_lockout_policy(username: str):
    user = User.objects.filter(username=username).first()
    return get_effective_policy(user) if user else get_policy()


def trusted_device_skips_mfa(request, user: User) -> bool:
    """Public wrapper: whether policy allows skipping the second factor on this device."""
    return _trusted_device_skip(request, user)


def authenticate_password_step(*, request, username: str, password: str) -> User | None:
    """
    Returns the user on password success (fully logged in, or awaiting 2FA), or None on
    bad credentials. Raises AccountThrottled when the (IP)/(username, IP) pair is locked.
    """
    from django.contrib.auth import logout

    if getattr(request, "user", None) and request.user.is_authenticated:
        abandon_pending_2fa(request)
        logout(request)

    ip = client_ip(request)
    check_allowed("login", username=username, ip=ip)  # may raise AccountThrottled

    user = authenticate(request, username=username, password=password)
    if not user:
        record_failure("login", username=username, ip=ip, policy=_login_lockout_policy(username))
        record_audit_event(event_type="auth.password.failed", metadata={"username": username}, request=request)
        return None
    if not user.is_security_active:
        # The password was correct; distinguish "needs verification" (safe to reveal, since they
        # proved the password) from generic deactivated/locked (stay generic).
        record_success("login", username=username, ip=ip)
        if user.status == User.Status.PENDING_ACTIVATION:
            raise EmailVerificationRequired(user.email)
        record_audit_event(actor=user, target_user=user, event_type="auth.password.inactive", request=request)
        return None

    record_success("login", username=username, ip=ip)
    request.session.cycle_key()
    if user_mfa_required(user) or enabled_factor_types(user):
        # Opt-in: a login from a policy-trusted device may skip the second factor (off by default).
        if _trusted_device_skip(request, user):
            complete_login(request=request, user=user, event_type="auth.login.completed_trusted_device")
            return user
        request.session["awaiting_2fa_user_id"] = user.pk
        request.session["awaiting_2fa_started_at"] = timezone.now().isoformat()
        request.session["awaiting_2fa_attempts"] = 0
        record_audit_event(actor=user, target_user=user, event_type="auth.password.accepted_awaiting_mfa", request=request)
        return user
    complete_login(request=request, user=user, event_type="auth.login.completed_password_only")
    return user


def _trusted_device_skip(request, user: User) -> bool:
    from security_policies.services import get_effective_policy
    from sessions.services import device_identifier, is_trusted_device

    policy = get_effective_policy(user)
    if not policy.trusted_device_skips_2fa or needs_strong_factor_enrollment(user):
        return False
    return is_trusted_device(user=user, identifier_hash=device_identifier(request))


def strong_factor_required_for_login(user: User) -> bool:
    """True if the user's role/flags require a phishing-resistant/device-bound login factor."""
    if user.force_strong_mfa:
        return True
    for membership in _active_org_memberships(user):
        if role_requires_mfa(membership.role, get_policy(membership.organization)) and membership.role in PRIVILEGED_ROLES:
            return True
    return False


def policy_allowed_2fa_methods(user: User) -> set[str]:
    return set(get_effective_policy(user).allowed_2fa_methods)


def _apply_policy_method_filter(user: User, methods: set[str]) -> set[str]:
    allowed = policy_allowed_2fa_methods(user)
    filtered = methods & allowed
    if "backup_code" in methods and "backup_code" in allowed:
        filtered.add("backup_code")
    return filtered


def allowed_login_methods(user: User) -> set[str]:
    """
    Methods the user may use to COMPLETE a login challenge. Restricted to what they've
    actually enrolled, org policy allowed_2fa_methods, and -- for strong-factor-required
    roles -- to strong factors (plus single-use backup codes for recovery).
    """
    methods = _apply_policy_method_filter(user, available_factor_types(user))
    if strong_factor_required_for_login(user):
        methods = {m for m in methods if m in STRONG_FACTORS or m == "backup_code"}
    return methods


@transaction.atomic
def complete_login(*, request, user: User, event_type: str = "auth.login.completed") -> None:
    # A user deactivated/locked during the awaiting-2FA window must not complete login.
    if not user.is_security_active:
        raise AccountInactive("Account is no longer active.")
    # Raises StrongFactorRequired for a privileged user lacking a strong factor -- callers
    # route such users to enrollment instead of surfacing a 500.
    enforce_privileged_factor_policy(user)
    login(request, user)
    request.session.cycle_key()
    request.session.pop("awaiting_2fa_user_id", None)
    request.session.pop("awaiting_2fa_started_at", None)
    request.session.pop("awaiting_2fa_attempts", None)
    request.session.pop("email_otp_challenge_id", None)
    mark_recent_auth(request, "login")
    user.last_login_at = timezone.now()
    user.save(update_fields=["last_login_at"])
    create_active_session(request, user)
    is_new_device = note_login_device(request, user)
    record_audit_event(actor=user, target_user=user, event_type=event_type, request=request)
    # Notify on a NEW device only -- not on every sign-in -- to avoid alert fatigue.
    if is_new_device:
        emit_outbox_event(
            event_type="login.new_device",
            aggregate_type="user",
            aggregate_id=str(user.pk),
            payload={"user_id": user.pk, "event": event_type},
        )


def pending_2fa_user(request) -> User | None:
    uid = request.session.get("awaiting_2fa_user_id")
    if not uid:
        return None
    return User.objects.filter(pk=uid).first()


def available_factor_types(user: User) -> set[str]:
    """Factor types the user can use to satisfy a login challenge (backup codes always allowed)."""
    factors = enabled_factor_types(user)
    if MFADevice.objects.filter(user=user, type=MFADevice.Type.TOTP, enabled_at__isnull=False, disabled_at__isnull=True).exists():
        factors.add("totp")
    from mfa.models import BackupCode

    if BackupCode.objects.filter(user=user, used_at__isnull=True).exists():
        factors.add("backup_code")
    return factors


def register_pending_2fa_attempt(request) -> bool:
    """
    Count a failed 2FA attempt in the awaiting window. Returns True when the attempt cap
    is exceeded -- the caller must clear the intermediate state and emit a risk event.
    """
    from django.conf import settings

    attempts = int(request.session.get("awaiting_2fa_attempts", 0)) + 1
    request.session["awaiting_2fa_attempts"] = attempts
    return attempts >= settings.AWAITING_2FA_MAX_ATTEMPTS


def abandon_pending_2fa(request, user=None, reason: str = "attempt_cap") -> None:
    uid = request.session.pop("awaiting_2fa_user_id", None)
    request.session.pop("awaiting_2fa_started_at", None)
    request.session.pop("awaiting_2fa_attempts", None)
    request.session.pop("email_otp_challenge_id", None)
    if user is None and uid:
        user = User.objects.filter(pk=uid).first()
    if uid:
        detect_risk_event(user=user, event_type="auth.2fa.abandoned", severity="medium", details={"reason": reason})


@transaction.atomic
def deactivate_user(*, actor: User, user: User, reason: str = "") -> User:
    from django.core.exceptions import PermissionDenied

    from organizations.services import can_manage_user

    if not can_manage_user(actor, user):
        raise PermissionDenied("You are not permitted to deactivate this user.")
    user.status = User.Status.DEACTIVATED
    user.is_active = False
    user.bump_security_stamp()
    user.save(update_fields=["status", "is_active", "security_stamp"])
    revoke_all_user_sessions(actor=actor, user=user, reason="deactivated")
    record_audit_event(actor=actor, target_user=user, event_type="account.deactivated", metadata={"reason": reason})
    emit_outbox_event(
        event_type="account.deactivated", aggregate_type="user",
        aggregate_id=str(user.pk), payload={"user_id": user.pk},
    )
    return user


def export_user_data(user: User) -> dict:
    """Subject-access export of a user's own account/security data (spec 22)."""
    from mfa.models import MFADevice
    from sessions.models import ActiveSession

    return {
        "user": {
            "id": user.pk,
            "username": user.username,
            "email": user.email,
            "email_verified": user.email_verified,
            "status": user.status,
            "created_at": user.created_at.isoformat(),
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        },
        "emails": list(
            EmailAddress.objects.filter(user=user).values("email", "is_primary", "verified_at")
        ),
        "memberships": list(
            OrganizationMembership.objects.filter(user=user).values("organization__slug", "role", "status")
        ),
        "factors": list(MFADevice.objects.filter(user=user).values("type", "name", "enabled_at", "disabled_at")),
        "sessions": list(
            ActiveSession.objects.filter(user=user).values("created_at", "last_seen_at", "ip_address", "revoked_at")
        ),
    }


@transaction.atomic
def erase_user(*, actor: User, user: User) -> User:
    """
    Right-to-erasure (spec 22 / ADR-0024): anonymize/tombstone the subject and destroy
    credentials/secrets, while preserving append-only audit rows (which now reference an
    opaque, anonymized subject). Distinct from deactivation and export.
    """
    from django.core.exceptions import PermissionDenied

    from mfa.models import BackupCode, EmailOTPChallenge, MFADevice, WebAuthnChallenge, WebAuthnCredential
    from passwords.models import EmailVerificationChallenge, PasswordResetChallenge
    from security_events.models import SecurityRiskEvent
    from sessions.models import ActiveSession, DeviceRiskEvent, TrustedDevice

    # Erasure is a platform-level privacy action (or self-service); org admins get deactivation.
    if actor.pk != user.pk and not actor.is_superuser:
        raise PermissionDenied("Erasure requires a platform administrator.")

    opaque = f"erased_{user.pk}"
    user.username = opaque
    user.email = f"{opaque}@erased.invalid"
    user.first_name = ""
    user.last_name = ""
    user.email_verified_at = None
    user.status = User.Status.DEACTIVATED
    user.is_active = False
    user.set_unusable_password()
    user.bump_security_stamp()
    user.save()

    # Destroy credentials and transient challenges (they carry email/IP/UA PII).
    MFADevice.objects.filter(user=user).delete()
    BackupCode.objects.filter(user=user).delete()
    WebAuthnCredential.objects.filter(user=user).delete()
    WebAuthnChallenge.objects.filter(user=user).delete()
    EmailOTPChallenge.objects.filter(user=user).delete()
    EmailAddress.objects.filter(user=user).delete()
    PasswordResetChallenge.objects.filter(user=user).delete()
    EmailVerificationChallenge.objects.filter(user=user).delete()
    TrustedDevice.objects.filter(user=user).delete()

    # Sever PII on rows we retain for operational history.
    revoke_all_user_sessions(actor=actor, user=user, reason="erased")
    ActiveSession.objects.filter(user=user).update(ip_address=None, user_agent="", device_label="")
    DeviceRiskEvent.objects.filter(user=user).update(ip_address=None, user_agent="", metadata={})
    SecurityRiskEvent.objects.filter(user=user).update(detection_details={})

    record_audit_event(actor=actor, target_user=user, event_type="account.erased")
    return user


def require_recent_auth(request, action: str = "default") -> bool:
    # Backwards-compatible shim; recent-auth logic lives in accounts.recent_auth and is
    # scope-aware (global vs per-action).
    from .recent_auth import has_recent_auth

    return has_recent_auth(request, action)
