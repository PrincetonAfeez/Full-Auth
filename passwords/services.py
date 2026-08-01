"""Business logic and service layer for passwords."""
import hashlib
import secrets
from datetime import timedelta
from urllib.error import URLError
from urllib.request import Request, urlopen

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.db import transaction
from django.utils import timezone

from accounts.models import User
from notifications.services import emit_outbox_event
from security_events.services import record_audit_event
from sessions.services import revoke_all_user_sessions

from .models import EmailVerificationChallenge, PasswordResetChallenge


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


_HIBP_BREAKER_KEY = "hibp:consecutive_failures"
_HIBP_BREAKER_TTL = 300


def _hibp_breaker_failures() -> int:
    from django.core.cache import cache

    try:
        return cache.get(_HIBP_BREAKER_KEY, 0) or 0
    except Exception:
        return 0


def _hibp_record_failure() -> int:
    from django.core.cache import cache

    try:
        cache.add(_HIBP_BREAKER_KEY, 0, _HIBP_BREAKER_TTL)
        return cache.incr(_HIBP_BREAKER_KEY) or 0
    except Exception:
        return 0


def _hibp_reset() -> None:
    from django.core.cache import cache

    try:
        cache.delete(_HIBP_BREAKER_KEY)
    except Exception:
        pass


def screen_breached_password(password: str) -> None:
    # Toggle lets tests/offline environments skip the live HIBP call (hermetic, no network).
    if not getattr(settings, "BREACH_SCREENING_ENABLED", True):
        return
    # SHA-1 is the HIBP range-API protocol hash (k-anonymity), NOT password storage (that's
    # Argon2). usedforsecurity=False documents intent and silences SAST.
    digest = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    if not settings.HIBP_RANGE_API_URL.startswith(("http://", "https://")):
        return  # only ever call an HTTP(S) endpoint; never file:// or custom schemes
    try:
        request = Request(settings.HIBP_RANGE_API_URL + prefix, headers={"User-Agent": "full-auth-platform"})
        with urlopen(request, timeout=2) as response:  # nosec B310 - scheme validated above
            body = response.read().decode()
    except (OSError, URLError):
        # Circuit breaker: a brief blip still fails CLOSED in production (blocks the weak-password
        # path), but a SUSTAINED outage trips the breaker and degrades to fail-OPEN (skip
        # screening) with a high-severity alert -- so a HIBP outage can't take down signup/reset.
        from security_events.services import detect_risk_event

        failures = _hibp_record_failure()
        threshold = getattr(settings, "HIBP_BREAKER_THRESHOLD", 5)
        if failures >= threshold:
            detect_risk_event(event_type="hibp.circuit_open", severity="high",
                              details={"consecutive_failures": failures})
            return  # degrade gracefully
        if settings.ENVIRONMENT in getattr(settings, "DEPLOY_ENVIRONMENTS", {"production", "staging"}):
            raise ValueError("Password breach screening is temporarily unavailable")
        return
    _hibp_reset()
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate == suffix:
            raise ValueError(f"Password appears in a breached corpus ({count} matches)")


def request_password_reset(*, user, request=None) -> tuple[PasswordResetChallenge, str]:
    token = secrets.token_urlsafe(32)
    from accounts.client_ip import client_ip

    with transaction.atomic():
        PasswordResetChallenge.objects.filter(user=user, used_at__isnull=True, superseded_at__isnull=True).update(
            superseded_at=timezone.now()
        )
        challenge = PasswordResetChallenge.objects.create(
            user=user,
            token_hash=_hash(token),
            expires_at=timezone.now() + timedelta(hours=1),
            requester_ip=client_ip(request) if request else None,
            requester_user_agent=request.META.get("HTTP_USER_AGENT", "") if request else "",
        )
        emit_outbox_event(
            event_type="password_reset.requested",
            aggregate_type="user",
            aggregate_id=str(user.pk),
            # token is transient: the worker builds the email link then scrubs it from the row.
            payload={"user_id": user.pk, "challenge_id": challenge.pk, "token": token},
        )
        record_audit_event(actor=None, target_user=user, event_type="password.reset.requested", request=request)
    return challenge, token


@transaction.atomic
def complete_password_reset(*, token: str, new_password: str) -> bool:
    challenge = PasswordResetChallenge.objects.select_for_update().filter(token_hash=_hash(token)).first()
    if not challenge or challenge.used_at or challenge.superseded_at or challenge.expires_at <= timezone.now():
        return False
    validate_password(new_password, user=challenge.user)
    screen_breached_password(new_password)
    challenge.user.set_password(new_password)
    challenge.user.bump_security_stamp()
    challenge.user.save(update_fields=["password", "security_stamp"])
    challenge.used_at = timezone.now()
    challenge.save(update_fields=["used_at"])
    revoke_all_user_sessions(actor=challenge.user, user=challenge.user, reason="password_reset")
    record_audit_event(actor=challenge.user, target_user=challenge.user, event_type="password.reset.completed")
    return True


@transaction.atomic
def change_password(*, user, current_password: str, new_password: str) -> None:
    """Authenticated password change (spec 15/16 -- recent-auth enforced at the view)."""
    if not user.check_password(current_password):
        raise ValueError("Current password is incorrect.")
    validate_password(new_password, user=user)
    screen_breached_password(new_password)
    user.set_password(new_password)
    user.bump_security_stamp()
    user.save(update_fields=["password", "security_stamp"])
    revoke_all_user_sessions(actor=user, user=user, reason="password_changed")
    emit_outbox_event(
        event_type="password.changed",
        aggregate_type="user",
        aggregate_id=str(user.pk),
        payload={"user_id": user.pk},
    )
    record_audit_event(actor=user, target_user=user, event_type="password.changed")


def request_email_verification(*, user, email: str | None = None) -> tuple[EmailVerificationChallenge, str]:
    token = secrets.token_urlsafe(32)
    email = (email or user.email).lower()
    EmailVerificationChallenge.objects.filter(user=user, email=email, used_at__isnull=True, superseded_at__isnull=True).update(
        superseded_at=timezone.now()
    )
    challenge = EmailVerificationChallenge.objects.create(
        user=user,
        email=email,
        token_hash=_hash(token),
        expires_at=timezone.now() + timedelta(hours=24),
    )
    emit_outbox_event(
        event_type="email_verification.requested",
        aggregate_type="user",
        aggregate_id=str(user.pk),
        payload={"user_id": user.pk, "challenge_id": challenge.pk, "token": token, "email": email},
    )
    return challenge, token


class EmailAlreadyInUse(ValueError):
    """The target email is already claimed by another account."""


@transaction.atomic
def verify_email(*, token: str) -> bool:
    from accounts.models import EmailAddress

    challenge = EmailVerificationChallenge.objects.select_for_update().filter(token_hash=_hash(token)).first()
    if not challenge or challenge.used_at or challenge.superseded_at or challenge.expires_at <= timezone.now():
        return False
    user = challenge.user
    target = challenge.email.lower()

    # Uniqueness guard: never let verification 500 on a colliding email (spec: fail safely).
    if User.objects.filter(email=target).exclude(pk=user.pk).exists():
        raise EmailAlreadyInUse("That email is already associated with another account.")
    if EmailAddress.objects.filter(email=target).exclude(user=user).exists():
        raise EmailAlreadyInUse("That email is already associated with another account.")

    email_changed = user.email.lower() != target
    user.email = target
    user.mark_email_verified()
    user.save(update_fields=["email", "email_verified_at", "status"])

    # Keep the EmailAddress projection consistent with User.email. Demote the old primary
    # FIRST so we never momentarily have two rows with is_primary=True (which would violate
    # the one_primary_email_per_user partial-unique constraint on an email change).
    EmailAddress.objects.filter(user=user, is_primary=True).exclude(email=target).update(is_primary=False)
    EmailAddress.objects.update_or_create(
        user=user,
        email=target,
        defaults={"is_primary": True, "verified_at": timezone.now(), "pending_change_to": ""},
    )

    if email_changed:
        # Invalidate pending Email-OTP challenges tied to the old address (spec 13/15).
        _invalidate_pending_email_otp(user)

    challenge.used_at = timezone.now()
    challenge.save(update_fields=["used_at"])
    record_audit_event(actor=user, target_user=user, event_type="email.verified")
    return True


def _invalidate_pending_email_otp(user) -> None:
    from mfa.models import EmailOTPChallenge

    EmailOTPChallenge.objects.filter(user=user, used_at__isnull=True).update(used_at=timezone.now())


@transaction.atomic
def request_email_change(*, user, new_email: str, request=None):
    """
    Begin a primary-email change: record the pending target and send a verification link to
    the NEW address. The change only takes effect once verify_email consumes that token.
    Requires recent-auth at the view layer (spec 15).
    """
    from accounts.models import EmailAddress

    new_email = new_email.lower()
    if User.objects.filter(email=new_email).exclude(pk=user.pk).exists():
        raise EmailAlreadyInUse("That email is already associated with another account.")
    EmailAddress.objects.filter(user=user, is_primary=True).update(pending_change_to=new_email)
    _invalidate_pending_email_otp(user)
    record_audit_event(actor=user, target_user=user, event_type="email.change.requested", request=request)
    return request_email_verification(user=user, email=new_email)
