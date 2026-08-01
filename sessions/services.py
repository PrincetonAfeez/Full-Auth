"""Business logic and service layer for sessions."""
import hashlib
from datetime import timedelta

from django.contrib.auth import logout
from django.db import transaction
from django.utils import timezone

from security_events.services import detect_risk_event, record_audit_event
from security_policies.services import get_effective_policy

from accounts.client_ip import client_ip

from .models import ActiveSession, DeviceRiskEvent, TrustedDevice
from .cache import invalidate_session_cache


def create_active_session(request, user) -> ActiveSession:
    # Use the user's effective (strictest applicable) policy so org-scoped timeouts apply.
    policy = get_effective_policy(user)
    return ActiveSession.create_for_request(request, user, policy)


@transaction.atomic
def revoke_session(*, actor, active_session: ActiveSession, request=None) -> ActiveSession:
    active_session = ActiveSession.objects.select_for_update().get(pk=active_session.pk)
    active_session.revoked_at = timezone.now()
    active_session.revoked_by = actor
    active_session.save(update_fields=["revoked_at", "revoked_by"])
    invalidate_session_cache(active_session.session_key_hash)
    record_audit_event(
        actor=actor,
        target_user=active_session.user,
        event_type="session.revoked",
        metadata={"session": active_session.session_key_hash[:12]},
        request=request,
    )
    return active_session


@transaction.atomic
def revoke_all_user_sessions(*, actor, user, reason: str) -> int:
    # Flag every active session; the enforcement middleware denies each on its next request
    # (it also security-stamp-invalidates when callers bump the stamp). Session-store flush of
    # other devices is intentionally enforcement-based since only the key *hash* is stored.
    count = ActiveSession.objects.filter(user=user, revoked_at__isnull=True).update(
        revoked_at=timezone.now(), revoked_by=actor
    )
    for row in ActiveSession.objects.filter(user=user).values_list("session_key_hash", flat=True):
        invalidate_session_cache(row)
    record_audit_event(actor=actor, target_user=user, event_type="session.revoked_all", metadata={"reason": reason})
    return count


def force_logout(request, reason: str) -> None:
    request.session["security_logout_reason"] = reason
    logout(request)


def trust_device(*, user, identifier_hash: str, display_name: str, policy=None) -> TrustedDevice:
    policy = policy or get_effective_policy(user)
    return TrustedDevice.objects.update_or_create(
        user=user,
        device_identifier_hash=identifier_hash,
        defaults={
            "display_name": display_name,
            "trusted_until": timezone.now() + timedelta(days=policy.trusted_device_duration_days),
            "policy_version": policy.policy_version,
            "revoked_at": None,
        },
    )[0]


@transaction.atomic
def revoke_trusted_device(*, actor, user, device_id: int) -> bool:
    device = TrustedDevice.objects.filter(pk=device_id, user=user, revoked_at__isnull=True).first()
    if not device:
        return False
    device.revoked_at = timezone.now()
    device.save(update_fields=["revoked_at"])
    record_audit_event(actor=actor, target_user=user, event_type="trusted_device.revoked",
                       metadata={"device": device.display_name})
    return True


DEVICE_COOKIE = "device_id"


def device_identifier(request) -> str:
    """
    Device fingerprint. Prefers a per-device opaque cookie (set by the enforcement middleware),
    falling back to a User-Agent hash before the cookie exists. Defense-in-depth signal only.
    """
    if request is None:
        return hashlib.sha256(b"").hexdigest()
    seed = request.COOKIES.get(DEVICE_COOKIE) or request.META.get("HTTP_USER_AGENT", "")
    return hashlib.sha256(seed.encode()).hexdigest()


def is_trusted_device(*, user, identifier_hash: str) -> bool:
    return TrustedDevice.objects.filter(
        user=user, device_identifier_hash=identifier_hash, revoked_at__isnull=True,
        trusted_until__gt=timezone.now(),
    ).exists()


def _device_seen_before(user, identifier: str) -> bool:
    return DeviceRiskEvent.objects.filter(user=user, metadata__device=identifier).exists()


def note_login_device(request, user) -> bool:
    """
    Record the login device and return True only when it is genuinely NEW for this user.
    A SecurityRiskEvent (an *open* signal for the console) is emitted only on first sighting,
    not on every login -- previously-seen (but untrusted) devices are recorded quietly.
    """
    if request is None:
        return False
    identifier = device_identifier(request)
    if is_trusted_device(user=user, identifier_hash=identifier) or _device_seen_before(user, identifier):
        return False
    # First time we've seen this device for this user -> ledger entry + one risk signal.
    DeviceRiskEvent.objects.create(
        user=user,
        event_type="login.new_device",
        severity="low",
        ip_address=client_ip(request) if request else None,
        user_agent=request.META.get("HTTP_USER_AGENT", ""),
        metadata={"device": identifier},
    )
    detect_risk_event(user=user, event_type="login.new_device", severity="low")
    return True
