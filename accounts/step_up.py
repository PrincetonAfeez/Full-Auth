"""Step-up and recent-auth credential verification helpers."""
from django.conf import settings

from accounts.services import policy_allowed_2fa_methods
from accounts.throttle import AccountThrottled, check_allowed, client_ip, record_failure, record_success
from mfa.models import MFADevice
from mfa.services import consume_backup_code, verify_totp


def verify_step_up_credential(*, user, password: str = "", totp_code: str = "", backup_code: str = "") -> bool:
    """Return True when the user re-proved with password or an enrolled policy-allowed factor."""
    allowed = policy_allowed_2fa_methods(user)
    if password and user.has_usable_password() and user.check_password(password):
        return True
    if totp_code and "totp" in allowed:
        device = MFADevice.objects.filter(
            user=user, type=MFADevice.Type.TOTP, enabled_at__isnull=False, disabled_at__isnull=True
        ).first()
        return bool(device and verify_totp(device=device, code=totp_code))
    if backup_code and "backup_code" in allowed:
        return consume_backup_code(user=user, code=backup_code)
    return False


def check_step_up_allowed(*, request, user) -> None:
    """Raise AccountThrottled when step-up verification is rate-limited."""
    check_allowed("step_up", username=user.username, ip=client_ip(request))


def record_step_up_failure(*, request, user) -> None:
    from security_policies.services import get_effective_policy

    record_failure("step_up", username=user.username, ip=client_ip(request), policy=get_effective_policy(user))


def record_step_up_success(*, request, user) -> None:
    record_success("step_up", username=user.username, ip=client_ip(request))


def register_step_up_attempt(request) -> bool:
    """Count a failed step-up attempt; return True when cap exceeded."""
    attempts = int(request.session.get("step_up_attempts", 0)) + 1
    request.session["step_up_attempts"] = attempts
    return attempts >= getattr(settings, "STEP_UP_MAX_ATTEMPTS", 5)


def clear_step_up_attempts(request) -> None:
    request.session.pop("step_up_attempts", None)
