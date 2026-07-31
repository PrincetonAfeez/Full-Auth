"""Business logic and service layer for mfa."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
import uuid
from datetime import timedelta

from cryptography.fernet import Fernet
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from security_events.services import detect_risk_event, record_audit_event
from security_policies.services import get_effective_policy

from .models import BackupCode, EmailOTPChallenge, MFADevice, TOTPDevice, WebAuthnCredential


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _fernet() -> Fernet:
    key = settings.TOTP_ENCRYPTION_KEY
    if not key:
        if getattr(settings, "TESTING", False):
            digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
            key = base64.urlsafe_b64encode(digest).decode()
        else:
            raise RuntimeError("TOTP_ENCRYPTION_KEY must be configured.")
    return Fernet(key.encode())


def encrypt_totp_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_totp_secret(encrypted_secret: str) -> str:
    return _fernet().decrypt(encrypted_secret.encode()).decode()


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp_code(secret: str, step: int, digits: int = 6) -> str:
    normalized = secret + ("=" * ((8 - len(secret) % 8) % 8))
    key = base64.b32decode(normalized, casefold=True)
    msg = struct.pack(">Q", step)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def current_totp_step(timestamp: int | None = None, period: int = 30) -> int:
    return int((timestamp or time.time()) // period)


@transaction.atomic
def enable_totp(*, user, name: str) -> tuple[MFADevice, str]:
    """
    Begin TOTP enrollment. The device is created *disabled*; it only becomes enabled once
    the user confirms a first valid code via verify_totp (spec 13: first-code verification
    before enabling).
    """
    secret = generate_totp_secret()
    device = MFADevice.objects.create(user=user, type=MFADevice.Type.TOTP, name=name)
    TOTPDevice.objects.create(device=device, encrypted_secret=encrypt_totp_secret(secret))
    record_audit_event(actor=user, target_user=user, event_type="mfa.totp.enrollment_started")
    return device, secret


@transaction.atomic
def verify_totp(*, device: MFADevice, code: str, drift: int = 1) -> bool:
    totp = TOTPDevice.objects.select_for_update().get(device=device)
    secret = decrypt_totp_secret(totp.encrypted_secret)
    now_step = current_totp_step()
    for step in range(now_step - drift, now_step + drift + 1):
        if step <= totp.last_accepted_step:
            continue
        if hmac.compare_digest(_totp_code(secret, step), code):
            totp.last_accepted_step = step
            totp.confirmed_at = totp.confirmed_at or timezone.now()
            totp.save(update_fields=["last_accepted_step", "confirmed_at"])
            device.enabled_at = device.enabled_at or timezone.now()
            device.disabled_at = None
            device.last_used_at = timezone.now()
            device.save(update_fields=["enabled_at", "disabled_at", "last_used_at"])
            return True
    return False


def generate_backup_codes(*, user, count: int = 10) -> list[str]:
    batch_id = str(uuid.uuid4())
    BackupCode.objects.filter(user=user, used_at__isnull=True).update(used_at=timezone.now())
    plain_codes = [secrets.token_urlsafe(9) for _ in range(count)]
    BackupCode.objects.bulk_create(
        [BackupCode(user=user, code_hash=_hash_secret(code), batch_id=batch_id) for code in plain_codes]
    )
    record_audit_event(actor=user, target_user=user, event_type="mfa.backup_codes.generated")
    return plain_codes


@transaction.atomic
def consume_backup_code(*, user, code: str) -> bool:
    code_hash = _hash_secret(code)
    backup = BackupCode.objects.select_for_update().filter(user=user, code_hash=code_hash, used_at__isnull=True).first()
    if not backup:
        return False
    backup.used_at = timezone.now()
    backup.save(update_fields=["used_at"])
    record_audit_event(actor=user, target_user=user, event_type="mfa.backup_code.used")
    return True


def verify_login_factor(*, request, user, method: str, code: str) -> bool:
    """Verify a login-time second factor. WebAuthn uses dedicated ceremony endpoints."""
    if method == "totp":
        device = MFADevice.objects.filter(
            user=user, type=MFADevice.Type.TOTP, enabled_at__isnull=False, disabled_at__isnull=True
        ).first()
        return bool(device and verify_totp(device=device, code=code))
    if method == "email_otp":
        challenge_id = request.session.get("email_otp_challenge_id")
        return bool(challenge_id and verify_email_otp(challenge_id=challenge_id, code=code, user=user))
    if method == "backup_code":
        return consume_backup_code(user=user, code=code)
    return False


def register_totp_enroll_attempt(request) -> bool:
    """Count a failed TOTP enrollment confirm; return True when cap exceeded."""
    attempts = int(request.session.get("totp_enroll_attempts", 0)) + 1
    request.session["totp_enroll_attempts"] = attempts
    return attempts >= getattr(settings, "STEP_UP_MAX_ATTEMPTS", 5)


def clear_totp_enroll_attempts(request) -> None:
    request.session.pop("totp_enroll_attempts", None)


def enable_email_otp(*, user) -> MFADevice:
    """
    Enroll Email OTP as a login factor (spec 13: requires a verified primary email). Creates
    (or re-enables) an enabled MFADevice of type email_otp so it becomes selectable at login.
    """
    if not user.email_verified:
        raise ValueError("Verify your primary email before enabling email OTP.")
    # filter().first() (not get_or_create) since there is no unique (user, type) constraint.
    device = MFADevice.objects.filter(user=user, type=MFADevice.Type.EMAIL_OTP).first()
    if device is None:
        device = MFADevice.objects.create(user=user, type=MFADevice.Type.EMAIL_OTP, name="Email OTP", enabled_at=timezone.now())
    elif device.disabled_at or device.enabled_at is None:
        device.disabled_at = None
        device.enabled_at = device.enabled_at or timezone.now()
        device.save(update_fields=["disabled_at", "enabled_at"])
    record_audit_event(actor=user, target_user=user, event_type="mfa.email_otp.enabled")
    return device


def store_totp_enrollment_secret(*, user_id: int, device_id: int, secret: str, ttl: int = 600) -> None:
    from django.core.cache import cache

    cache.set(f"totp_enroll:{user_id}:{device_id}", encrypt_totp_secret(secret), ttl)


def get_totp_enrollment_secret(*, user_id: int, device_id: int) -> str | None:
    from django.core.cache import cache

    encrypted = cache.get(f"totp_enroll:{user_id}:{device_id}")
    if not encrypted:
        return None
    return decrypt_totp_secret(encrypted)


def clear_totp_enrollment_secret(*, user_id: int, device_id: int) -> None:
    from django.core.cache import cache

    cache.delete(f"totp_enroll:{user_id}:{device_id}")


class EmailOTPThrottled(Exception):
    """Too many Email-OTP codes requested in the throttle window."""


def _email_otp_resend_allowed(user, max_per_window: int = 3, window_seconds: int = 600) -> bool:
    from django.core.cache import cache

    key = f"otp_resend:{user.pk}"
    try:
        cache.add(key, 0, window_seconds)
        return (cache.incr(key) or 0) <= max_per_window
    except Exception:
        from django.conf import settings

        if getattr(settings, "ENVIRONMENT", "development") in getattr(settings, "DEPLOY_ENVIRONMENTS", ("production", "staging")):
            return False
        return not getattr(settings, "THROTTLE_FAIL_CLOSED", False)


def begin_email_otp(*, user, request=None, deliver: bool = False) -> tuple[EmailOTPChallenge, str]:
    if not _email_otp_resend_allowed(user):
        raise EmailOTPThrottled("Too many verification codes requested. Try again later.")
    code = f"{secrets.randbelow(1000000):06d}"
    from accounts.client_ip import client_ip

    challenge = EmailOTPChallenge.objects.create(
        user=user,
        target_email=user.email,
        code_hash=_hash_secret(code),
        expires_at=timezone.now() + timedelta(minutes=10),
        resend_count=0,
        request_metadata={"ip": client_ip(request)} if request else {},
    )
    record_audit_event(actor=user, target_user=user, event_type="mfa.email_otp.challenge_created")
    if deliver:
        dispatch_email_otp(challenge=challenge, code=code)
    return challenge, code


def dispatch_email_otp(*, challenge: EmailOTPChallenge, code: str) -> None:
    """
    Send the code to the target email. Email OTP is an inherently interactive challenge, so
    it is sent in-path rather than via the outbox -- the plaintext code is never persisted.
    """
    from django.core.mail import send_mail

    send_mail(
        subject="Your Full Auth verification code",
        message=f"Your verification code is {code}. It expires in 10 minutes.",
        from_email=None,
        recipient_list=[challenge.target_email],
        fail_silently=False,
    )


@transaction.atomic
def verify_email_otp(*, challenge_id: int, code: str, user=None) -> bool:
    qs = EmailOTPChallenge.objects.select_for_update().filter(pk=challenge_id)
    if user is not None:
        qs = qs.filter(user=user)
    challenge = qs.first()
    if challenge is None:  # missing/stale/foreign challenge -> clean failure, never a 500
        return False
    policy = get_effective_policy(challenge.user)
    if challenge.used_at or challenge.expires_at <= timezone.now():
        return False
    if challenge.verify_attempts >= policy.email_otp_max_verify_attempts:
        detect_risk_event(user=challenge.user, event_type="mfa.email_otp.attempt_cap_exceeded", severity="medium")
        return False
    challenge.verify_attempts += 1
    ok = hmac.compare_digest(challenge.code_hash, _hash_secret(code))
    if ok:
        challenge.used_at = timezone.now()
    challenge.save(update_fields=["verify_attempts", "used_at"])
    return ok


@transaction.atomic
def disable_mfa_device(*, user, device: MFADevice) -> None:
    """Disable a factor atomically; revoke linked passkey credentials when applicable."""
    from accounts.services import needs_strong_factor_enrollment

    if device.user_id != user.pk:
        raise ValueError("Factor not found.")
    now = timezone.now()
    cred_pk = None
    device.disabled_at = now
    device.save(update_fields=["disabled_at"])
    if device.type == MFADevice.Type.WEBAUTHN:
        cred_pk = (device.metadata or {}).get("credential_id")
        if cred_pk:
            WebAuthnCredential.objects.filter(user=user, pk=cred_pk, revoked_at__isnull=True).update(revoked_at=now)
    if needs_strong_factor_enrollment(user):
        device.disabled_at = None
        device.save(update_fields=["disabled_at"])
        if cred_pk:
            WebAuthnCredential.objects.filter(user=user, pk=cred_pk).update(revoked_at=None)
        raise ValueError("You must keep at least one strong factor (TOTP or passkey) enrolled.")
