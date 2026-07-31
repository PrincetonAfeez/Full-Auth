"""
Server-side WebAuthn/passkey ceremonies (spec 13 / ADR-0015).

Uses the audited `webauthn` (py_webauthn) library for attestation/assertion parsing --
never hand-rolled. Challenges are persisted single-use and expiring in WebAuthnChallenge;
registration/assertion validate freshness, expected origin, and RP ID, and track the
signature counter (a non-increasing counter raises a clone-risk event).
"""
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from security_events.services import detect_risk_event, record_audit_event

from .models import MFADevice, WebAuthnChallenge, WebAuthnCredential


def _lib():
    import webauthn
    from webauthn.helpers import bytes_to_base64url
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    return webauthn, bytes_to_base64url, {
        "AuthenticatorSelectionCriteria": AuthenticatorSelectionCriteria,
        "PublicKeyCredentialDescriptor": PublicKeyCredentialDescriptor,
        "ResidentKeyRequirement": ResidentKeyRequirement,
        "UserVerificationRequirement": UserVerificationRequirement,
    }


def _origin_ok(origin: str) -> bool:
    return origin in settings.WEBAUTHN_EXPECTED_ORIGINS


def begin_registration(*, user, origin: str) -> str:
    if not _origin_ok(origin):
        raise ValueError("Untrusted origin")
    webauthn, b64, structs = _lib()
    options = webauthn.generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_id=str(user.pk).encode(),
        user_name=user.username,
        authenticator_selection=structs["AuthenticatorSelectionCriteria"](
            resident_key=structs["ResidentKeyRequirement"].PREFERRED,
            user_verification=structs["UserVerificationRequirement"].REQUIRED,
        ),
    )
    WebAuthnChallenge.objects.create(
        user=user,
        ceremony_type=WebAuthnChallenge.CeremonyType.REGISTRATION,
        challenge=b64(options.challenge),
        expires_at=timezone.now() + timedelta(minutes=5),
        expected_rp_id=settings.WEBAUTHN_RP_ID,
        expected_origin=origin,
    )
    return webauthn.options_to_json(options)


@transaction.atomic
def complete_registration(*, user, credential, origin: str, challenge_b64: str) -> WebAuthnCredential:
    if not _origin_ok(origin):
        raise ValueError("Untrusted origin")
    webauthn, b64, _ = _lib()
    from webauthn.helpers import base64url_to_bytes

    ceremony = (
        WebAuthnChallenge.objects.select_for_update()
        .filter(user=user, challenge=challenge_b64, ceremony_type=WebAuthnChallenge.CeremonyType.REGISTRATION)
        .first()
    )
    if not ceremony or ceremony.user_id != user.pk or ceremony.used_at or ceremony.expires_at <= timezone.now() or ceremony.expected_origin != origin:
        raise ValueError("Invalid WebAuthn ceremony")
    verification = webauthn.verify_registration_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(challenge_b64),
        expected_rp_id=settings.WEBAUTHN_RP_ID,
        expected_origin=origin,
    )
    ceremony.used_at = timezone.now()
    ceremony.save(update_fields=["used_at"])

    device = MFADevice.objects.create(
        user=user, type=MFADevice.Type.WEBAUTHN, name="Passkey", enabled_at=timezone.now()
    )
    cred = WebAuthnCredential.objects.create(
        user=user,
        credential_id=b64(verification.credential_id),
        public_key=b64(verification.credential_public_key),
        sign_count=verification.sign_count,
        device_name="Passkey",
    )
    device.metadata = {"credential_id": cred.pk}
    device.save(update_fields=["metadata"])
    record_audit_event(actor=user, target_user=user, event_type="mfa.webauthn.registered")
    return cred


def _enabled_webauthn_credentials(user):
    """Credentials linked to an enabled WebAuthn MFADevice (disabled factors are excluded)."""
    cred_pks = []
    for device in MFADevice.objects.filter(
        user=user, type=MFADevice.Type.WEBAUTHN, enabled_at__isnull=False, disabled_at__isnull=True
    ):
        cred_pk = (device.metadata or {}).get("credential_id")
        if cred_pk:
            cred_pks.append(cred_pk)
    return WebAuthnCredential.objects.filter(user=user, pk__in=cred_pks, revoked_at__isnull=True)


def begin_assertion(*, user, origin: str) -> str:
    if not _origin_ok(origin):
        raise ValueError("Untrusted origin")
    webauthn, b64, structs = _lib()
    allow = [
        structs["PublicKeyCredentialDescriptor"](id=_b64url_to_bytes(c.credential_id))
        for c in _enabled_webauthn_credentials(user)
    ]
    options = webauthn.generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        allow_credentials=allow or None,
        user_verification=structs["UserVerificationRequirement"].REQUIRED,
    )
    WebAuthnChallenge.objects.create(
        user=user,
        ceremony_type=WebAuthnChallenge.CeremonyType.ASSERTION,
        challenge=b64(options.challenge),
        expires_at=timezone.now() + timedelta(minutes=5),
        expected_rp_id=settings.WEBAUTHN_RP_ID,
        expected_origin=origin,
    )
    return webauthn.options_to_json(options)


def _b64url_to_bytes(value: str) -> bytes:
    from webauthn.helpers import base64url_to_bytes

    return base64url_to_bytes(value)


class SignCountRegressionError(Exception):
    pass


@transaction.atomic
def _complete_assertion_atomic(*, user, credential, origin: str, challenge_b64: str) -> None:
    if not _origin_ok(origin):
        raise ValueError("Untrusted origin")
    webauthn, b64, _ = _lib()
    from webauthn.helpers import base64url_to_bytes

    ceremony = (
        WebAuthnChallenge.objects.select_for_update()
        .filter(user=user, challenge=challenge_b64, ceremony_type=WebAuthnChallenge.CeremonyType.ASSERTION)
        .first()
    )
    if not ceremony or ceremony.user_id != user.pk or ceremony.used_at or ceremony.expires_at <= timezone.now() or ceremony.expected_origin != origin:
        raise ValueError("Invalid WebAuthn ceremony")

    cred_id = credential.get("id") if isinstance(credential, dict) else None
    stored = (
        WebAuthnCredential.objects.select_for_update()
        .filter(user=user, credential_id=cred_id, revoked_at__isnull=True)
        .first()
    )
    if not stored or not _enabled_webauthn_credentials(user).filter(pk=stored.pk).exists():
        raise ValueError("Unknown credential")

    verification = webauthn.verify_authentication_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(challenge_b64),
        expected_rp_id=settings.WEBAUTHN_RP_ID,
        expected_origin=origin,
        credential_public_key=base64url_to_bytes(stored.public_key),
        credential_current_sign_count=stored.sign_count,
    )
    ceremony.used_at = timezone.now()
    ceremony.save(update_fields=["used_at"])

    if verification.new_sign_count <= stored.sign_count and not (verification.new_sign_count == 0 and stored.sign_count == 0):
        raise SignCountRegressionError()
    stored.sign_count = max(stored.sign_count, verification.new_sign_count)
    stored.last_used_at = timezone.now()
    stored.save(update_fields=["sign_count", "last_used_at"])
    record_audit_event(actor=user, target_user=user, event_type="mfa.webauthn.asserted")


def complete_assertion(*, user, credential, origin: str, challenge_b64: str) -> bool:
    try:
        _complete_assertion_atomic(
            user=user, credential=credential, origin=origin, challenge_b64=challenge_b64
        )
    except SignCountRegressionError:
        detect_risk_event(user=user, event_type="mfa.webauthn.sign_count_regression", severity="high")
        raise ValueError("Sign count regression detected") from None
    return True
