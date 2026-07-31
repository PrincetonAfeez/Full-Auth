"""Django unit tests for the mfa app."""
import json
import unittest

from django.test import TestCase, override_settings
from django.utils import timezone

from accounts.models import User
from security_events.models import SecurityRiskEvent
from security_policies.models import SecurityPolicy

try:
    import importlib.util

    from soft_webauthn import SoftWebauthnDevice

    _WEBAUTHN_E2E = importlib.util.find_spec("webauthn") is not None
except Exception:  # optional dev dependency / crypto skew
    _WEBAUTHN_E2E = False

from .services import (
    _totp_code,
    begin_email_otp,
    consume_backup_code,
    current_totp_step,
    enable_totp,
    generate_backup_codes,
    verify_email_otp,
    verify_totp,
)


class MFATests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="member", email="member@example.test", password="CorrectHorse123!", status=User.Status.ACTIVE
        )

    def test_totp_step_is_single_use(self):
        device, secret = enable_totp(user=self.user, name="Authenticator")
        code = _totp_code(secret, current_totp_step())

        self.assertTrue(verify_totp(device=device, code=code))
        self.assertFalse(verify_totp(device=device, code=code))

    def test_backup_codes_are_single_use(self):
        code = generate_backup_codes(user=self.user, count=1)[0]

        self.assertTrue(consume_backup_code(user=self.user, code=code))
        self.assertFalse(consume_backup_code(user=self.user, code=code))

    def test_email_otp_attempt_cap_records_risk(self):
        SecurityPolicy.objects.create(organization=None, email_otp_max_verify_attempts=1)
        challenge, _ = begin_email_otp(user=self.user)

        self.assertFalse(verify_email_otp(challenge_id=challenge.pk, code="000000"))
        self.assertFalse(verify_email_otp(challenge_id=challenge.pk, code="111111"))
        self.assertTrue(
            SecurityRiskEvent.objects.filter(user=self.user, event_type="mfa.email_otp.attempt_cap_exceeded").exists()
        )

    def test_expired_email_otp_is_rejected(self):
        challenge, code = begin_email_otp(user=self.user)
        challenge.expires_at = timezone.now() - timezone.timedelta(seconds=1)
        challenge.save(update_fields=["expires_at"])

        self.assertFalse(verify_email_otp(challenge_id=challenge.pk, code=code))



class WebAuthnSignCountTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="wauser", email="wa@example.test", password="CorrectHorse123!", status=User.Status.ACTIVE
        )
        from .models import MFADevice, WebAuthnCredential

        self.cred = WebAuthnCredential.objects.create(
            user=self.user, credential_id="cred-1", public_key="dGVzdA", sign_count=5, device_name="Passkey"
        )
        MFADevice.objects.create(
            user=self.user,
            type=MFADevice.Type.WEBAUTHN,
            name="Passkey",
            enabled_at=timezone.now(),
            metadata={"credential_id": self.cred.pk},
        )

    def _ceremony(self, challenge="ch-1"):
        from .models import WebAuthnChallenge

        return WebAuthnChallenge.objects.create(
            user=self.user, ceremony_type=WebAuthnChallenge.CeremonyType.ASSERTION, challenge=challenge,
            expires_at=timezone.now() + timezone.timedelta(minutes=5),
            expected_rp_id="localhost", expected_origin="http://localhost:8000",
        )

    def test_sign_count_regression_rejects_assertion(self):
        from unittest.mock import MagicMock, patch

        from mfa import webauthn as wa

        self._ceremony("ch-1")
        verification = MagicMock(new_sign_count=3)
        with patch("mfa.webauthn._lib") as mock_lib:
            webauthn_mod = MagicMock()
            webauthn_mod.verify_authentication_response.return_value = verification
            mock_lib.return_value = (webauthn_mod, lambda x: x, {})
            with self.assertRaises(ValueError):
                wa.complete_assertion(
                    user=self.user, credential={"id": "cred-1"}, origin="http://localhost:8000", challenge_b64="ch-1"
                )
        self.assertTrue(
            SecurityRiskEvent.objects.filter(user=self.user, event_type="mfa.webauthn.sign_count_regression").exists()
        )

    def test_assertion_replay_rejected(self):
        from unittest.mock import MagicMock, patch

        from mfa import webauthn as wa

        self._ceremony("ch-1")
        verification = MagicMock(new_sign_count=6)
        with patch("mfa.webauthn._lib") as mock_lib:
            webauthn_mod = MagicMock()
            webauthn_mod.verify_authentication_response.return_value = verification
            mock_lib.return_value = (webauthn_mod, lambda x: x, {})
            wa.complete_assertion(
                user=self.user, credential={"id": "cred-1"}, origin="http://localhost:8000", challenge_b64="ch-1"
            )
        with self.assertRaises(ValueError):
            wa.complete_assertion(
                user=self.user, credential={"id": "cred-1"}, origin="http://localhost:8000", challenge_b64="ch-1"
            )


ORIGIN = "http://localhost:8000"


def _b64(data):
    from webauthn.helpers import bytes_to_base64url

    return bytes_to_base64url(data)


def _unb64(value):
    from webauthn.helpers import base64url_to_bytes

    return base64url_to_bytes(value)


def _reg_options_to_soft(options_json):
    o = json.loads(options_json)
    return {
        "publicKey": {
            "challenge": _unb64(o["challenge"]),
            "rp": o["rp"],
            "user": {"id": _unb64(o["user"]["id"]), "name": o["user"]["name"], "displayName": o["user"]["displayName"]},
            "pubKeyCredParams": o["pubKeyCredParams"],
        }
    }


def _soft_reg_to_credential(att):
    # Mirror what browser JS posts to the server (base64url strings in a JSON-ish dict).
    return {
        "id": _b64(att["rawId"]),
        "rawId": _b64(att["rawId"]),
        "response": {
            "attestationObject": _b64(att["response"]["attestationObject"]),
            "clientDataJSON": _b64(att["response"]["clientDataJSON"]),
        },
        "type": att["type"],
        "clientExtensionResults": {},
    }


def _assert_options_to_soft(options_json):
    o = json.loads(options_json)
    return {
        "publicKey": {
            "challenge": _unb64(o["challenge"]),
            "rpId": o["rpId"],
            "allowCredentials": [{"type": "public-key", "id": _unb64(c["id"])} for c in o.get("allowCredentials", [])],
        }
    }


def _soft_assert_to_credential(asrt):
    resp = asrt["response"]
    return {
        "id": _b64(asrt["rawId"]),
        "rawId": _b64(asrt["rawId"]),
        "response": {
            "authenticatorData": _b64(resp["authenticatorData"]),
            "clientDataJSON": _b64(resp["clientDataJSON"]),
            "signature": _b64(resp["signature"]),
            "userHandle": _b64(resp["userHandle"]) if resp.get("userHandle") else None,
        },
        "type": asrt["type"],
        "clientExtensionResults": {},
    }


@unittest.skipUnless(_WEBAUTHN_E2E, "requires the optional soft-webauthn dev dependency")
@override_settings(WEBAUTHN_RP_ID="localhost", WEBAUTHN_EXPECTED_ORIGINS=[ORIGIN])
class WebAuthnEndToEndCryptoTests(TestCase):
    """
    Full ceremony with a software authenticator producing REAL attestation/assertion objects,
    driven through the actual mfa.webauthn service layer -- so origin/RP/challenge validation
    and signature verification are exercised, not stubbed.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="passkey", email="pk@example.test", password="CorrectHorse123!", status=User.Status.ACTIVE
        )
        self.device = SoftWebauthnDevice()

    def _register(self):
        from mfa import webauthn as wa

        options_json = wa.begin_registration(user=self.user, origin=ORIGIN)
        challenge_b64 = json.loads(options_json)["challenge"]
        att = self.device.create(_reg_options_to_soft(options_json), ORIGIN)
        return wa.complete_registration(
            user=self.user, credential=_soft_reg_to_credential(att), origin=ORIGIN, challenge_b64=challenge_b64
        )

    def test_full_registration_then_assertion(self):
        from mfa import webauthn as wa
        from mfa.models import MFADevice, WebAuthnCredential

        cred = self._register()
        self.assertTrue(WebAuthnCredential.objects.filter(pk=cred.pk).exists())
        self.assertTrue(MFADevice.objects.filter(user=self.user, type=MFADevice.Type.WEBAUTHN, enabled_at__isnull=False).exists())

        options_json = wa.begin_assertion(user=self.user, origin=ORIGIN)
        challenge_b64 = json.loads(options_json)["challenge"]
        asrt = self.device.get(_assert_options_to_soft(options_json), ORIGIN)
        ok = wa.complete_assertion(
            user=self.user, credential=_soft_assert_to_credential(asrt), origin=ORIGIN, challenge_b64=challenge_b64
        )
        self.assertTrue(ok)
        cred.refresh_from_db()
        self.assertGreaterEqual(cred.sign_count, 1)  # counter advanced by a genuine assertion

    def test_registration_rejects_wrong_origin(self):
        from mfa import webauthn as wa

        options_json = wa.begin_registration(user=self.user, origin=ORIGIN)
        challenge_b64 = json.loads(options_json)["challenge"]
        # Authenticator signs over a DIFFERENT origin -> server verification must reject it.
        att = self.device.create(_reg_options_to_soft(options_json), "http://evil.example")
        with self.assertRaises(Exception):
            wa.complete_registration(
                user=self.user, credential=_soft_reg_to_credential(att), origin=ORIGIN, challenge_b64=challenge_b64
            )

    def test_assertion_ceremony_is_single_use(self):
        from mfa import webauthn as wa

        self._register()
        options_json = wa.begin_assertion(user=self.user, origin=ORIGIN)
        challenge_b64 = json.loads(options_json)["challenge"]
        asrt = self.device.get(_assert_options_to_soft(options_json), ORIGIN)
        cred_dict = _soft_assert_to_credential(asrt)
        self.assertTrue(wa.complete_assertion(user=self.user, credential=cred_dict, origin=ORIGIN, challenge_b64=challenge_b64))
        # Replaying the same (now-used) ceremony must fail.
        with self.assertRaises(ValueError):
            wa.complete_assertion(user=self.user, credential=cred_dict, origin=ORIGIN, challenge_b64=challenge_b64)


class DisableMFADeviceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="disable", email="disable@example.test", password="CorrectHorse123!", status=User.Status.ACTIVE
        )

    def test_disable_webauthn_revokes_credential(self):
        from django.utils import timezone

        from .models import MFADevice, WebAuthnCredential
        from .services import disable_mfa_device

        cred = WebAuthnCredential.objects.create(
            user=self.user, credential_id="cred-x", public_key="dGVzdA", sign_count=0, device_name="Passkey"
        )
        device = MFADevice.objects.create(
            user=self.user,
            type=MFADevice.Type.WEBAUTHN,
            name="Passkey",
            enabled_at=timezone.now(),
            metadata={"credential_id": cred.pk},
        )
        disable_mfa_device(user=self.user, device=device)
        device.refresh_from_db()
        cred.refresh_from_db()
        self.assertIsNotNone(device.disabled_at)
        self.assertIsNotNone(cred.revoked_at)
