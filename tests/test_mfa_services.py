"""Pytest coverage for mfa services."""
import pytest
from django.utils import timezone

from mfa.models import MFADevice
from mfa.services import (
    consume_backup_code,
    current_totp_step,
    decrypt_totp_secret,
    enable_totp,
    encrypt_totp_secret,
    generate_backup_codes,
    generate_totp_secret,
    verify_login_factor,
    verify_totp,
    _totp_code,
)


@pytest.mark.django_db
class TestTotpCrypto:
    def test_generate_secret(self):
        secret = generate_totp_secret()
        assert len(secret) >= 16

    def test_encrypt_decrypt_roundtrip(self):
        secret = generate_totp_secret()
        encrypted = encrypt_totp_secret(secret)
        assert decrypt_totp_secret(encrypted) == secret

    def test_totp_code_deterministic(self):
        step = current_totp_step()
        code = _totp_code("JBSWY3DPEHPK3PXP", step)
        assert len(code) == 6
        assert code.isdigit()


@pytest.mark.django_db
class TestEnableAndVerifyTotp:
    def test_enrollment_and_verify(self, verified_user):
        device, secret = enable_totp(user=verified_user, name="Auth App")
        assert device.enabled_at is None
        step = current_totp_step()
        code = _totp_code(secret, step)
        assert verify_totp(device=device, code=code)
        device.refresh_from_db()
        assert device.enabled_at is not None

    def test_wrong_code_fails(self, verified_user):
        device, _secret = enable_totp(user=verified_user, name="Auth")
        assert not verify_totp(device=device, code="000000")


@pytest.mark.django_db
class TestBackupCodes:
    def test_generate_and_consume(self, verified_user):
        codes = generate_backup_codes(user=verified_user, count=3)
        assert len(codes) == 3
        assert consume_backup_code(user=verified_user, code=codes[0])
        assert not consume_backup_code(user=verified_user, code=codes[0])

    def test_invalid_backup_code(self, verified_user):
        assert not consume_backup_code(user=verified_user, code="not-a-code")


@pytest.mark.django_db
class TestVerifyLoginFactor:
    def test_totp_login_factor(self, verified_user):
        from django.test import RequestFactory

        device, secret = enable_totp(user=verified_user, name="Login")
        step = current_totp_step()
        code = _totp_code(secret, step)
        verify_totp(device=device, code=code)
        next_code = _totp_code(secret, step + 1)
        request = RequestFactory().post("/login/2fa")
        assert verify_login_factor(request=request, user=verified_user, method="totp", code=next_code)

    def test_unknown_method(self, verified_user):
        from django.test import RequestFactory

        request = RequestFactory().post("/login/2fa")
        assert not verify_login_factor(request=request, user=verified_user, method="unknown", code="x")
