"""Pytest coverage for accounts recent auth."""
import pytest
from django.test import RequestFactory

from accounts.recent_auth import (
    bind_step_up_challenge,
    consume_step_up_challenge,
    has_recent_auth,
    mark_recent_auth,
    normalize_step_up_action,
    peek_step_up_challenge,
    safe_next_url,
)
from accounts.step_up import (
    clear_step_up_attempts,
    register_step_up_attempt,
    verify_step_up_credential,
)
from mfa.services import _totp_code, current_totp_step, enable_totp, generate_backup_codes, verify_totp


@pytest.mark.django_db
class TestNormalizeStepUpAction:
    @pytest.mark.parametrize(
        "action,expected",
        [
            ("manage_mfa", "manage_mfa"),
            ("change_password", "change_password"),
            ("invalid_action", None),
            ("", None),
        ],
    )
    def test_normalize(self, action, expected):
        assert normalize_step_up_action(action) == expected


@pytest.mark.django_db
class TestSafeNextUrl:
    def test_accepts_relative_path(self, verified_user):
        rf = RequestFactory()
        request = rf.get("/")
        request.user = verified_user
        assert safe_next_url(request, "/security/") == "/security/"

    def test_rejects_external_url(self, verified_user):
        rf = RequestFactory()
        request = rf.get("/")
        request.user = verified_user
        result = safe_next_url(request, "https://evil.example/phish")
        assert "evil.example" not in result


@pytest.mark.django_db
class TestStepUpChallenge:
    def test_bind_and_consume(self, verified_user):
        rf = RequestFactory()
        request = rf.get("/")
        request.session = {}
        request.user = verified_user
        token = bind_step_up_challenge(request, action="manage_mfa", next_url="/security/")
        assert token
        assert peek_step_up_challenge(request) is not None
        assert consume_step_up_challenge(
            request, action="manage_mfa", next_url="/security/", token=token
        )
        assert peek_step_up_challenge(request) is None

    def test_consume_rejects_wrong_token(self, verified_user):
        rf = RequestFactory()
        request = rf.get("/")
        request.session = {}
        request.user = verified_user
        bind_step_up_challenge(request, action="manage_mfa", next_url="/security/")
        assert not consume_step_up_challenge(
            request, action="manage_mfa", next_url="/security/", token="wrong"
        )


@pytest.mark.django_db
class TestRecentAuth:
    def test_mark_and_has_global(self, verified_user):
        rf = RequestFactory()
        request = rf.get("/")
        request.session = {}
        request.user = verified_user
        mark_recent_auth(request, "change_password")
        assert has_recent_auth(request, "change_password")

    def test_expired_recent_auth(self, verified_user):
        rf = RequestFactory()
        request = rf.get("/")
        request.session = {"recent_auth_at": "2000-01-01T00:00:00+00:00"}
        request.user = verified_user
        assert has_recent_auth(request, "default") is False


@pytest.mark.django_db
class TestVerifyStepUpCredential:
    def test_password_verification(self, verified_user):
        assert verify_step_up_credential(user=verified_user, password="CorrectHorse123!")

    def test_wrong_password(self, verified_user):
        assert not verify_step_up_credential(user=verified_user, password="wrong")

    def test_totp_verification(self, verified_user):
        device, secret = enable_totp(user=verified_user, name="Auth")
        step = current_totp_step()
        code = _totp_code(secret, step)
        verify_totp(device=device, code=code)
        next_code = _totp_code(secret, step + 1)
        assert verify_step_up_credential(user=verified_user, totp_code=next_code)

    def test_backup_code_verification(self, verified_user):
        codes = generate_backup_codes(user=verified_user)
        assert verify_step_up_credential(user=verified_user, backup_code=codes[0])


@pytest.mark.django_db
class TestStepUpAttempts:
    def test_register_and_clear(self):
        rf = RequestFactory()
        request = rf.post("/")
        request.session = {}
        assert register_step_up_attempt(request) is False
        clear_step_up_attempts(request)
        assert "step_up_attempts" not in request.session
