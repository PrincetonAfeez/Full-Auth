"""Pytest coverage for passwords services."""
from unittest.mock import MagicMock, patch

import pytest
from django.test import RequestFactory

from accounts.models import User
from passwords.models import EmailVerificationChallenge, PasswordResetChallenge
from passwords.services import (
    EmailAlreadyInUse,
    change_password,
    complete_password_reset,
    request_email_change,
    request_email_verification,
    request_password_reset,
    screen_breached_password,
    verify_email,
)


@pytest.mark.django_db
class TestScreenBreachedPassword:
    def test_disabled_skips(self, settings):
        settings.BREACH_SCREENING_ENABLED = False
        screen_breached_password("anypassword")

    @patch("passwords.services.urlopen")
    def test_breached_password_raises(self, mock_urlopen, settings):
        settings.BREACH_SCREENING_ENABLED = True
        settings.HIBP_RANGE_API_URL = "https://api.pwnedpasswords.com/range/"
        mock_urlopen.return_value.__enter__.return_value.read.return_value = b"ABCDE:123\n"
        with patch("passwords.services.hashlib.sha1") as mock_sha1:
            mock_sha1.return_value.hexdigest.return_value = "00000ABCDE"
            with pytest.raises(ValueError, match="breached"):
                screen_breached_password("password123")


@pytest.mark.django_db
class TestPasswordReset:
    def test_request_and_complete(self, user_factory, settings):
        settings.BREACH_SCREENING_ENABLED = False
        user = user_factory("resetme")
        rf = RequestFactory()
        request = rf.post("/reset/")
        _challenge, token = request_password_reset(user=user, request=request)
        assert PasswordResetChallenge.objects.filter(user=user).exists()
        assert complete_password_reset(token=token, new_password="NewCorrectHorse456!")
        user.refresh_from_db()
        assert user.check_password("NewCorrectHorse456!")

    def test_invalid_token(self):
        assert not complete_password_reset(token="bad", new_password="NewCorrectHorse456!")


@pytest.mark.django_db
class TestChangePassword:
    def test_success(self, verified_user, settings):
        settings.BREACH_SCREENING_ENABLED = False
        change_password(user=verified_user, current_password="CorrectHorse123!", new_password="NewCorrectHorse456!")
        verified_user.refresh_from_db()
        assert verified_user.check_password("NewCorrectHorse456!")

    def test_wrong_current(self, verified_user):
        with pytest.raises(ValueError, match="incorrect"):
            change_password(user=verified_user, current_password="wrong", new_password="NewCorrectHorse456!")


@pytest.mark.django_db
class TestEmailVerification:
    def test_request_and_verify(self, user_factory, settings):
        settings.BREACH_SCREENING_ENABLED = False
        user = user_factory("verifyme", email_verified=False, status=User.Status.PENDING_ACTIVATION)
        _challenge, token = request_email_verification(user=user)
        assert EmailVerificationChallenge.objects.filter(user=user).exists()
        assert verify_email(token=token)
        user.refresh_from_db()
        assert user.email_verified_at is not None

    def test_email_already_in_use(self, user_factory):
        user_factory("existing", email="taken@example.test")
        user = user_factory("claimer", email="other@example.test", email_verified=False)
        _challenge, token = request_email_verification(user=user, email="taken@example.test")
        with pytest.raises(EmailAlreadyInUse):
            verify_email(token=token)

    def test_request_email_change(self, verified_user):
        _challenge, token = request_email_change(user=verified_user, new_email="newaddr@example.test")
        assert token
        verified_user.refresh_from_db()
