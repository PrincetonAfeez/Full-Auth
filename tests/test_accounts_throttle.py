"""Pytest coverage for accounts throttle."""
from unittest.mock import patch

import pytest
from django.test import RequestFactory

from accounts.client_ip import client_ip as direct_client_ip
from accounts.throttle import (
    AccountThrottled,
    ThrottleBackendUnavailable,
    check_allowed,
    clear_lock,
    client_ip,
    rate_limit_request,
    record_failure,
    record_success,
)
from security_policies.models import SecurityPolicy


@pytest.mark.django_db
class TestClientIp:
    def test_remote_addr(self):
        request = RequestFactory().get("/", REMOTE_ADDR="203.0.113.1")
        assert client_ip(request) == "203.0.113.1"

    def test_none_request(self):
        assert direct_client_ip(None) == "unknown"

    def test_x_forwarded_for_when_trusted(self, settings):
        settings.SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
        request = RequestFactory().get("/", HTTP_X_FORWARDED_FOR="198.51.100.2, 10.0.0.1")
        assert client_ip(request) == "198.51.100.2"


@pytest.mark.django_db
class TestThrottleLockout:
    def test_record_failure_locks(self):
        policy = SecurityPolicy.objects.create(organization=None, lockout_threshold=2, lockout_duration_minutes=1)
        record_failure("login", username="u", ip="1.2.3.4", policy=policy)
        record_failure("login", username="u", ip="1.2.3.4", policy=policy)
        with pytest.raises(AccountThrottled):
            check_allowed("login", username="u", ip="1.2.3.4")

    def test_record_success_clears_userip_lock(self):
        policy = SecurityPolicy.objects.create(organization=None, lockout_threshold=2, lockout_duration_minutes=1)
        record_failure("login", username="u", ip="1.2.3.4", policy=policy)
        record_success("login", username="u", ip="1.2.3.4")
        check_allowed("login", username="u", ip="1.2.3.4")

    def test_clear_lock(self):
        policy = SecurityPolicy.objects.create(organization=None, lockout_threshold=1, lockout_duration_minutes=5)
        record_failure("login", username="u", ip="1.2.3.4", policy=policy)
        clear_lock("login", username="u", ip="1.2.3.4")
        check_allowed("login", username="u", ip="1.2.3.4")


@pytest.mark.django_db
class TestRateLimitRequest:
    def test_exceeds_limit(self):
        rate_limit_request("test", ip="9.9.9.9", limit=2, window_seconds=60)
        rate_limit_request("test", ip="9.9.9.9", limit=2, window_seconds=60)
        with pytest.raises(AccountThrottled):
            rate_limit_request("test", ip="9.9.9.9", limit=2, window_seconds=60)


@pytest.mark.django_db
class TestThrottleFailClosed:
    @patch("accounts.throttle.cache.get", side_effect=ConnectionError("redis down"))
    def test_check_allowed_fail_closed(self, _mock, settings):
        settings.THROTTLE_FAIL_CLOSED = True
        with pytest.raises(ThrottleBackendUnavailable):
            check_allowed("login", username="u", ip="1.1.1.1")
