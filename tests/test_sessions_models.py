"""Pytest coverage for sessions models."""
import pytest
from django.contrib.sessions.backends.db import SessionStore
from django.test import RequestFactory
from django.utils import timezone

from sessions.models import ActiveSession, hash_session_key
from security_policies.services import get_effective_policy


def _request_with_session():
    rf = RequestFactory()
    request = rf.get("/", REMOTE_ADDR="203.0.113.10", HTTP_USER_AGENT="TestBrowser/1.0")
    session = SessionStore()
    session.create()
    request.session = session
    return request


@pytest.mark.django_db
class TestActiveSessionModel:
    def test_create_for_request(self, verified_user):
        request = _request_with_session()
        policy = get_effective_policy(verified_user)
        active = ActiveSession.create_for_request(request, verified_user, policy)
        assert active.user_id == verified_user.pk
        assert active.session_key_hash == hash_session_key(request.session.session_key)

    def test_extend_idle(self, verified_user):
        request = _request_with_session()
        policy = get_effective_policy(verified_user)
        active = ActiveSession.create_for_request(request, verified_user, policy)
        before = active.expires_idle_at
        active.extend_idle(policy)
        assert active.expires_idle_at >= before

    def test_hash_session_key_deterministic(self):
        assert hash_session_key("abc") == hash_session_key("abc")
        assert hash_session_key("abc") != hash_session_key("def")
