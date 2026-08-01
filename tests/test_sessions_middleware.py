"""Pytest coverage for sessions middleware."""
import pytest
from django.contrib.sessions.backends.db import SessionStore
from django.test import RequestFactory
from django.utils import timezone

from sessions.middleware import SecurityEnforcementMiddleware
from sessions.models import ActiveSession, hash_session_key
from sessions.services import (
    create_active_session,
    device_identifier,
    is_trusted_device,
    note_login_device,
    revoke_all_user_sessions,
    revoke_session,
    revoke_trusted_device,
    trust_device,
)
from sessions.cache import get_cached_session_id, invalidate_session_cache, set_cached_session_id


def _middleware_response(request):
    def get_response(req):
        from django.http import HttpResponse
        return HttpResponse("ok")

    return SecurityEnforcementMiddleware(get_response)(request)


@pytest.mark.django_db
class TestSessionCache:
    def test_set_get_invalidate(self):
        set_cached_session_id("abc123", 42)
        assert get_cached_session_id("abc123") == 42
        invalidate_session_cache("abc123")
        assert get_cached_session_id("abc123") is None


def _request_with_session(method="get", path="/", **kwargs):
    rf = RequestFactory()
    request = getattr(rf, method)(path, **kwargs)
    session = SessionStore()
    session.create()
    request.session = session
    return request


@pytest.mark.django_db
class TestSessionServices:
    def test_create_active_session(self, verified_user):
        request = _request_with_session()
        session = create_active_session(request, verified_user)
        assert session.user_id == verified_user.pk

    def test_revoke_session(self, verified_user, superuser):
        request = _request_with_session()
        active = create_active_session(request, verified_user)
        revoke_session(actor=superuser, active_session=active, request=request)
        active.refresh_from_db()
        assert active.revoked_at is not None

    def test_revoke_all_user_sessions(self, verified_user, superuser):
        request = _request_with_session()
        create_active_session(request, verified_user)
        count = revoke_all_user_sessions(actor=superuser, user=verified_user, reason="test")
        assert count >= 1

    def test_trust_and_revoke_device(self, verified_user, superuser):
        ident = "devicehash123"
        device = trust_device(user=verified_user, identifier_hash=ident, display_name="Laptop")
        assert is_trusted_device(user=verified_user, identifier_hash=ident)
        assert revoke_trusted_device(actor=superuser, user=verified_user, device_id=device.pk)
        assert not is_trusted_device(user=verified_user, identifier_hash=ident)

    def test_device_identifier(self):
        rf = RequestFactory()
        request = rf.get("/", HTTP_USER_AGENT="TestAgent/1.0")
        assert len(device_identifier(request)) == 64

    def test_note_login_device_new(self, verified_user):
        rf = RequestFactory()
        request = rf.get("/", HTTP_USER_AGENT="BrandNewDevice/1.0")
        assert note_login_device(request, verified_user) is True
        assert note_login_device(request, verified_user) is False


@pytest.mark.django_db
class TestSecurityEnforcementMiddleware:
    def test_bypass_healthz(self):
        rf = RequestFactory()
        request = rf.get("/healthz")
        response = _middleware_response(request)
        assert response.status_code == 200

    def test_unauthenticated_passes(self):
        rf = RequestFactory()
        request = rf.get("/login/")
        request.user = type("U", (), {"is_authenticated": False})()
        request.session = {}
        response = _middleware_response(request)
        assert response.status_code == 200

    def test_missing_active_session_denies(self, verified_user, auth_client):
        rf = RequestFactory()
        request = rf.get("/security/")
        request.user = verified_user
        request.session = auth_client.session
        ActiveSession.objects.filter(user=verified_user).delete()
        response = _middleware_response(request)
        assert response.status_code in (302, 401)

    def test_expired_session_denies(self, verified_user, auth_client):
        rf = RequestFactory()
        request = rf.get("/security/")
        request.user = verified_user
        request.session = auth_client.session
        session_hash = hash_session_key(request.session.session_key)
        active = ActiveSession.objects.get(session_key_hash=session_hash)
        active.expires_idle_at = timezone.now() - timezone.timedelta(minutes=1)
        active.save(update_fields=["expires_idle_at"])
        invalidate_session_cache(session_hash)
        response = _middleware_response(request)
        assert response.status_code in (302, 401)
