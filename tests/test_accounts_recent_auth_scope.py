"""Pytest coverage for accounts recent auth scope."""
import pytest
from django.test import RequestFactory
from django.utils import timezone

from accounts.recent_auth import has_recent_auth, mark_recent_auth, recent_auth_required
from security_policies.services import get_policy


@pytest.mark.django_db
class TestRecentAuthScope:
    def test_per_action_scope(self, verified_user, settings):
        policy = get_policy()
        policy.recent_auth_scope = "per_action"
        policy.save()
        rf = RequestFactory()
        request = rf.get("/")
        request.session = {}
        request.user = verified_user
        mark_recent_auth(request, "manage_mfa")
        assert has_recent_auth(request, "manage_mfa")
        assert not has_recent_auth(request, "change_password")

    def test_global_scope(self, verified_user):
        policy = get_policy()
        policy.recent_auth_scope = "global"
        policy.save()
        rf = RequestFactory()
        request = rf.get("/")
        request.session = {}
        request.user = verified_user
        mark_recent_auth(request, "manage_mfa")
        assert has_recent_auth(request, "change_password")


@pytest.mark.django_db
class TestRecentAuthDecorator:
    def test_decorator_redirects_without_auth(self, verified_user):
        from django.http import HttpResponse

        @recent_auth_required(action="manage_mfa")
        def protected(request):
            return HttpResponse("ok")

        rf = RequestFactory()
        request = rf.get("/security/")
        request.user = verified_user
        request.session = {}
        response = protected(request)
        assert response.status_code in (302, 403)

    def test_decorator_allows_with_fresh_auth(self, verified_user):
        from django.http import HttpResponse

        @recent_auth_required(action="manage_mfa")
        def protected(request):
            return HttpResponse("ok")

        rf = RequestFactory()
        request = rf.get("/security/")
        request.user = verified_user
        request.session = {}
        mark_recent_auth(request, "manage_mfa")
        response = protected(request)
        assert response.status_code == 200
