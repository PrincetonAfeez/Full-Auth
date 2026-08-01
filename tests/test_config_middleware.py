"""Pytest coverage for config middleware."""
import logging

import pytest
from django.test import RequestFactory

from config.middleware import (
    ApiRateLimitMiddleware,
    RequestIDLogFilter,
    RequestIDMiddleware,
    get_request_id,
)


def _simple_response(request):
    def get_response(req):
        from django.http import HttpResponse

        return HttpResponse("ok")

    return get_response(request)


@pytest.mark.django_db
class TestRequestIDMiddleware:
    def test_generates_request_id(self):
        request = RequestFactory().get("/")
        middleware = RequestIDMiddleware(_simple_response)
        response = middleware(request)
        assert hasattr(request, "request_id")
        assert response["X-Request-ID"] == request.request_id

    def test_honors_inbound_header(self):
        request = RequestFactory().get("/", HTTP_X_REQUEST_ID="abc-123")
        middleware = RequestIDMiddleware(_simple_response)
        response = middleware(request)
        assert request.request_id == "abc-123"
        assert response["X-Request-ID"] == "abc-123"


class TestRequestIDLogFilter:
    def test_injects_request_id(self):
        filt = RequestIDLogFilter()
        record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
        assert filt.filter(record)
        assert hasattr(record, "request_id")


@pytest.mark.django_db
class TestApiRateLimitMiddleware:
    def test_allows_under_limit(self, settings):
        settings.API_RATE_LIMIT_PER_MINUTE = 100
        request = RequestFactory().get("/api/v1/auth/status/")
        request.user = type("U", (), {"is_authenticated": False})()
        middleware = ApiRateLimitMiddleware(_simple_response)
        response = middleware(request)
        assert response.status_code == 200

    def test_blocks_over_limit(self, settings):
        settings.API_RATE_LIMIT_PER_MINUTE = 1
        request = RequestFactory().get("/api/v1/auth/status/", REMOTE_ADDR="1.2.3.4")
        request.user = type("U", (), {"is_authenticated": False})()
        middleware = ApiRateLimitMiddleware(_simple_response)
        middleware(request)
        response = middleware(request)
        assert response.status_code == 429

    def test_non_api_passes(self, settings):
        settings.API_RATE_LIMIT_PER_MINUTE = 0
        request = RequestFactory().get("/login/")
        middleware = ApiRateLimitMiddleware(_simple_response)
        response = middleware(request)
        assert response.status_code == 200
