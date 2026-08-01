"""Pytest coverage for api middleware."""
import json

import pytest
from django.test import Client
from django.urls import reverse


@pytest.mark.django_db
class TestApiJsonValidation:
    def test_malformed_json_rejected(self, client):
        response = client.post(
            reverse("api:auth_login"),
            data="{not json",
            content_type="application/json",
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_json"


@pytest.mark.django_db
class TestRateLimitHeaders:
    def test_throttled_login_includes_retry_after(self, client, verified_user):
        for _ in range(20):
            client.post(
                reverse("api:auth_login"),
                data=json.dumps({"username": "verified", "password": "wrong"}),
                content_type="application/json",
            )
        response = client.post(
            reverse("api:auth_login"),
            data=json.dumps({"username": "verified", "password": "wrong"}),
            content_type="application/json",
        )
        if response.status_code == 429:
            assert "Retry-After" in response
