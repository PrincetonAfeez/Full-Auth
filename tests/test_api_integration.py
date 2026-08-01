"""Pytest coverage for api integration."""
import json

import pytest
from django.urls import reverse


@pytest.mark.django_db
class TestAuthStatus:
    def test_unauthenticated(self, client):
        response = client.get(reverse("api:auth_status"))
        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is False

    def test_authenticated(self, auth_client):
        response = auth_client.get(reverse("api:auth_status"))
        assert response.status_code == 200
        assert response.json()["authenticated"] is True


@pytest.mark.django_db
class TestMeEndpoint:
    def test_me_returns_user(self, auth_client, verified_user):
        response = auth_client.get(reverse("api:me"))
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == verified_user.username

    def test_me_unauthenticated(self, client):
        response = client.get(reverse("api:me"))
        assert response.status_code == 401


@pytest.mark.django_db
class TestStepUpApi:
    def test_step_up_begin(self, auth_client):
        response = auth_client.post(
            reverse("api:step_up_begin"),
            data=json.dumps({"action": "manage_mfa", "next": "/security/"}),
            content_type="application/json",
        )
        assert response.status_code == 200
        assert "token" in response.json()

    def test_step_up_verify_password(self, auth_client, verified_user):
        begin = auth_client.post(
            reverse("api:step_up_begin"),
            data=json.dumps({"action": "manage_mfa", "next": "/security/"}),
            content_type="application/json",
        )
        token = begin.json()["token"]
        response = auth_client.post(
            reverse("api:step_up_verify"),
            data=json.dumps({
                "action": "manage_mfa",
                "next": "/security/",
                "token": token,
                "password": "CorrectHorse123!",
            }),
            content_type="application/json",
        )
        assert response.status_code == 200


@pytest.mark.django_db
class TestSessionsApi:
    def test_list_sessions(self, auth_client):
        response = auth_client.get(reverse("api:sessions"))
        assert response.status_code == 200
        data = response.json()
        assert "sessions" in data
        assert "page" in data
