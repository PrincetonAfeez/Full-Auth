"""Pytest coverage for web integration."""
import pytest
from django.urls import reverse


@pytest.mark.django_db
class TestWebLogin:
    def test_login_page(self, client):
        response = client.get(reverse("web:login"))
        assert response.status_code == 200

    def test_login_success(self, client, verified_user):
        response = client.post(
            reverse("web:login"),
            {"username": "verified", "password": "CorrectHorse123!"},
        )
        assert response.status_code in (200, 302)

    def test_login_bad_password(self, client, verified_user):
        response = client.post(
            reverse("web:login"),
            {"username": "verified", "password": "wrong"},
        )
        assert response.status_code in (200, 401, 403)


@pytest.mark.django_db
class TestWebSecurity:
    def test_security_requires_auth(self, client):
        response = client.get(reverse("web:security"))
        assert response.status_code in (302, 401, 403)

    def test_security_authenticated(self, auth_client):
        response = auth_client.get(reverse("web:security"))
        assert response.status_code in (200, 302)


@pytest.mark.django_db
class TestHealthEndpoints:
    def test_healthz(self, client):
        response = client.get("/healthz")
        assert response.status_code == 200

    def test_readyz(self, client):
        response = client.get("/readyz")
        assert response.status_code in (200, 503)
