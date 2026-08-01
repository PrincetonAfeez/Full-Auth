"""Pytest coverage for web console."""
import pytest
from django.urls import reverse


@pytest.mark.django_db
class TestConsoleAccess:
    def test_superuser_can_access_console(self, superuser_client):
        response = superuser_client.get(reverse("web:console"))
        assert response.status_code == 200

    def test_regular_user_denied(self, auth_client):
        response = auth_client.get(reverse("web:console"))
        assert response.status_code == 403


@pytest.mark.django_db
class TestConsoleSections:
    def test_console_users(self, superuser_client):
        response = superuser_client.get(reverse("web:console_users"))
        assert response.status_code == 200

    def test_console_orgs(self, superuser_client):
        response = superuser_client.get(reverse("web:console_orgs"))
        assert response.status_code == 200

    def test_console_audit(self, superuser_client):
        response = superuser_client.get(reverse("web:console_audit"))
        assert response.status_code == 200

    def test_console_risk(self, superuser_client):
        response = superuser_client.get(reverse("web:console_risk"))
        assert response.status_code == 200

    def test_htmx_returns_partial(self, superuser_client):
        response = superuser_client.get(reverse("web:console_users"), HTTP_HX_REQUEST="true")
        assert response.status_code == 200
        assert "console/_users.html" in [t.name for t in response.templates]
