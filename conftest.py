"""Shared pytest fixtures for the Full Auth test suite."""
import json
import os

# Must be set before Django loads settings (pytest uses MD5 hasher + disables HIBP).
os.environ.setdefault("FULL_AUTH_TESTING", "1")

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from accounts.models import EmailAddress
from security_policies.services import get_effective_policy, get_policy
from sessions.models import ActiveSession, hash_session_key

User = get_user_model()


@pytest.fixture
def user_factory(db):
    def _factory(
        username="user",
        email=None,
        password="CorrectHorse123!",
        *,
        status=User.Status.ACTIVE,
        email_verified=True,
        is_superuser=False,
        is_staff=False,
        force_strong_mfa=False,
    ):
        verified_at = timezone.now() if email_verified else None
        user = User.objects.create_user(
            username=username,
            email=email or f"{username}@example.test",
            password=password,
            status=status,
            is_superuser=is_superuser,
            is_staff=is_staff,
            force_strong_mfa=force_strong_mfa,
            email_verified_at=verified_at,
        )
        if email_verified:
            EmailAddress.objects.create(
                user=user, email=user.email, is_primary=True, verified_at=verified_at
            )
        return user

    return _factory


@pytest.fixture
def verified_user(user_factory):
    return user_factory("verified")


@pytest.fixture
def superuser(user_factory):
    return user_factory("super", is_superuser=True, is_staff=True)


@pytest.fixture
def auth_client(db, verified_user):
    """Client with force_login + valid ActiveSession (middleware-safe)."""
    client = Client()
    client.force_login(verified_user)
    policy = get_effective_policy(verified_user)
    now = timezone.now()
    ActiveSession.objects.update_or_create(
        session_key_hash=hash_session_key(client.session.session_key),
        defaults={
            "user": verified_user,
            "expires_idle_at": now + timezone.timedelta(minutes=policy.idle_timeout_minutes),
            "expires_absolute_at": now + timezone.timedelta(hours=policy.absolute_timeout_hours),
            "security_stamp": verified_user.security_stamp,
            "policy_version": policy.policy_version,
            "revoked_at": None,
        },
    )
    return client


@pytest.fixture
def recent_auth_client(auth_client):
    """Authenticated client with fresh recent-auth timestamps."""
    session = auth_client.session
    now = timezone.now().isoformat()
    session["recent_auth_at"] = now
    session["recent_auth_at:default"] = now
    session["recent_auth_at:manage_mfa"] = now
    session["recent_auth_at:change_password"] = now
    session["recent_auth_at:change_email"] = now
    session["recent_auth_at:revoke_session"] = now
    session["recent_auth_at:regenerate_backup_codes"] = now
    session["recent_auth_at:disable_mfa"] = now
    session["recent_auth_at:export_data"] = now
    session.save()
    return auth_client


@pytest.fixture
def superuser_client(db, superuser):
    """Client with force_login + valid ActiveSession for a superuser."""
    client = Client()
    client.force_login(superuser)
    policy = get_effective_policy(superuser)
    now = timezone.now()
    ActiveSession.objects.update_or_create(
        session_key_hash=hash_session_key(client.session.session_key),
        defaults={
            "user": superuser,
            "expires_idle_at": now + timezone.timedelta(minutes=policy.idle_timeout_minutes),
            "expires_absolute_at": now + timezone.timedelta(hours=policy.absolute_timeout_hours),
            "security_stamp": superuser.security_stamp,
            "policy_version": policy.policy_version,
            "revoked_at": None,
        },
    )
    return client


@pytest.fixture
def api_json():
    def _post(client, url_name, payload=None, **url_kwargs):
        return client.post(
            reverse(url_name, kwargs=url_kwargs),
            data=json.dumps(payload or {}),
            content_type="application/json",
        )

    def _get(client, url_name, **url_kwargs):
        return client.get(reverse(url_name, kwargs=url_kwargs))

    return type("ApiJson", (), {"post": _post, "get": _get})()


@pytest.fixture(autouse=True)
def _clear_cache(db):
    from django.core.cache import cache

    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def global_policy(db):
    return get_policy()
