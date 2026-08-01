"""Per-request session enforcement, security headers, and device cookies."""
from datetime import timezone as dt_timezone

from django.conf import settings
from django.contrib.auth import logout
from django.http import JsonResponse
from django.shortcuts import redirect
from django.utils import timezone

from security_policies.services import get_effective_policy

from .models import ActiveSession, hash_session_key


class SecurityEnforcementMiddleware:
    """
    Re-derive session validity from authoritative storage on every request.
    The session cookie is treated as a pointer, not as security truth.

    Fail-closed: if the authoritative ActiveSession record cannot be found or
    trusted, the request is denied rather than allowed.
    """

    BYPASS_PREFIXES = ("/admin/login/", "/healthz", "/readyz", "/metrics", "/internal/", "/static/")
    # Routes permitted while the session is in the intermediate awaiting-2FA state.
    AWAITING_2FA_ALLOWED = (
        "/login/2fa", "/login/mfa", "/logout",
        "/api/v1/auth/2fa", "/api/v1/auth/logout", "/api/v1/auth/status/",
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith(self.BYPASS_PREFIXES):
            return self.get_response(request)
        denial = self._enforce(request)
        response = denial if denial is not None else self.get_response(request)
        self._apply_security_headers(request, response)
        self._ensure_device_cookie(request, response)
        return response

    def _apply_security_headers(self, request, response):
        if "Cache-Control" not in response:
            response["Cache-Control"] = "no-store"
        response.setdefault("Content-Security-Policy", settings.CONTENT_SECURITY_POLICY)
        response.setdefault("Referrer-Policy", getattr(settings, "SECURE_REFERRER_POLICY", "same-origin"))

    def _ensure_device_cookie(self, request, response):
        # Opaque, long-lived per-device id used as the trusted-device fingerprint seed. Not a
        # secret; it only strengthens the device signal beyond a shared User-Agent hash.
        from sessions.services import DEVICE_COOKIE

        if request.COOKIES.get(DEVICE_COOKIE):
            return
        import secrets

        response.set_cookie(
            DEVICE_COOKIE, secrets.token_urlsafe(24), max_age=60 * 60 * 24 * 730,
            httponly=True, samesite="Lax", secure=settings.SESSION_COOKIE_SECURE,
        )

    def _is_api(self, request):
        return request.path.startswith("/api/")

    def _deny(self, request, *, code, detail, status, redirect_to="web:login"):
        if self._is_api(request):
            return JsonResponse(
                {"error": {"code": code, "message": detail, "fields": {}, "request_id": getattr(request, "request_id", "")}},
                status=status,
            )
        return redirect(redirect_to)

    def _awaiting_expired(self, request):
        started = request.session.get("awaiting_2fa_started_at")
        if not started:
            return True
        try:
            started_at = timezone.datetime.fromisoformat(started)
        except (ValueError, TypeError):
            return True
        if timezone.is_naive(started_at):
            started_at = timezone.make_aware(started_at, dt_timezone.utc)
        ttl = timezone.timedelta(minutes=settings.AWAITING_2FA_TTL_MINUTES)
        return timezone.now() - started_at > ttl

    def _enforce(self, request):
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            if request.session.get("awaiting_2fa_user_id"):
                # Intermediate state expired while abandoned -> clear and restart at password step.
                if self._awaiting_expired(request):
                    from accounts.services import abandon_pending_2fa

                    abandon_pending_2fa(request, reason="expired")
                    return None
                if request.path.startswith(self.AWAITING_2FA_ALLOWED):
                    return None
                return self._deny(
                    request, code="awaiting_2fa", detail="Second factor required.", status=401,
                    redirect_to="web:mfa_challenge",
                )
            return None

        if user.status == user.Status.LOCKED:
            logout(request)
            return self._deny(request, code="account_locked", detail="Account is locked.", status=423)

        if not user.is_security_active:
            logout(request)
            return self._deny(request, code="unauthenticated", detail="Session is no longer valid.", status=401)

        if not request.session.session_key:
            logout(request)
            return self._deny(request, code="unauthenticated", detail="Session is no longer valid.", status=401)

        policy = get_effective_policy(user)
        session_hash = hash_session_key(request.session.session_key)
        from sessions.cache import get_cached_session_id, invalidate_session_cache, set_cached_session_id

        active_session = None
        cached_id = get_cached_session_id(session_hash)
        if cached_id is not None:
            active_session = ActiveSession.objects.filter(pk=cached_id, user=user, session_key_hash=session_hash).first()
            if active_session is None:
                invalidate_session_cache(session_hash)
        if active_session is None:
            active_session = ActiveSession.objects.filter(session_key_hash=session_hash, user=user).first()
            if active_session is not None:
                set_cached_session_id(session_hash, active_session.pk)

        # Fail-closed: a missing authoritative record terminates the session (spec 7a step 2).
        if active_session is None:
            invalidate_session_cache(session_hash)
            logout(request)
            return self._deny(request, code="unauthenticated", detail="Session is no longer valid.", status=401)

        if active_session.revoked_at is not None:
            invalidate_session_cache(session_hash)
            logout(request)
            return self._deny(request, code="session_revoked", detail="Session was revoked.", status=401)

        now = timezone.now()
        if active_session.expires_idle_at <= now or active_session.expires_absolute_at <= now:
            active_session.revoked_at = now
            active_session.save(update_fields=["revoked_at"])
            invalidate_session_cache(session_hash)
            logout(request)
            return self._deny(request, code="session_expired", detail="Session expired.", status=401)

        if active_session.security_stamp != user.security_stamp or active_session.policy_version != policy.policy_version:
            invalidate_session_cache(session_hash)
            logout(request)
            return self._deny(request, code="reauthentication_required", detail="Please sign in again.", status=401)

        # Annotate recent-auth freshness for view/route step-up guards (fresh, never cached in
        # session). Scope-aware, matching the actual guard used by views.
        from accounts.recent_auth import has_recent_auth

        # Global recent-auth only; per-action guards must call has_recent_auth(request, action).
        request.recent_auth_ok = has_recent_auth(request, "default")

        # Write-throttle last_seen_at: only persist when it has actually moved by more than
        # LAST_SEEN_WRITE_THROTTLE_SECONDS, to avoid a DB write on every single request.
        threshold = timezone.timedelta(seconds=settings.LAST_SEEN_WRITE_THROTTLE_SECONDS)
        if now - active_session.last_seen_at >= threshold:
            active_session.extend_idle(policy)
            active_session.save(update_fields=["last_seen_at", "expires_idle_at"])
        return None
