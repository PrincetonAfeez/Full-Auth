"""
Recent-auth / step-up (spec 16). Recent-auth is a distinct, re-proven fact -- being
logged in, even recently, is never sufficient. Scope is policy-configurable:

* global      -> one timestamp per session greenlights all sensitive actions in the window.
* per_action  -> each sensitive action class must be freshly re-proven.
"""
from datetime import timezone as dt_timezone
from functools import wraps
from urllib.parse import urlencode

from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme

from security_policies.services import get_effective_policy

STEP_UP_SESSION_KEY = "step_up_challenge"

# Actions that may be satisfied via step-up (must match @recent_auth_required / api_recent_auth_error).
STEP_UP_ALLOWED_ACTIONS = frozenset(
    {
        "default",
        "login",
        "change_password",
        "change_email",
        "regenerate_backup_codes",
        "manage_mfa",
        "disable_mfa",
        "revoke_session",
        "trust_device",
        "revoke_trusted_device",
        "export_data",
        "admin_revoke_sessions",
        "deactivate_user",
        "erase_user",
        "org_lifecycle",
        "security_policy",
        "org_membership",
        "assign_role",
    }
)


def normalize_step_up_action(action: str) -> str | None:
    return action if action in STEP_UP_ALLOWED_ACTIONS else None


def safe_next_url(request, url: str | None, *, default_name: str = "web:dashboard") -> str:
    """Return url when same-host safe; otherwise the named default route."""
    if url and url_has_allowed_host_and_scheme(
        url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return url
    return reverse(default_name)


def bind_step_up_challenge(request, *, action: str, next_url: str) -> str | None:
    """Bind the step-up page to a specific action and destination (server-side). Returns the token."""
    import secrets

    normalized = normalize_step_up_action(action)
    if normalized is None:
        return None
    safe_next = safe_next_url(request, next_url)
    token = secrets.token_urlsafe(16)
    request.session[STEP_UP_SESSION_KEY] = {
        "action": normalized,
        "next": safe_next,
        "token": token,
    }
    return token


def peek_step_up_challenge(request) -> dict | None:
    return request.session.get(STEP_UP_SESSION_KEY)


def consume_step_up_challenge(request, *, action: str, next_url: str, token: str) -> bool:
    """Validate and clear a bound step-up challenge before marking recent-auth."""
    challenge = request.session.pop(STEP_UP_SESSION_KEY, None)
    if not challenge:
        return False
    normalized = normalize_step_up_action(action)
    if normalized is None or challenge.get("action") != normalized:
        return False
    if challenge.get("next") != safe_next_url(request, next_url):
        return False
    if not token or challenge.get("token") != token:
        return False
    return True


def _session_key(action: str, scope: str) -> str:
    if scope == "per_action":
        return f"recent_auth_at:{action}"
    return "recent_auth_at"


def mark_recent_auth(request, action: str = "default") -> None:
    now_iso = timezone.now().isoformat()
    # Always set the global key; also set the per-action key so either scope is satisfied.
    request.session["recent_auth_at"] = now_iso
    request.session[f"recent_auth_at:{action}"] = now_iso


def has_recent_auth(request, action: str = "default") -> bool:
    policy = get_effective_policy(getattr(request, "user", None))
    scope = policy.recent_auth_scope
    value = request.session.get(_session_key(action, scope))
    if not value:
        return False
    try:
        seen_at = timezone.datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return False
    if timezone.is_naive(seen_at):
        seen_at = timezone.make_aware(seen_at, dt_timezone.utc)
    window = timezone.timedelta(minutes=policy.recent_auth_window_minutes)
    return timezone.now() - seen_at <= window


def recent_auth_required(action: str = "default"):
    """Web decorator: bounce to the step-up page (preserving ?next) when stale."""

    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            if not has_recent_auth(request, action):
                next_url = request.get_full_path()
                bind_step_up_challenge(request, action=action, next_url=next_url)
                query = urlencode({"next": next_url, "action": action})
                return redirect(f"{reverse('web:step_up')}?{query}")
            return view(request, *args, **kwargs)

        return wrapper

    return decorator


def api_recent_auth_error(request, action: str = "default"):
    """API guard: returns a 403 recent_auth_required envelope, or None if satisfied."""
    if has_recent_auth(request, action):
        return None
    step_up_query = urlencode({"next": request.get_full_path(), "action": action})
    return JsonResponse(
        {
            "error": {
                "code": "recent_auth_required",
                "message": "Re-authentication is required for this action.",
                "fields": {
                    "action": action,
                    "step_up_url": f"{reverse('web:step_up')}?{step_up_query}",
                    "step_up_begin": reverse("api:step_up_begin"),
                },
                "request_id": getattr(request, "request_id", ""),
            }
        },
        status=403,
    )
