"""HTTP views for the api app."""
import json
from functools import wraps

from django.contrib.auth import get_user_model, logout
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_GET, require_POST

from accounts.recent_auth import (
    api_recent_auth_error,
    bind_step_up_challenge,
    consume_step_up_challenge,
    has_recent_auth,
    mark_recent_auth,
    normalize_step_up_action,
    peek_step_up_challenge,
    safe_next_url,
)
from accounts.services import (
    AccountInactive,
    StrongFactorRequired,
    abandon_pending_2fa,
    authenticate_password_step,
    complete_login,
    needs_strong_factor_enrollment,
    pending_2fa_user,
    register_pending_2fa_attempt,
)
from accounts.step_up import (
    check_step_up_allowed,
    clear_step_up_attempts,
    record_step_up_failure,
    record_step_up_success,
    register_step_up_attempt,
    verify_step_up_credential,
)
from accounts.throttle import AccountThrottled, client_ip, rate_limit_request
from mfa.models import MFADevice
from mfa.services import (
    begin_email_otp,
    clear_totp_enroll_attempts,
    generate_backup_codes,
    register_totp_enroll_attempt,
    verify_email_otp,
    verify_login_factor,
    verify_totp,
)
from organizations.services import can_manage_user
from passwords.services import complete_password_reset, request_password_reset, verify_email
from sessions.models import ActiveSession
from sessions.services import revoke_all_user_sessions, revoke_session


def _error(request, code: str, message: str, status: int, fields: dict | None = None) -> JsonResponse:
    response = JsonResponse(
        {"error": {"code": code, "message": message, "fields": fields or {}, "request_id": getattr(request, "request_id", "")}},
        status=status,
    )
    if status == 429:
        retry_after = (fields or {}).get("retry_after", 60)
        response["Retry-After"] = str(retry_after)
    return response


def _json_body(request) -> dict:
    if request.content_type and "application/json" in request.content_type:
        try:
            return json.loads(request.body or b"{}")
        except ValueError:
            return {}
    return request.POST.dict()


def login_required(view):
    """API auth gate: returns a 401 error envelope instead of a 302 redirect (web/API parity)."""

    @wraps(view)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return _error(request, "unauthenticated", "Authentication required.", 401)
        return view(request, *args, **kwargs)

    return wrapper


def csrf_failure(request, reason=""):
    """CSRF_FAILURE_VIEW: JSON envelope for API paths, Django's default page elsewhere."""
    if request.path.startswith("/api/"):
        return _error(request, "csrf_failed", "CSRF verification failed.", 403, {"reason": reason})
    from django.views.csrf import csrf_failure as default_csrf_failure

    return default_csrf_failure(request, reason=reason)


# --- auth ---------------------------------------------------------------------

@require_GET
@ensure_csrf_cookie
def auth_status(request):
    # GET this first to obtain the CSRF cookie, then send its value as the X-CSRFToken
    # header on subsequent writes (non-browser clients bootstrap here).
    if request.user.is_authenticated:
        return JsonResponse({"authenticated": True, "awaiting_2fa": False, "user_id": request.user.pk})
    awaiting = bool(request.session.get("awaiting_2fa_user_id"))
    return JsonResponse({"authenticated": False, "awaiting_2fa": awaiting})


@require_POST
def auth_login(request):
    body = _json_body(request)
    from accounts.services import EmailVerificationRequired

    try:
        user = authenticate_password_step(
            request=request, username=body.get("username", ""), password=body.get("password", "")
        )
    except AccountThrottled as exc:
        return _error(request, "throttled", "Too many attempts.", 429, {"retry_after": exc.retry_after})
    except EmailVerificationRequired:
        return _error(request, "email_verification_required", "Verify your email before signing in.", 403)
    if not user:
        return _error(request, "invalid_credentials", "The username or password is invalid.", 401)
    if request.session.get("awaiting_2fa_user_id"):
        return _error(request, "awaiting_2fa", "Additional verification is required.", 401,
                      {"enrollment_required": needs_strong_factor_enrollment(user)})
    return JsonResponse({"ok": True, "authenticated": True})


@require_POST
def auth_2fa_verify(request):
    user = pending_2fa_user(request)
    if not user:
        return _error(request, "unauthenticated", "No pending second-factor challenge.", 401)
    body = _json_body(request)
    method = body.get("method", "totp")
    code = body.get("code", "")
    from accounts.services import AccountInactive, allowed_login_methods

    allowed = allowed_login_methods(user)

    if method == "email_otp_send":
        if "email_otp" not in allowed:
            return _error(request, "factor_not_allowed", "Email OTP is not available for this account.", 403)
        try:
            challenge, _ = begin_email_otp(user=user, request=request, deliver=True)
        except Exception as exc:  # noqa: BLE001
            return _error(request, "throttled", str(exc), 429)
        request.session["email_otp_challenge_id"] = challenge.pk
        return JsonResponse({"ok": True, "sent": True})

    ok = method in allowed and verify_login_factor(request=request, user=user, method=method, code=code)
    if ok:
        try:
            complete_login(request=request, user=user, event_type="auth.login.completed_mfa")
        except StrongFactorRequired:
            return _error(request, "enrollment_required", "Enroll a strong factor to continue.", 403)
        except AccountInactive:
            abandon_pending_2fa(request, user=user, reason="deactivated")
            return _error(request, "account_inactive", "This account is no longer active.", 423)
        request.session.pop("email_otp_challenge_id", None)
        return JsonResponse({"ok": True, "authenticated": True})

    if register_pending_2fa_attempt(request):
        abandon_pending_2fa(request, user=user, reason="attempt_cap")
        return _error(request, "awaiting_2fa_expired", "Too many invalid codes.", 401)
    return _error(request, "invalid_code", "The verification code is invalid.", 401)


@require_POST
def auth_logout(request):
    abandon_pending_2fa(request)
    logout(request)
    return JsonResponse({"ok": True})


@require_POST
def password_reset_request_view(request):
    try:
        rate_limit_request("password_reset", ip=client_ip(request), limit=5, window_seconds=3600)
    except AccountThrottled as exc:
        return _error(request, "throttled", "Too many requests.", 429, {"retry_after": exc.retry_after})
    body = _json_body(request)
    email = body.get("email", "").lower()
    user = get_user_model().objects.filter(email=email).first()
    if user and user.email_verified:
        request_password_reset(user=user, request=request)
    # Enumeration-safe: identical response regardless of account existence.
    return JsonResponse({"ok": True})


@require_POST
def password_reset_complete_view(request):
    body = _json_body(request)
    try:
        ok = complete_password_reset(token=body.get("token", ""), new_password=body.get("password", ""))
    except ValueError as exc:
        return _error(request, "invalid_password", str(exc), 400)
    if not ok:
        return _error(request, "stale_challenge", "This reset link is invalid or has expired.", 409)
    return JsonResponse({"ok": True})


@require_POST
def email_verification_complete_view(request):
    body = _json_body(request)
    from passwords.services import EmailAlreadyInUse

    try:
        ok = verify_email(token=body.get("token", ""))
    except EmailAlreadyInUse as exc:
        return _error(request, "conflict", str(exc), 409)
    if not ok:
        return _error(request, "stale_challenge", "This verification link is invalid or has expired.", 409)
    return JsonResponse({"ok": True})


# --- me -----------------------------------------------------------------------

@require_GET
@login_required
def me(request):
    memberships = [
        {"organization": m.organization.slug, "role": m.role}
        for m in request.user.memberships.select_related("organization").filter(status="active")
    ]
    return JsonResponse(
        {
            "id": request.user.pk,
            "username": request.user.username,
            "email": request.user.email,
            "email_verified": request.user.email_verified,
            "memberships": memberships,
        }
    )


@require_GET
@login_required
def me_security(request):
    from security_policies.services import get_effective_policy

    factors = [
        {"id": f.pk, "type": f.type, "name": f.name, "enabled": f.enabled}
        for f in MFADevice.objects.filter(user=request.user)
    ]
    policy = get_effective_policy(request.user)
    return JsonResponse(
        {
            "factors": factors,
            "recent_auth": {
                "scope": policy.recent_auth_scope,
                "default_ok": has_recent_auth(request, "default"),
            },
            "recent_auth_ok": has_recent_auth(request, "default"),
        }
    )


@require_GET
@login_required
def sessions(request):
    qs = ActiveSession.objects.filter(user=request.user).order_by("-last_seen_at")
    rows, page = _page(request, qs)
    return JsonResponse(
        {
            "sessions": [
                {
                    "id": row.pk,
                    "created_at": row.created_at.isoformat(),
                    "last_seen_at": row.last_seen_at.isoformat(),
                    "expires_idle_at": row.expires_idle_at.isoformat(),
                    "expires_absolute_at": row.expires_absolute_at.isoformat(),
                    "revoked": row.revoked_at is not None,
                }
                for row in rows
            ],
            "page": page,
        }
    )


@require_POST
@login_required
def revoke_session_view(request, session_id: int):
    guard = api_recent_auth_error(request, "revoke_session")
    if guard:
        return guard
    active_session = ActiveSession.objects.filter(pk=session_id, user=request.user).first()
    if not active_session:
        return _error(request, "not_found", "Session not found.", 404)
    revoke_session(actor=request.user, active_session=active_session, request=request)
    return JsonResponse({"ok": True})


@require_POST
@login_required
def regenerate_backup_codes_view(request):
    guard = api_recent_auth_error(request, "regenerate_backup_codes")
    if guard:
        return guard
    codes = generate_backup_codes(user=request.user)
    return JsonResponse({"codes": codes})


@require_POST
@login_required
def totp_enable_view(request):
    """Begin TOTP enrollment: returns the (unconfirmed) device id and provisioning secret."""
    guard = api_recent_auth_error(request, "manage_mfa")
    if guard:
        return guard
    from mfa.services import enable_totp

    MFADevice.objects.filter(user=request.user, type=MFADevice.Type.TOTP, enabled_at__isnull=True).delete()
    device, secret = enable_totp(user=request.user, name="Authenticator")
    return JsonResponse({"device_id": device.pk, "secret": secret})


@require_POST
@login_required
def totp_confirm_view(request):
    """Confirm a TOTP enrollment with a first code, enabling the device."""
    guard = api_recent_auth_error(request, "manage_mfa")
    if guard:
        return guard
    body = _json_body(request)
    device = MFADevice.objects.filter(pk=body.get("device_id"), user=request.user, type=MFADevice.Type.TOTP).first()
    if not device:
        return _error(request, "not_found", "Enrollment not found.", 404)
    if not verify_totp(device=device, code=body.get("code", "")):
        if register_totp_enroll_attempt(request):
            return _error(request, "throttled", "Too many invalid codes.", 429)
        return _error(request, "invalid_code", "That code did not verify.", 400)
    clear_totp_enroll_attempts(request)
    # Mint recovery codes on first-factor enrollment (parity with the web flow) if none exist.
    from mfa.models import BackupCode

    codes = None
    if not BackupCode.objects.filter(user=request.user, used_at__isnull=True).exists():
        codes = generate_backup_codes(user=request.user)
    return JsonResponse({"ok": True, "backup_codes": codes})


@require_POST
@login_required
def email_otp_enable_view(request):
    guard = api_recent_auth_error(request, "manage_mfa")
    if guard:
        return guard
    from mfa.services import enable_email_otp

    try:
        enable_email_otp(user=request.user)
    except ValueError as exc:
        return _error(request, "email_unverified", str(exc), 400)
    return JsonResponse({"ok": True})


@require_POST
@login_required
def disable_factor_view(request, factor_id: int):
    guard = api_recent_auth_error(request, "disable_mfa")
    if guard:
        return guard
    from mfa.services import disable_mfa_device
    from notifications.services import emit_outbox_event
    from security_events.services import record_audit_event

    device = MFADevice.objects.filter(pk=factor_id, user=request.user).first()
    if not device:
        return _error(request, "not_found", "Factor not found.", 404)
    try:
        disable_mfa_device(user=request.user, device=device)
    except ValueError as exc:
        return _error(request, "strong_factor_required", str(exc), 409)
    record_audit_event(
        actor=request.user, target_user=request.user, event_type="mfa.factor.disabled",
        metadata={"factor_id": device.pk, "type": device.type}, request=request,
    )
    emit_outbox_event(
        event_type="mfa.factor.disabled", aggregate_type="user",
        aggregate_id=str(request.user.pk), payload={"user_id": request.user.pk},
    )
    return JsonResponse({"ok": True})


# --- webauthn / passkeys ------------------------------------------------------

def _origin(request) -> str:
    origin = request.META.get("HTTP_ORIGIN")
    if not origin:
        raise ValueError("Origin header required")
    return origin


def _webauthn_client_error(request, exc: Exception):
    import logging

    logging.getLogger(__name__).warning("WebAuthn error: %s", exc, exc_info=exc)
    return _error(request, "webauthn_error", "WebAuthn ceremony failed.", 400)


def _webauthn_login_guard(request, user):
    from accounts.services import allowed_login_methods

    if "webauthn" not in allowed_login_methods(user):
        return _error(request, "factor_not_allowed", "Passkey is not available for this account.", 403)
    return None


@require_POST
@login_required
def webauthn_register_options(request):
    guard = api_recent_auth_error(request, "manage_mfa")
    if guard:
        return guard
    from mfa import webauthn as wa

    try:
        options_json = wa.begin_registration(user=request.user, origin=_origin(request))
    except ValueError as exc:
        return _error(request, "webauthn_error", str(exc), 400)
    return JsonResponse(json.loads(options_json))


@require_POST
@login_required
def webauthn_register_verify(request):
    guard = api_recent_auth_error(request, "manage_mfa")
    if guard:
        return guard
    from mfa import webauthn as wa

    body = _json_body(request)
    try:
        wa.complete_registration(
            user=request.user, credential=body.get("credential"),
            origin=_origin(request), challenge_b64=body.get("challenge", ""),
        )
    except Exception as exc:  # noqa: BLE001
        return _webauthn_client_error(request, exc)
    return JsonResponse({"ok": True})


@require_POST
def auth_webauthn_register_options(request):
    user = pending_2fa_user(request)
    if not user:
        return _error(request, "unauthenticated", "No pending second-factor challenge.", 401)
    if not needs_strong_factor_enrollment(user):
        return _error(request, "enrollment_not_required", "Passkey enrollment is not allowed during login.", 403)
    from mfa import webauthn as wa

    try:
        options_json = wa.begin_registration(user=user, origin=_origin(request))
    except ValueError as exc:
        return _error(request, "webauthn_error", str(exc), 400)
    return JsonResponse(json.loads(options_json))


@require_POST
def auth_webauthn_register_verify(request):
    user = pending_2fa_user(request)
    if not user:
        return _error(request, "unauthenticated", "No pending second-factor challenge.", 401)
    if not needs_strong_factor_enrollment(user):
        return _error(request, "enrollment_not_required", "Passkey enrollment is not allowed during login.", 403)
    from mfa import webauthn as wa

    body = _json_body(request)
    try:
        wa.complete_registration(
            user=user, credential=body.get("credential"),
            origin=_origin(request), challenge_b64=body.get("challenge", ""),
        )
    except Exception as exc:  # noqa: BLE001
        return _webauthn_client_error(request, exc)
    try:
        complete_login(request=request, user=user, event_type="auth.login.completed_mfa_enrolled")
    except StrongFactorRequired:
        return JsonResponse({"ok": True, "enrolled": True, "authenticated": False})
    return JsonResponse({"ok": True, "enrolled": True, "authenticated": True})


@require_POST
def webauthn_assertion_options(request):
    from mfa import webauthn as wa

    user = pending_2fa_user(request)
    if not user:
        return _error(request, "unauthenticated", "No user context for assertion.", 401)
    denied = _webauthn_login_guard(request, user)
    if denied:
        return denied
    try:
        options_json = wa.begin_assertion(user=user, origin=_origin(request))
    except ValueError as exc:
        return _error(request, "webauthn_error", str(exc), 400)
    return JsonResponse(json.loads(options_json))


@require_POST
def webauthn_assertion_verify(request):
    from mfa import webauthn as wa

    user = pending_2fa_user(request)
    if not user:
        return _error(request, "unauthenticated", "No pending second-factor challenge.", 401)
    denied = _webauthn_login_guard(request, user)
    if denied:
        return denied
    body = _json_body(request)
    try:
        ok = wa.complete_assertion(
            user=user, credential=body.get("credential"),
            origin=_origin(request), challenge_b64=body.get("challenge", ""),
        )
    except Exception as exc:  # noqa: BLE001
        if register_pending_2fa_attempt(request):
            abandon_pending_2fa(request, user=user, reason="attempt_cap")
            return _error(request, "awaiting_2fa_expired", "Too many invalid codes.", 401)
        return _webauthn_client_error(request, exc)
    if not ok:
        if register_pending_2fa_attempt(request):
            abandon_pending_2fa(request, user=user, reason="attempt_cap")
            return _error(request, "awaiting_2fa_expired", "Too many invalid codes.", 401)
        return _error(request, "invalid_code", "Assertion failed.", 401)
    try:
        complete_login(request=request, user=user, event_type="auth.login.completed_webauthn")
    except StrongFactorRequired:
        return _error(request, "enrollment_required", "Enroll a strong factor to continue.", 403)
    except AccountInactive:
        abandon_pending_2fa(request, user=user, reason="deactivated")
        return _error(request, "account_inactive", "This account is no longer active.", 423)
    return JsonResponse({"ok": True, "authenticated": True})


@require_POST
@login_required
def step_up_webauthn_options(request):
    from mfa import webauthn as wa

    if not peek_step_up_challenge(request):
        return _error(request, "invalid_step_up", "Step-up challenge invalid or expired.", 403)
    try:
        options_json = wa.begin_assertion(user=request.user, origin=_origin(request))
    except ValueError as exc:
        return _error(request, "webauthn_error", str(exc), 400)
    return JsonResponse(json.loads(options_json))


def _step_up_fail_rebind(request, *, action: str, next_url: str) -> None:
    bind_step_up_challenge(request, action=action, next_url=next_url)


@require_POST
@login_required
def step_up_begin(request):
    body = _json_body(request)
    action = body.get("action", "default")
    if normalize_step_up_action(action) is None:
        return _error(request, "invalid_action", "Unknown step-up action.", 400)
    next_url = safe_next_url(request, body.get("next") or request.get_full_path())
    token = bind_step_up_challenge(request, action=action, next_url=next_url)
    if not token:
        return _error(request, "invalid_action", "Unknown step-up action.", 400)
    return JsonResponse({"ok": True, "action": action, "next": next_url, "token": token})


@require_POST
@login_required
def step_up_verify(request):
    body = _json_body(request)
    action = body.get("action", "default")
    if normalize_step_up_action(action) is None:
        return _error(request, "invalid_action", "Unknown step-up action.", 400)
    next_url = safe_next_url(request, body.get("next", ""))
    token = body.get("token", "")
    try:
        check_step_up_allowed(request=request, user=request.user)
    except AccountThrottled:
        _step_up_fail_rebind(request, action=action, next_url=next_url)
        return _error(request, "throttled", "Too many step-up attempts.", 429)
    if not consume_step_up_challenge(request, action=action, next_url=next_url, token=token):
        return _error(request, "invalid_step_up", "Step-up challenge invalid or expired.", 403)
    if verify_step_up_credential(
        user=request.user,
        password=body.get("password", ""),
        totp_code=body.get("totp_code", ""),
        backup_code=body.get("backup_code", ""),
    ):
        mark_recent_auth(request, action)
        clear_step_up_attempts(request)
        record_step_up_success(request=request, user=request.user)
        return JsonResponse({"ok": True, "next": next_url})
    record_step_up_failure(request=request, user=request.user)
    if register_step_up_attempt(request):
        _step_up_fail_rebind(request, action=action, next_url=next_url)
        return _error(request, "throttled", "Too many step-up attempts.", 429)
    _step_up_fail_rebind(request, action=action, next_url=next_url)
    return _error(request, "invalid_code", "Could not verify your identity.", 401)


@require_POST
@login_required
def step_up_webauthn_verify(request):
    from mfa import webauthn as wa

    body = _json_body(request)
    action = body.get("action", "default")
    if normalize_step_up_action(action) is None:
        return _error(request, "invalid_action", "Unknown step-up action.", 400)
    next_url = safe_next_url(request, body.get("next", ""))
    token = body.get("token", "")
    try:
        check_step_up_allowed(request=request, user=request.user)
    except AccountThrottled:
        _step_up_fail_rebind(request, action=action, next_url=next_url)
        return _error(request, "throttled", "Too many step-up attempts.", 429)
    if not consume_step_up_challenge(request, action=action, next_url=next_url, token=token):
        return _error(request, "invalid_step_up", "Step-up challenge invalid or expired.", 403)
    try:
        ok = wa.complete_assertion(
            user=request.user, credential=body.get("credential"),
            origin=_origin(request), challenge_b64=body.get("challenge", ""),
        )
    except Exception as exc:  # noqa: BLE001
        record_step_up_failure(request=request, user=request.user)
        if register_step_up_attempt(request):
            _step_up_fail_rebind(request, action=action, next_url=next_url)
            return _error(request, "throttled", "Too many step-up attempts.", 429)
        _step_up_fail_rebind(request, action=action, next_url=next_url)
        return _webauthn_client_error(request, exc)
    if not ok:
        record_step_up_failure(request=request, user=request.user)
        if register_step_up_attempt(request):
            _step_up_fail_rebind(request, action=action, next_url=next_url)
            return _error(request, "throttled", "Too many step-up attempts.", 429)
        _step_up_fail_rebind(request, action=action, next_url=next_url)
        return _error(request, "invalid_code", "Assertion failed.", 401)
    mark_recent_auth(request, action)
    clear_step_up_attempts(request)
    record_step_up_success(request=request, user=request.user)
    return JsonResponse({"ok": True, "next": next_url})


# --- admin --------------------------------------------------------------------

@require_POST
@login_required
def admin_revoke_user_sessions(request, user_id: int):
    guard = api_recent_auth_error(request, "admin_revoke_sessions")
    if guard:
        return guard
    target = get_user_model().objects.filter(pk=user_id).first()
    if not target:
        return _error(request, "not_found", "User not found.", 404)
    if not can_manage_user(request.user, target):
        return _error(request, "forbidden", "Not permitted.", 403)
    count = revoke_all_user_sessions(actor=request.user, user=target, reason="admin_revoke")
    return JsonResponse({"ok": True, "revoked": count})


@require_POST
@login_required
def admin_deactivate_user(request, user_id: int):
    guard = api_recent_auth_error(request, "deactivate_user")
    if guard:
        return guard
    from accounts.services import deactivate_user

    target = get_user_model().objects.filter(pk=user_id).first()
    if not target:
        return _error(request, "not_found", "User not found.", 404)
    try:
        deactivate_user(actor=request.user, user=target, reason=_json_body(request).get("reason", ""))
    except PermissionDenied as exc:
        return _error(request, "forbidden", str(exc), 403)
    return JsonResponse({"ok": True})


@require_POST
@login_required
def admin_erase_user(request, user_id: int):
    guard = api_recent_auth_error(request, "erase_user")
    if guard:
        return guard
    from accounts.services import erase_user

    target = get_user_model().objects.filter(pk=user_id).first()
    if not target:
        return _error(request, "not_found", "User not found.", 404)
    try:
        erase_user(actor=request.user, user=target)
    except PermissionDenied as exc:
        return _error(request, "forbidden", str(exc), 403)
    return JsonResponse({"ok": True})


# --- tenant helpers -----------------------------------------------------------

def _scoped_org_or_error(request, slug: str):
    from organizations.models import Organization
    from organizations.services import verify_tenant_scope

    org = Organization.objects.filter(slug=slug).first()
    if org is None or not verify_tenant_scope(request.user, org):
        return None, _error(request, "not_found", "Organization not found.", 404)
    return org, None


# --- me password / email change -----------------------------------------------

@require_POST
@login_required
def me_password_change(request):
    guard = api_recent_auth_error(request, "change_password")
    if guard:
        return guard
    from passwords.services import change_password

    body = _json_body(request)
    try:
        change_password(
            user=request.user,
            current_password=body.get("current_password", ""),
            new_password=body.get("password", ""),
        )
    except ValueError as exc:
        return _error(request, "invalid_password", str(exc), 400)
    return JsonResponse({"ok": True})


@require_POST
@login_required
def me_email_change(request):
    guard = api_recent_auth_error(request, "change_email")
    if guard:
        return guard
    from passwords.services import EmailAlreadyInUse, request_email_change

    body = _json_body(request)
    try:
        request_email_change(user=request.user, new_email=body.get("email", ""), request=request)
    except EmailAlreadyInUse as exc:
        return _error(request, "conflict", str(exc), 409)
    return JsonResponse({"ok": True})



@require_GET
@login_required
def organization_members(request, slug: str):
    """Tenant-isolated: a non-member gets 404 (existence not revealed) before any row is read."""
    from organizations.models import Organization, OrganizationMembership
    from organizations.services import has_role_at_least, verify_tenant_scope

    org = Organization.objects.filter(slug=slug).first()
    # Defense-in-depth (ADR-0017): scope check before any tenant row is read.
    if org is None or not verify_tenant_scope(request.user, org):
        return _error(request, "not_found", "Organization not found.", 404)
    if org.status != Organization.Status.ACTIVE and not request.user.is_superuser:
        return _error(request, "organization_suspended", "Organization is not active.", 403)
    # The full roster (including owners/admins) is visible to STAFF and above; lower roles
    # only see their own membership.
    if has_role_at_least(request.user, org, OrganizationMembership.Role.STAFF):
        qs = OrganizationMembership.objects.filter(organization=org).select_related("user").order_by("user__username")
    else:
        qs = OrganizationMembership.objects.filter(organization=org, user=request.user).select_related("user")
    rows, page = _page(request, qs)
    members = [{"username": m.user.username, "role": m.role, "status": m.status} for m in rows]
    return JsonResponse({"organization": org.slug, "members": members, "page": page})


# --- trusted devices ---------------------------------------------------------

@require_GET
@login_required
def trusted_devices(request):
    from sessions.models import TrustedDevice

    qs = TrustedDevice.objects.filter(user=request.user).order_by("-trusted_until")
    rows, page = _page(request, qs)
    devices = [
        {"id": d.pk, "name": d.display_name, "trusted_until": d.trusted_until.isoformat(),
         "revoked": d.revoked_at is not None}
        for d in rows
    ]
    return JsonResponse({"trusted_devices": devices, "page": page})


@require_POST
@login_required
def trust_current_device(request):
    guard = api_recent_auth_error(request, "trust_device")
    if guard:
        return guard
    from sessions.services import device_identifier, trust_device

    name = _json_body(request).get("name", "This device")
    device = trust_device(user=request.user, identifier_hash=device_identifier(request), display_name=name)
    return JsonResponse({"ok": True, "id": device.pk})


@require_POST
@login_required
def revoke_trusted_device_view(request, device_id: int):
    guard = api_recent_auth_error(request, "revoke_trusted_device")
    if guard:
        return guard
    from sessions.services import revoke_trusted_device

    if not revoke_trusted_device(actor=request.user, user=request.user, device_id=device_id):
        return _error(request, "not_found", "Trusted device not found.", 404)
    return JsonResponse({"ok": True})


# --- self-service data export ------------------------------------------------

@require_GET
@login_required
def me_export(request):
    guard = api_recent_auth_error(request, "export_data")
    if guard:
        return guard
    from accounts.services import export_user_data

    return JsonResponse(export_user_data(request.user))


# --- notification preferences ------------------------------------------------

@require_GET
@login_required
def notification_preferences(request):
    from notifications.services import get_preferences

    return JsonResponse({"preferences": get_preferences(request.user)})


@require_POST
@login_required
def set_notification_preference(request):
    from notifications.services import set_preference

    body = _json_body(request)
    try:
        set_preference(user=request.user, category=body.get("category", ""), email_enabled=bool(body.get("email_enabled", True)))
    except ValueError as exc:
        return _error(request, "invalid", str(exc), 400)
    return JsonResponse({"ok": True})


# --- admin security console --------------------------------------------------

def _require_platform_admin(request):
    return None if request.user.is_superuser else _error(request, "forbidden", "Platform admin required.", 403)


def _page(request, queryset):
    """Simple ?limit=&offset= pagination (limit 1..200, default 50)."""
    try:
        limit = max(1, min(200, int(request.GET.get("limit", 50))))
        offset = max(0, int(request.GET.get("offset", 0)))
    except (TypeError, ValueError):
        limit, offset = 50, 0
    total = queryset.count()
    return list(queryset[offset : offset + limit]), {"total": total, "limit": limit, "offset": offset}


@require_GET
@login_required
def admin_users(request):
    denied = _require_platform_admin(request)
    if denied:
        return denied
    rows, page = _page(request, get_user_model().objects.order_by("-id").values("id", "username", "email", "status", "is_active"))
    return JsonResponse({"users": rows, "page": page})


@require_GET
@login_required
def admin_audit_events(request):
    denied = _require_platform_admin(request)
    if denied:
        return denied
    from security_events.models import AuditEvent

    qs = AuditEvent.objects.values("id", "event_type", "actor_id", "target_user_id", "timestamp")
    event_type = request.GET.get("event_type")
    if event_type:
        qs = qs.filter(event_type=event_type)
    rows, page = _page(request, qs)
    return JsonResponse({"audit_events": rows, "page": page})


@require_GET
@login_required
def admin_security_events(request):
    denied = _require_platform_admin(request)
    if denied:
        return denied
    from security_events.models import SecurityRiskEvent

    qs = SecurityRiskEvent.objects.values("id", "event_type", "severity", "status", "created_at")
    severity = request.GET.get("severity")
    if severity:
        qs = qs.filter(severity=severity)
    rows, page = _page(request, qs)
    return JsonResponse({"security_events": rows, "page": page})


@require_POST
@login_required
def admin_org_suspend(request, slug: str):
    denied = _require_platform_admin(request)
    if denied:
        return denied
    guard = api_recent_auth_error(request, "org_lifecycle")
    if guard:
        return guard
    from organizations.models import Organization
    from organizations.services import reactivate_organization, suspend_organization

    org = Organization.objects.filter(slug=slug).first()
    if not org:
        return _error(request, "not_found", "Organization not found.", 404)
    action = _json_body(request).get("action", "suspend")
    (reactivate_organization if action == "reactivate" else suspend_organization)(actor=request.user, organization=org)
    return JsonResponse({"ok": True, "status": org.status})


@require_POST
@login_required
def admin_org_close(request, slug: str):
    denied = _require_platform_admin(request)
    if denied:
        return denied
    guard = api_recent_auth_error(request, "org_lifecycle")
    if guard:
        return guard
    from organizations.models import Organization
    from organizations.services import close_organization

    org = Organization.objects.filter(slug=slug).first()
    if not org:
        return _error(request, "not_found", "Organization not found.", 404)
    close_organization(actor=request.user, organization=org)
    return JsonResponse({"ok": True, "status": org.status})


@require_POST
@login_required
def org_update_policy(request, slug: str):
    """Org admin edits their organization's security policy (creating one if absent)."""
    guard = api_recent_auth_error(request, "security_policy")
    if guard:
        return guard
    from organizations.models import Organization
    from security_policies.services import update_org_policy

    org, denied = _scoped_org_or_error(request, slug)
    if denied:
        return denied
    try:
        policy = update_org_policy(actor=request.user, organization=org, changes=_json_body(request))
    except PermissionDenied as exc:
        return _error(request, "forbidden", str(exc), 403)
    except ValueError as exc:
        return _error(request, "invalid", str(exc), 400)
    return JsonResponse({"ok": True, "policy_version": policy.policy_version})


# --- email verification resend -----------------------------------------------

@require_POST
def email_verification_request_view(request):
    """Enumeration-safe, throttled resend of a verification link (spec: recover from a lost link)."""
    try:
        rate_limit_request("email_verification", ip=client_ip(request), limit=5, window_seconds=3600)
    except AccountThrottled as exc:
        return _error(request, "throttled", "Too many requests.", 429, {"retry_after": exc.retry_after})
    from passwords.services import request_email_verification

    email = _json_body(request).get("email", "").lower()
    user = get_user_model().objects.filter(email=email).first()
    if user and not user.email_verified:
        request_email_verification(user=user)
    return JsonResponse({"ok": True})


# --- organization membership management --------------------------------------

@require_POST
@login_required
def org_invite(request, slug: str):
    guard = api_recent_auth_error(request, "org_membership")
    if guard:
        return guard
    from notifications.services import emit_outbox_event
    from organizations.models import Organization
    from organizations.services import invite_user

    org, denied = _scoped_org_or_error(request, slug)
    if denied:
        return denied
    body = _json_body(request)
    try:
        invitation, token = invite_user(
            actor=request.user, organization=org, email=body.get("email", ""), role=body.get("role", "member")
        )
    except PermissionDenied as exc:
        return _error(request, "forbidden", str(exc), 403)
    except (ValueError, KeyError) as exc:
        return _error(request, "invalid", str(exc), 400)
    # Deliver the invitation link via the outbox (token is transient, scrubbed after send).
    emit_outbox_event(
        event_type="organization.invitation.created", aggregate_type="organization",
        aggregate_id=str(org.pk),
        payload={"user_id": None, "email": invitation.email, "token": token, "organization": org.slug},
    )
    return JsonResponse({"ok": True, "invitation_id": invitation.pk})


@require_POST
@login_required
def org_accept_invitation(request):
    from organizations.services import accept_invitation

    try:
        membership = accept_invitation(user=request.user, token=_json_body(request).get("token", ""))
    except PermissionDenied as exc:
        return _error(request, "forbidden", str(exc), 403)
    except ValueError as exc:
        return _error(request, "invalid", str(exc), 400)
    return JsonResponse({"ok": True, "role": membership.role})


@require_POST
@login_required
def org_change_member_role(request, slug: str, user_id: int):
    guard = api_recent_auth_error(request, "org_membership")
    if guard:
        return guard
    from organizations.models import OrganizationMembership
    from organizations.services import change_membership_role

    org, denied = _scoped_org_or_error(request, slug)
    if denied:
        return denied
    membership = OrganizationMembership.objects.filter(organization=org, user_id=user_id).first()
    if not membership:
        return _error(request, "not_found", "Membership not found.", 404)
    try:
        change_membership_role(actor=request.user, membership=membership, role=_json_body(request).get("role", ""))
    except PermissionDenied as exc:
        return _error(request, "forbidden", str(exc), 403)
    return JsonResponse({"ok": True, "role": membership.role})


@require_POST
@login_required
def org_remove_member(request, slug: str, user_id: int):
    guard = api_recent_auth_error(request, "org_membership")
    if guard:
        return guard
    from organizations.models import OrganizationMembership
    from organizations.services import remove_membership

    org, denied = _scoped_org_or_error(request, slug)
    if denied:
        return denied
    membership = OrganizationMembership.objects.filter(organization=org, user_id=user_id).first()
    if not membership:
        return _error(request, "not_found", "Membership not found.", 404)
    try:
        remove_membership(actor=request.user, membership=membership)
    except PermissionDenied as exc:
        return _error(request, "forbidden", str(exc), 403)
    return JsonResponse({"ok": True})


@require_POST
@login_required
def admin_assign_role(request, user_id: int):
    denied = _require_platform_admin(request)
    if denied:
        return denied
    guard = api_recent_auth_error(request, "assign_role")
    if guard:
        return guard
    from organizations.models import Organization
    from organizations.services import assign_role

    target = get_user_model().objects.filter(pk=user_id).first()
    if not target:
        return _error(request, "not_found", "User not found.", 404)
    body = _json_body(request)
    org_slug = body.get("organization")
    organization = Organization.objects.filter(slug=org_slug).first() if org_slug else None
    try:
        assign_role(
            actor=request.user,
            user=target,
            organization=organization,
            group_name=body.get("group", ""),
        )
    except PermissionDenied as exc:
        return _error(request, "forbidden", str(exc), 403)
    except ValueError as exc:
        return _error(request, "invalid", str(exc), 400)
    return JsonResponse({"ok": True})
