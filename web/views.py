"""HTTP views for the web app."""
from django.contrib import messages
from django.contrib.auth import get_user_model, logout
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods, require_POST

from accounts.recent_auth import (
    bind_step_up_challenge,
    consume_step_up_challenge,
    mark_recent_auth,
    normalize_step_up_action,
    recent_auth_required,
    safe_next_url,
)
from accounts.step_up import (
    check_step_up_allowed,
    clear_step_up_attempts,
    record_step_up_failure,
    record_step_up_success,
    register_step_up_attempt,
    verify_step_up_credential,
)
from accounts.services import (
    AccountInactive,
    EmailVerificationRequired,
    StrongFactorRequired,
    abandon_pending_2fa,
    allowed_login_methods,
    authenticate_password_step,
    complete_login,
    needs_strong_factor_enrollment,
    pending_2fa_user,
    register_member,
    register_pending_2fa_attempt,
)
from accounts.throttle import AccountThrottled, client_ip, rate_limit_request
from mfa.models import MFADevice
from mfa.services import (
    begin_email_otp,
    clear_totp_enrollment_secret,
    clear_totp_enroll_attempts,
    enable_email_otp,
    enable_totp,
    generate_backup_codes,
    get_totp_enrollment_secret,
    register_totp_enroll_attempt,
    store_totp_enrollment_secret,
    verify_email_otp,
    verify_login_factor,
    verify_totp,
)
from organizations.services import accept_invitation
from passwords.services import (
    EmailAlreadyInUse,
    change_password,
    complete_password_reset,
    request_email_change,
    request_email_verification,
    request_password_reset,
    verify_email,
)
from sessions.models import ActiveSession
from sessions.services import revoke_session


def _safe_next(request, default="web:dashboard"):
    nxt = request.POST.get("next") or request.GET.get("next")
    return safe_next_url(request, nxt, default_name=default)


@login_required
def dashboard(request):
    return render(request, "web/dashboard.html")


@require_http_methods(["GET"])
def terms(request):
    return render(request, "web/legal.html", {"title": "Terms of Service", "doc": "terms"})


@require_http_methods(["GET"])
def privacy(request):
    return render(request, "web/legal.html", {"title": "Privacy Policy", "doc": "privacy"})


@require_http_methods(["GET", "POST"])
def register(request):
    if request.method == "POST":
        if not request.POST.get("accept_terms"):
            messages.error(request, "You must accept the Terms of Service and Privacy Policy.")
            return render(request, "registration/register.html", status=400)
        try:
            rate_limit_request("register", ip=client_ip(request), limit=10, window_seconds=3600)
        except AccountThrottled:
            messages.error(request, "Too many attempts. Please wait and try again.")
            return render(request, "registration/register.html", status=429)
        try:
            user = register_member(
                username=request.POST["username"],
                email=request.POST["email"],
                password=request.POST["password"],
            )
        except ValidationError as exc:
            # Password-policy messages are safe to show.
            messages.error(request, "; ".join(exc.messages))
        except ValueError as exc:
            # Breach-screening messages are safe to show.
            messages.error(request, str(exc))
        except IntegrityError:
            # Never leak raw DB constraint text (would enumerate accounts). Generic message.
            messages.error(request, "That account could not be created. Try a different username or email.")
        else:
            from security_events.services import record_audit_event

            record_audit_event(
                actor=user,
                target_user=user,
                event_type="account.registered",
                metadata={"terms_accepted": True},
                request=request,
            )
            messages.success(request, "Account created. Check the worker/email logs for your verification link.")
            return redirect("web:login")
    return render(request, "registration/register.html")


@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.method == "POST":
        try:
            user = authenticate_password_step(
                request=request,
                username=request.POST.get("username", ""),
                password=request.POST.get("password", ""),
            )
        except AccountThrottled:
            messages.error(request, "Too many attempts. Please wait and try again.")
            return render(request, "registration/login.html", status=429)
        except EmailVerificationRequired:
            messages.error(request, "Please verify your email before signing in. You can request a new link below.")
            return redirect("web:resend_verification")

        if not user:
            messages.error(request, "The username or password is invalid.")
        elif request.session.get("awaiting_2fa_user_id"):
            if needs_strong_factor_enrollment(user):
                return redirect("web:mfa_enroll")
            return redirect("web:mfa_challenge")
        else:
            return redirect("web:dashboard")
    return render(request, "registration/login.html")


@require_http_methods(["GET", "POST"])
def mfa_challenge(request):
    user = pending_2fa_user(request)
    if not user:
        return redirect("web:login")
    if needs_strong_factor_enrollment(user):
        return redirect("web:mfa_enroll")

    # Only offer methods the user has enrolled and is allowed to complete with (policy-aware).
    factors = allowed_login_methods(user)
    method = request.GET.get("method") or ("totp" if "totp" in factors else next(iter(factors), "backup_code"))

    if request.method == "POST":
        method = request.POST.get("method", method)
        if method == "email_otp_send":
            if "email_otp" not in factors:
                messages.error(request, "Email OTP is not available for this account.")
                return redirect("web:mfa_challenge")
            try:
                challenge, _ = begin_email_otp(user=user, request=request, deliver=True)
            except Exception as exc:  # noqa: BLE001
                messages.error(request, str(exc))
            else:
                request.session["email_otp_challenge_id"] = challenge.pk
                messages.success(request, "A verification code was emailed to you.")
            return redirect(f"{reverse('web:mfa_challenge')}?method=email_otp")

        code = request.POST.get("code", "")
        # Reject a completing factor the user isn't allowed to use (e.g. email OTP for a role
        # that requires a strong factor, or a factor that was never enrolled).
        ok = method in factors and verify_login_factor(request=request, user=user, method=method, code=code)
        if ok:
            try:
                complete_login(request=request, user=user, event_type="auth.login.completed_mfa")
            except StrongFactorRequired:
                return redirect("web:mfa_enroll")
            except AccountInactive:
                abandon_pending_2fa(request, user=user, reason="deactivated")
                messages.error(request, "This account is no longer active.")
                return redirect("web:login")
            request.session.pop("email_otp_challenge_id", None)
            return redirect("web:dashboard")

        if register_pending_2fa_attempt(request):
            abandon_pending_2fa(request, user=user, reason="attempt_cap")
            messages.error(request, "Too many invalid codes. Please sign in again.")
            return redirect("web:login")
        messages.error(request, "The verification code is invalid.")

    return render(
        request,
        "registration/mfa_challenge.html",
        {"factors": sorted(factors), "method": method},
    )


@require_http_methods(["GET", "POST"])
def mfa_enroll(request):
    """First-factor enrollment reachable from the awaiting-2FA state (fixes genesis lockout)."""
    user = pending_2fa_user(request)
    if not user:
        return redirect("web:login")

    device_id = request.session.get("enroll_totp_device_id")
    provisioning = get_totp_enrollment_secret(user_id=user.pk, device_id=device_id) if device_id else None

    if request.method == "POST":
        if request.POST.get("stage") == "start" or not device_id:
            MFADevice.objects.filter(
                user=user, type=MFADevice.Type.TOTP, enabled_at__isnull=True
            ).delete()
            device, secret = enable_totp(user=user, name="Authenticator")
            request.session["enroll_totp_device_id"] = device.pk
            store_totp_enrollment_secret(user_id=user.pk, device_id=device.pk, secret=secret)
            return render(request, "registration/mfa_enroll.html", {"secret": secret, "stage": "confirm"})

        device = MFADevice.objects.filter(pk=device_id, user=user).first()
        if device and verify_totp(device=device, code=request.POST.get("code", "")):
            from mfa.models import BackupCode

            codes = None
            if not BackupCode.objects.filter(user=user, used_at__isnull=True).exists():
                codes = generate_backup_codes(user=user)
            clear_totp_enrollment_secret(user_id=user.pk, device_id=device_id)
            request.session.pop("enroll_totp_device_id", None)
            clear_totp_enroll_attempts(request)
            try:
                complete_login(request=request, user=user, event_type="auth.login.completed_mfa_enrolled")
            except StrongFactorRequired:
                messages.error(request, "Enrollment incomplete.")
                return redirect("web:mfa_enroll")
            if codes:
                return render(request, "registration/backup_codes.html", {"codes": codes})
            return redirect("web:dashboard")

        if register_pending_2fa_attempt(request):
            abandon_pending_2fa(request, user=user, reason="attempt_cap")
            messages.error(request, "Too many invalid codes. Please sign in again.")
            return redirect("web:login")
        if register_totp_enroll_attempt(request):
            abandon_pending_2fa(request, user=user, reason="attempt_cap")
            messages.error(request, "Too many invalid codes. Please sign in again.")
            return redirect("web:login")
        messages.error(request, "That code did not verify. Try again.")
        return render(request, "registration/mfa_enroll.html", {"secret": provisioning, "stage": "confirm"})

    return render(
        request,
        "registration/mfa_enroll.html",
        {"stage": "start", "passkey_enroll": needs_strong_factor_enrollment(user)},
    )


@require_POST
def logout_view(request):
    abandon_pending_2fa(request)
    logout(request)
    return redirect("web:login")


@login_required
def security_home(request):
    active_sessions = ActiveSession.objects.filter(user=request.user).order_by("-last_seen_at")
    factors = MFADevice.objects.filter(user=request.user)
    return render(request, "security/home.html", {"active_sessions": active_sessions, "factors": factors})


@login_required
@recent_auth_required("revoke_session")
@require_POST
def revoke_session_web(request, session_id: int):
    active_session = ActiveSession.objects.filter(pk=session_id, user=request.user).first()
    if not active_session:
        raise PermissionDenied("Session not found.")
    revoke_session(actor=request.user, active_session=active_session, request=request)
    messages.success(request, "Session revoked.")
    return redirect("web:security")


@require_http_methods(["GET", "POST"])
def step_up(request):
    """Re-prove password or an enrolled factor to satisfy recent-auth for a sensitive action."""
    if not request.user.is_authenticated:
        return redirect("web:login")
    action = request.GET.get("action") or request.POST.get("action") or "default"
    if normalize_step_up_action(action) is None:
        messages.error(request, "That action is not valid for step-up confirmation.")
        return redirect("web:dashboard")
    next_url = _safe_next(request)
    token = request.POST.get("token") or request.GET.get("token") or ""
    ctx = {"action": action, "next": next_url, "token": token}

    if request.method == "POST":
        try:
            check_step_up_allowed(request=request, user=request.user)
        except AccountThrottled:
            token = bind_step_up_challenge(request, action=action, next_url=next_url) or ""
            ctx["token"] = token
            messages.error(request, "Too many attempts. Please wait and try again.")
            return render(request, "registration/step_up.html", ctx, status=429)
        if not consume_step_up_challenge(request, action=action, next_url=next_url, token=token):
            messages.error(request, "This confirmation link is invalid or expired. Try again.")
            return redirect("web:step_up")
        if verify_step_up_credential(
            user=request.user,
            password=request.POST.get("password", ""),
            totp_code=request.POST.get("totp_code", ""),
            backup_code=request.POST.get("backup_code", ""),
        ):
            mark_recent_auth(request, action)
            clear_step_up_attempts(request)
            record_step_up_success(request=request, user=request.user)
            return redirect(next_url)
        record_step_up_failure(request=request, user=request.user)
        if register_step_up_attempt(request):
            token = bind_step_up_challenge(request, action=action, next_url=next_url) or ""
            ctx["token"] = token
            messages.error(request, "Too many failed attempts. Please wait and try again.")
            return render(request, "registration/step_up.html", ctx, status=429)
        messages.error(request, "Could not verify your identity. Check your password or code and try again.")
        token = bind_step_up_challenge(request, action=action, next_url=next_url) or ""
        ctx["token"] = token
    elif request.method == "GET":
        token = bind_step_up_challenge(request, action=action, next_url=next_url) or ""
        ctx["token"] = token
    return render(request, "registration/step_up.html", ctx)


@require_http_methods(["GET", "POST"])
def password_reset_request(request):
    if request.method == "POST":
        try:
            rate_limit_request("password_reset", ip=client_ip(request), limit=5, window_seconds=3600)
        except AccountThrottled:
            messages.error(request, "Too many requests. Please wait and try again.")
            return render(request, "registration/password_reset_request.html", status=429)
        email = request.POST.get("email", "").lower()
        user = get_user_model().objects.filter(email=email).first()
        # Enumeration-safe: only send to a verified primary email, but always show success.
        if user and user.email_verified:
            request_password_reset(user=user, request=request)
        messages.success(request, "If that email exists, a reset link has been sent.")
        return redirect("web:login")
    return render(request, "registration/password_reset_request.html")


@require_http_methods(["GET", "POST"])
def password_reset_complete(request):
    token = request.GET.get("token") or request.POST.get("token", "")
    if request.method == "POST":
        try:
            ok = complete_password_reset(token=token, new_password=request.POST.get("password", ""))
        except ValueError as exc:
            messages.error(request, str(exc))
        else:
            if ok:
                messages.success(request, "Password reset. You can sign in now.")
                return redirect("web:login")
            messages.error(request, "This reset link is invalid or has expired.")
    return render(request, "registration/password_reset_complete.html", {"token": token})


@require_http_methods(["GET"])
def verify_email_view(request):
    token = request.GET.get("token", "")
    try:
        ok = verify_email(token=token)
    except EmailAlreadyInUse as exc:
        messages.error(request, str(exc))
        return redirect("web:login")
    messages.add_message(
        request,
        messages.SUCCESS if ok else messages.ERROR,
        "Email verified." if ok else "This verification link is invalid or has expired.",
    )
    return redirect("web:login")


@require_http_methods(["GET", "POST"])
def resend_verification(request):
    """Enumeration-safe, throttled resend of an email-verification link."""
    if request.method == "POST":
        try:
            rate_limit_request("email_verification", ip=client_ip(request), limit=5, window_seconds=3600)
        except AccountThrottled:
            messages.error(request, "Too many requests. Please wait and try again.")
            return render(request, "registration/resend_verification.html", status=429)
        email = request.POST.get("email", "").lower()
        user = get_user_model().objects.filter(email=email).first()
        if user and not user.email_verified:
            request_email_verification(user=user)
        messages.success(request, "If that account needs verification, a new link has been sent.")
        return redirect("web:login")
    return render(request, "registration/resend_verification.html")


@login_required
@require_http_methods(["GET", "POST"])
def accept_invitation_view(request):
    """Accept an organization invitation from an emailed token (requires a verified login)."""
    token = request.GET.get("token") or request.POST.get("token", "")
    if request.method == "POST":
        try:
            accept_invitation(user=request.user, token=token)
        except (ValueError, PermissionDenied) as exc:
            messages.error(request, str(exc))
        else:
            messages.success(request, "Invitation accepted.")
            return redirect("web:dashboard")
    return render(request, "registration/accept_invitation.html", {"token": token})


@login_required
@recent_auth_required("change_password")
@require_http_methods(["GET", "POST"])
def change_password_view(request):
    if request.method == "POST":
        try:
            change_password(
                user=request.user,
                current_password=request.POST.get("current_password", ""),
                new_password=request.POST.get("new_password", ""),
            )
        except ValueError as exc:
            messages.error(request, str(exc))
        else:
            messages.success(request, "Password changed. Please sign in again.")
            logout(request)
            return redirect("web:login")
    return render(request, "registration/change_password.html")


@login_required
@recent_auth_required("change_email")
@require_http_methods(["GET", "POST"])
def change_email_view(request):
    if request.method == "POST":
        try:
            request_email_change(user=request.user, new_email=request.POST.get("email", ""), request=request)
        except EmailAlreadyInUse as exc:
            messages.error(request, str(exc))
        else:
            messages.success(request, "Verification link sent to the new address.")
            return redirect("web:security")
    return render(request, "registration/change_email.html")


@login_required
@recent_auth_required("regenerate_backup_codes")
@require_POST
def regenerate_backup_codes(request):
    codes = generate_backup_codes(user=request.user)
    return render(request, "registration/backup_codes.html", {"codes": codes})


@login_required
@require_http_methods(["GET", "POST"])
def notification_preferences_view(request):
    from notifications.models import SUPPRESSIBLE_CATEGORIES
    from notifications.services import get_preferences, set_preference

    if request.method == "POST":
        for category in SUPPRESSIBLE_CATEGORIES:
            set_preference(user=request.user, category=category, email_enabled=(request.POST.get(category) == "on"))
        messages.success(request, "Notification preferences updated.")
        return redirect("web:notification_preferences")
    return render(request, "security/notification_preferences.html", {"preferences": get_preferences(request.user)})


@login_required
@recent_auth_required("manage_mfa")
@require_http_methods(["GET", "POST"])
def enroll_totp(request):
    """Self-service TOTP enrollment for a logged-in user (fixes: passkey was the only option)."""
    from mfa.models import BackupCode

    device_id = request.session.get("settings_totp_device_id")
    if request.method == "POST":
        if request.POST.get("stage") == "start" or not device_id:
            MFADevice.objects.filter(user=request.user, type=MFADevice.Type.TOTP, enabled_at__isnull=True).delete()
            device, secret = enable_totp(user=request.user, name="Authenticator")
            request.session["settings_totp_device_id"] = device.pk
            store_totp_enrollment_secret(user_id=request.user.pk, device_id=device.pk, secret=secret)
            return render(request, "registration/mfa_enroll.html", {"secret": secret, "stage": "confirm"})
        device = MFADevice.objects.filter(pk=device_id, user=request.user).first()
        if device and verify_totp(device=device, code=request.POST.get("code", "")):
            clear_totp_enrollment_secret(user_id=request.user.pk, device_id=device_id)
            request.session.pop("settings_totp_device_id", None)
            clear_totp_enroll_attempts(request)
            if not BackupCode.objects.filter(user=request.user, used_at__isnull=True).exists():
                codes = generate_backup_codes(user=request.user)
                return render(request, "registration/backup_codes.html", {"codes": codes})
            messages.success(request, "Authenticator enabled.")
            return redirect("web:security")
        if register_totp_enroll_attempt(request):
            messages.error(request, "Too many invalid codes. Please start enrollment again.")
            request.session.pop("settings_totp_device_id", None)
            return redirect("web:enroll_totp")
        messages.error(request, "That code did not verify. Try again.")
        secret = get_totp_enrollment_secret(user_id=request.user.pk, device_id=device_id) if device_id else ""
        return render(request, "registration/mfa_enroll.html", {"secret": secret, "stage": "confirm"})
    return render(request, "registration/mfa_enroll.html", {"stage": "start"})


@login_required
@recent_auth_required("manage_mfa")
@require_POST
def enroll_email_otp(request):
    try:
        enable_email_otp(user=request.user)
    except ValueError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, "Email OTP enabled.")
    return redirect("web:security")


@login_required
@recent_auth_required("disable_mfa")
@require_POST
def disable_factor_web(request, factor_id: int):
    from mfa.services import disable_mfa_device
    from notifications.services import emit_outbox_event
    from security_events.services import record_audit_event

    device = MFADevice.objects.filter(pk=factor_id, user=request.user).first()
    if not device:
        raise PermissionDenied("Factor not found.")
    try:
        disable_mfa_device(user=request.user, device=device)
    except ValueError as exc:
        messages.error(request, str(exc))
    else:
        record_audit_event(
            actor=request.user, target_user=request.user, event_type="mfa.factor.disabled",
            metadata={"factor_id": device.pk, "type": device.type}, request=request,
        )
        emit_outbox_event(
            event_type="mfa.factor.disabled", aggregate_type="user",
            aggregate_id=str(request.user.pk), payload={"user_id": request.user.pk},
        )
        messages.success(request, "Factor disabled.")
    return redirect("web:security")


@login_required
def admin_console(request):
    """Legacy route: redirect to the HTMX security console."""
    if not request.user.is_superuser:
        raise PermissionDenied("Platform administrator required.")
    return redirect("web:console")
