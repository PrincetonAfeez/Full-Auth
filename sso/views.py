"""HTTP views for the sso app."""
import logging
import secrets

from django.contrib import messages
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from accounts.services import (
    abandon_pending_2fa,
    complete_login,
    enabled_factor_types,
    trusted_device_skips_mfa,
    user_mfa_required,
)

from .connectors import get_connector, is_configured
from .models import IdentityProvider
from .services import SSOError, ensure_org_sso_access, resolve_user

logger = logging.getLogger(__name__)


def _validate_sso_state(request, slug: str) -> bool:
    expected = request.session.get("sso_state")
    provider_slug = request.session.get("sso_provider")
    received = request.GET.get("state", "")
    if not expected or provider_slug != slug or not received or received != expected:
        return False
    return True


def _sso_unavailable(request):
    messages.error(request, "SSO is not configured for this provider.")
    return redirect("web:login")


def _clear_existing_session(request) -> None:
    if getattr(request, "user", None) and request.user.is_authenticated:
        abandon_pending_2fa(request)
        logout(request)


@require_http_methods(["GET"])
def sso_begin(request, slug: str):
    provider = IdentityProvider.objects.filter(slug=slug, enabled=True).select_related("organization").first()
    if not provider or not is_configured(provider):
        return _sso_unavailable(request)
    if provider.organization_id and provider.organization.status != provider.organization.Status.ACTIVE:
        messages.error(request, "SSO is not available for this organization.")
        return redirect("web:login")
    state = secrets.token_urlsafe(24)
    request.session["sso_state"] = state
    request.session["sso_provider"] = slug
    return redirect(get_connector(provider).authorization_url(request, provider, state))


@require_http_methods(["GET", "POST"])
def sso_callback(request, slug: str):
    provider = IdentityProvider.objects.filter(slug=slug, enabled=True).select_related("organization").first()
    if not provider or not is_configured(provider):
        return _sso_unavailable(request)
    if provider.organization_id and provider.organization.status != provider.organization.Status.ACTIVE:
        messages.error(request, "SSO is not available for this organization.")
        return redirect("web:login")
    if not _validate_sso_state(request, slug):
        messages.error(request, "Invalid or expired SSO session. Please try again.")
        request.session.pop("sso_state", None)
        request.session.pop("sso_provider", None)
        return redirect("web:login")
    request.session.pop("sso_state", None)
    request.session.pop("sso_provider", None)
    try:
        external = get_connector(provider).complete(request, provider)
        user = resolve_user(provider=provider, external=external)
        ensure_org_sso_access(provider=provider, user=user)
    except SSOError as exc:
        messages.error(request, str(exc))
        return redirect("web:login")
    except Exception:
        logger.exception("SSO callback failed for provider %s", slug)
        from security_events.services import detect_risk_event

        detect_risk_event(event_type="sso.callback_failed", severity="high", details={"provider": slug})
        messages.error(request, "Sign-in with SSO failed. Please try again or use your password.")
        return redirect("web:login")

    _clear_existing_session(request)

    if user_mfa_required(user) or enabled_factor_types(user):
        if trusted_device_skips_mfa(request, user):
            complete_login(request=request, user=user, event_type="auth.login.completed_sso_trusted_device")
            return redirect("web:dashboard")
        request.session.cycle_key()
        request.session["awaiting_2fa_user_id"] = user.pk
        request.session["awaiting_2fa_started_at"] = timezone.now().isoformat()
        request.session["awaiting_2fa_attempts"] = 0
        return redirect("web:mfa_challenge")
    complete_login(request=request, user=user, event_type="auth.login.completed_sso")
    return redirect("web:dashboard")
