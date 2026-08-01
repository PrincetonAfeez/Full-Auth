"""
Platform security console (§21) -- HTMX-driven. Superuser-gated. Each section is an HTMX
partial loaded into the console shell; mutating actions post and re-render their section.
Every section is also directly reachable (full-page fallback) per §9.
"""
from functools import wraps

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from accounts.recent_auth import recent_auth_required
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from mfa.models import MFADevice
from notifications.models import NotificationDelivery
from organizations.models import Invitation, Organization
from security_events.models import AuditEvent, SecurityRiskEvent
from security_policies.models import SecurityPolicy
from sessions.models import ActiveSession


def console_required(view):
    @wraps(view)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not request.user.is_superuser:
            raise PermissionDenied("Platform administrator required.")
        return view(request, *args, **kwargs)

    return wrapper


def _render_section(request, template, context, *, status=200):
    # HTMX requests get the bare partial; direct navigation gets it wrapped in the console shell.
    context = {**context, "partial": template}
    if request.headers.get("HX-Request"):
        return render(request, template, context, status=status)
    return render(request, "console/shell.html", context, status=status)


@console_required
def console_home(request):
    return _render_section(request, "console/_overview.html", {
        "user_count": get_user_model().objects.count(),
        "org_count": Organization.objects.count(),
        "open_risks": SecurityRiskEvent.objects.filter(status=SecurityRiskEvent.Status.OPEN).count(),
        "active_sessions": ActiveSession.objects.filter(revoked_at__isnull=True).count(),
    })


@console_required
def console_users(request):
    q = request.GET.get("q", "").strip()
    users = get_user_model().objects.order_by("-id")
    if q:
        users = users.filter(username__icontains=q)
    return _render_section(request, "console/_users.html", {"users": users[:50], "q": q})


@console_required
def console_orgs(request):
    return _render_section(request, "console/_orgs.html", {
        "orgs": Organization.objects.order_by("name")[:100],
        "statuses": Organization.Status,
    })


@console_required
def console_sessions(request):
    rows = ActiveSession.objects.select_related("user").order_by("-last_seen_at")[:50]
    return _render_section(request, "console/_sessions.html", {"sessions": rows})


@console_required
def console_audit(request):
    events = AuditEvent.objects.select_related("actor", "target_user").all()[:100]
    return _render_section(request, "console/_audit.html", {"events": events})


@console_required
def console_risk(request):
    events = SecurityRiskEvent.objects.select_related("user").all()[:100]
    return _render_section(request, "console/_risk.html", {"events": events})


@console_required
def console_policies(request):
    return _render_section(request, "console/_policies.html", {
        "policies": SecurityPolicy.objects.select_related("organization").all()[:100],
    })


@console_required
def console_mfa(request):
    return _render_section(request, "console/_mfa.html", {
        "devices": MFADevice.objects.select_related("user").order_by("-id")[:100],
    })


@console_required
def console_invitations(request):
    return _render_section(request, "console/_invitations.html", {
        "invitations": Invitation.objects.select_related("organization", "inviter").order_by("-created_at")[:100],
    })


@console_required
def console_notifications(request):
    return _render_section(request, "console/_notifications.html", {
        "deliveries": NotificationDelivery.objects.select_related("recipient").order_by("-created_at")[:100],
    })


# --- actions -----------------------------------------------------------------

@console_required
@recent_auth_required("org_lifecycle")
@require_POST
def console_org_action(request, slug: str):
    from organizations.services import close_organization, reactivate_organization, suspend_organization

    org = Organization.objects.filter(slug=slug).first()
    if not org:
        raise PermissionDenied("Organization not found.")
    action = request.POST.get("action")
    try:
        if action == "suspend":
            suspend_organization(actor=request.user, organization=org)
        elif action == "reactivate":
            reactivate_organization(actor=request.user, organization=org)
        elif action == "close":
            close_organization(actor=request.user, organization=org)
    except PermissionDenied as exc:
        messages.error(request, str(exc))
    return console_orgs(request)


@console_required
@recent_auth_required("deactivate_user")
@require_POST
def console_user_deactivate(request, user_id: int):
    from accounts.services import deactivate_user

    target = get_user_model().objects.filter(pk=user_id).first()
    if target:
        try:
            deactivate_user(actor=request.user, user=target, reason="console")
        except PermissionDenied as exc:
            messages.error(request, str(exc))
    return console_users(request)


@console_required
@recent_auth_required("admin_revoke_sessions")
@require_POST
def console_session_revoke(request, session_id: int):
    from sessions.services import revoke_session

    active = ActiveSession.objects.filter(pk=session_id).first()
    if active and active.revoked_at is None:
        revoke_session(actor=request.user, active_session=active, request=request)
    return console_sessions(request)


@console_required
@recent_auth_required("default")
@require_POST
def console_risk_resolve(request, event_id: int):
    from security_events.models import SecurityRiskEvent
    from security_events.services import resolve_risk_event

    status = request.POST.get("status", "resolved")
    valid = {SecurityRiskEvent.Status.REVIEWED, SecurityRiskEvent.Status.RESOLVED, SecurityRiskEvent.Status.FALSE_POSITIVE}
    if status not in valid:
        return _render_section(
            request,
            "console/_risk.html",
            {"events": SecurityRiskEvent.objects.order_by("-created_at")[:50], "error": f"Invalid status: {status}"},
            status=400,
        )
    resolve_risk_event(actor=request.user, event_id=event_id, status=status)
    return console_risk(request)
