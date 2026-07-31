"""HTTP views for the ops app."""
import json
import logging

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

logger = logging.getLogger("ops.alerts")


def healthz(request):
    return JsonResponse({"ok": True})


def readyz(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        cache.set("readyz", "1", timeout=5)
        cache_ok = cache.get("readyz") == "1"
    except Exception:
        return JsonResponse({"ok": False}, status=503)
    return JsonResponse({"ok": cache_ok}, status=200 if cache_ok else 503)


def _forbidden():
    return HttpResponse("forbidden\n", status=403, content_type="text/plain")


def metrics(request):
    """
    Prometheus-style text exposition of security/ops counters (SLO + queue monitoring).
    Guarded by a bearer token (METRICS_TOKEN) so it isn't world-readable.
    """
    token = getattr(settings, "METRICS_TOKEN", "")
    if token:
        provided = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if provided != token:
            return _forbidden()

    from notifications.services import outbox_stats
    from security_events.models import SecurityRiskEvent
    from sessions.models import ActiveSession

    stats = outbox_stats()
    active = ActiveSession.objects.filter(revoked_at__isnull=True).count()
    open_risks = SecurityRiskEvent.objects.filter(status=SecurityRiskEvent.Status.OPEN).count()
    dead = stats["dead_letter"]
    oldest = stats["oldest_pending_age_seconds"]
    lines = [
        "# HELP fa_active_sessions Active (non-revoked) sessions.",
        "# TYPE fa_active_sessions gauge",
        f"fa_active_sessions {active}",
        "# HELP fa_open_risk_events Open security risk events.",
        "# TYPE fa_open_risk_events gauge",
        f"fa_open_risk_events {open_risks}",
        "# HELP fa_outbox_dead_letter Dead-lettered outbox events.",
        "# TYPE fa_outbox_dead_letter gauge",
        f"fa_outbox_dead_letter {dead}",
        "# HELP fa_outbox_oldest_pending_seconds Age of the oldest undelivered outbox event.",
        "# TYPE fa_outbox_oldest_pending_seconds gauge",
        f"fa_outbox_oldest_pending_seconds {oldest}",
    ]
    return HttpResponse("\n".join(lines) + "\n", content_type="text/plain; version=0.0.4")


@csrf_exempt
@require_POST
def alerts_webhook(request):
    """
    Alertmanager webhook sink. Token-guarded (ALERT_WEBHOOK_TOKEN). Every alert is logged with its
    severity (ERROR for page, WARNING otherwise) so it lands in the queryable log/Sentry pipeline —
    a working default alerting destination that needs no external pager credential.
    """
    token = getattr(settings, "ALERT_WEBHOOK_TOKEN", "")
    if token:
        provided = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if provided != token:
            return _forbidden()
    try:
        payload = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"error": {"code": "bad_request", "message": "invalid JSON"}}, status=400)

    alerts = payload.get("alerts", []) if isinstance(payload, dict) else []
    for alert in alerts:
        labels = alert.get("labels", {})
        severity = labels.get("severity", "warn")
        name = labels.get("alertname", "unknown")
        summary = alert.get("annotations", {}).get("summary", "")
        level = logging.ERROR if severity == "page" else logging.WARNING
        logger.log(level, "ALERT %s [%s] status=%s: %s", name, severity, alert.get("status"), summary)
    return JsonResponse({"ok": True, "received": len(alerts)})
