"""Resolve client IP from request headers (proxy-aware)."""
from django.conf import settings


def client_ip(request) -> str:
    if request is None:
        return "unknown"
    if _trust_forwarded_for():
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            return forwarded.split(",")[0].strip() or "unknown"
    return request.META.get("REMOTE_ADDR") or "unknown"


def _trust_forwarded_for() -> bool:
    return bool(getattr(settings, "SECURE_PROXY_SSL_HEADER", None))
