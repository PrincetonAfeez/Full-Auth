"""Cross-cutting HTTP middleware (request ID, API rate limits, JSON validation)."""
import logging
import uuid
from contextvars import ContextVar

_request_id_var: ContextVar[str] = ContextVar("request_id", default="")


def get_request_id() -> str:
    return _request_id_var.get()


class RequestIDMiddleware:
    """
    Assign a stable request id (honoring an inbound X-Request-ID) and expose it on the
    request, in a contextvar for log records, and as a response header. Everything that reads
    ``request.request_id`` (audit events, API error envelopes) now gets a real value.
    """

    HEADER = "HTTP_X_REQUEST_ID"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        incoming = request.META.get(self.HEADER, "")
        request_id = incoming[:64] if incoming else uuid.uuid4().hex
        request.request_id = request_id
        token = _request_id_var.set(request_id)
        try:
            response = self.get_response(request)
        finally:
            _request_id_var.reset(token)
        response["X-Request-ID"] = request_id
        return response


class RequestIDLogFilter(logging.Filter):
    """Inject the current request id into every log record for structured correlation."""

    def filter(self, record):
        record.request_id = get_request_id() or "-"
        return True


class SlowQueryLoggingMiddleware:
    """
    Logs DB queries slower than settings.DB_SLOW_QUERY_MS (0 = disabled) with the request id, for
    slow-query visibility without full query logging. Complements Postgres
    log_min_duration_statement (see docs/runbooks/monitoring.md).
    """

    def __init__(self, get_response):
        from django.conf import settings

        self.get_response = get_response
        self.threshold_ms = getattr(settings, "DB_SLOW_QUERY_MS", 0)
        self.logger = logging.getLogger("db.slow_query")
        if not self.threshold_ms:
            from django.core.exceptions import MiddlewareNotUsed

            raise MiddlewareNotUsed()

    def __call__(self, request):
        import time

        from django.db import connection

        def wrapper(execute, sql, params, many, context):
            start = time.monotonic()
            try:
                return execute(sql, params, many, context)
            finally:
                elapsed_ms = (time.monotonic() - start) * 1000
                if elapsed_ms >= self.threshold_ms:
                    self.logger.warning("slow query %.1fms: %s", elapsed_ms, sql[:500])

        with connection.execute_wrapper(wrapper):
            return self.get_response(request)


class ApiJsonValidationMiddleware:
    """Reject malformed JSON bodies on API write requests before view logic runs."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method in ("POST", "PUT", "PATCH") and request.path.startswith("/api/"):
            content_type = request.content_type or ""
            if "application/json" in content_type and request.body:
                import json

                try:
                    json.loads(request.body)
                except ValueError:
                    from django.http import JsonResponse

                    return JsonResponse(
                        {
                            "error": {
                                "code": "invalid_json",
                                "message": "Malformed JSON body.",
                                "fields": {},
                                "request_id": getattr(request, "request_id", ""),
                            }
                        },
                        status=400,
                    )
        return self.get_response(request)


def _rate_limit_response(request, *, retry_after: int = 60) -> "JsonResponse":
    from django.http import JsonResponse

    response = JsonResponse(
        {
            "error": {
                "code": "throttled",
                "message": "Rate limit exceeded.",
                "fields": {"retry_after": retry_after},
                "request_id": getattr(request, "request_id", ""),
            }
        },
        status=429,
    )
    response["Retry-After"] = str(retry_after)
    return response


class ApiRateLimitMiddleware:
    """
    A global per-principal ceiling on the /api/ surface (defense-in-depth on top of the
    per-flow auth throttles). Keyed by authenticated user id, else client IP; fixed 1-minute
    window in the shared cache. Over the limit -> 429 with the standard JSON error envelope.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith("/api/") and self._over_limit(request):
            return _rate_limit_response(request, retry_after=60)
        return self.get_response(request)

    def _over_limit(self, request) -> bool:
        import time

        from django.conf import settings
        from django.core.cache import cache

        from accounts.client_ip import client_ip

        limit = settings.API_RATE_LIMIT_PER_MINUTE
        user = getattr(request, "user", None)
        ip = client_ip(request)
        principal = f"u{user.pk}" if user is not None and user.is_authenticated else f"ip{ip}"
        key = f"apirl:{principal}:{int(time.time() // 60)}"
        try:
            cache.add(key, 0, 60)
            return (cache.incr(key) or 0) > limit
        except Exception:
            if settings.THROTTLE_FAIL_CLOSED:
                return True
            return False
