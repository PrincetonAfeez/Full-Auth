"""
Login/recovery throttling and lockout, backed by the shared cache (Redis in prod).

Design (spec 17): throttle by IP and by (username, IP) -- never by username alone,
so an attacker cannot lock a victim out with bad-password spam. Counters live in the
shared cache; when the cache is unavailable, protected flows fail closed if
settings.THROTTLE_FAIL_CLOSED is set.
"""
import time

from django.conf import settings
from django.core.cache import cache


class AccountThrottled(Exception):
    """Raised when a protected flow is currently locked/throttled."""

    def __init__(self, retry_after: int = 0):
        self.retry_after = retry_after
        super().__init__("Too many attempts. Try again later.")


class ThrottleBackendUnavailable(AccountThrottled):
    """Raised (fail-closed) when the throttle backend cannot be reached."""


def client_ip(request) -> str:
    from .client_ip import client_ip as _client_ip

    return _client_ip(request)


def _safe(op, *args, **kwargs):
    try:
        return op(*args, **kwargs)
    except Exception as exc:  # cache backend down
        if settings.THROTTLE_FAIL_CLOSED:
            raise ThrottleBackendUnavailable() from exc
        return None


def _keys(scope: str, username: str, ip: str):
    ident = (username or "").strip().lower()
    return (f"thr:{scope}:ip:{ip}", f"thr:{scope}:userip:{ident}:{ip}")


def check_allowed(scope: str, *, username: str, ip: str) -> None:
    """Raise AccountThrottled if either the IP or (username, IP) key is locked."""
    now = time.time()
    for key in _keys(scope, username, ip):
        locked_until = _safe(cache.get, key + ":locked")
        if locked_until and locked_until > now:
            raise AccountThrottled(retry_after=int(locked_until - now))


def record_failure(scope: str, *, username: str, ip: str, policy) -> None:
    """Increment failure counters; engage a time-bounded lock once the threshold trips."""
    threshold = max(1, policy.lockout_threshold)
    duration = max(60, policy.lockout_duration_minutes * 60)
    for key in _keys(scope, username, ip):
        count_key = key + ":count"
        # cache.add is a no-op if the key exists, giving us a rolling window == duration.
        _safe(cache.add, count_key, 0, duration)
        count = _safe(cache.incr, count_key) or 0
        if count >= threshold:
            _safe(cache.set, key + ":locked", time.time() + duration, duration)


def record_success(scope: str, *, username: str, ip: str) -> None:
    """
    Clear counters/locks for the (username, IP) pair on a good outcome. The IP-wide counter is
    intentionally left to age out so one legitimate login can't reset the brute-force signal
    for other usernames behind a shared/NAT IP.
    """
    _, userip_key = _keys(scope, username, ip)
    _safe(cache.delete, userip_key + ":count")
    _safe(cache.delete, userip_key + ":locked")


def clear_lock(scope: str, *, username: str, ip: str) -> None:
    """Admin unlock (clears both IP and user+IP counters/locks)."""
    for key in _keys(scope, username, ip):
        _safe(cache.delete, key + ":count")
        _safe(cache.delete, key + ":locked")


def rate_limit_request(scope: str, *, ip: str, limit: int, window_seconds: int) -> None:
    """
    Simple IP-keyed request rate limit for unauthenticated abuse-prone endpoints
    (password-reset / verification requests). Raises AccountThrottled once `limit` is
    exceeded within the window. Fail-closed on cache outage per settings.THROTTLE_FAIL_CLOSED.
    """
    key = f"rl:{scope}:ip:{ip}"
    _safe(cache.add, key, 0, window_seconds)
    count = _safe(cache.incr, key) or 0
    if count > limit:
        raise AccountThrottled(retry_after=window_seconds)
