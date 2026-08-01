"""Short-TTL cache for ActiveSession middleware lookups."""
from django.core.cache import cache

_PREFIX = "activesession:"
_TTL = 60


def _key(session_key_hash: str) -> str:
    return f"{_PREFIX}{session_key_hash}"


def get_cached_session_id(session_key_hash: str) -> int | None:
    try:
        value = cache.get(_key(session_key_hash))
        return int(value) if value is not None else None
    except Exception:
        return None


def set_cached_session_id(session_key_hash: str, session_id: int) -> None:
    try:
        cache.set(_key(session_key_hash), session_id, _TTL)
    except Exception:
        pass


def invalidate_session_cache(session_key_hash: str | None) -> None:
    if not session_key_hash:
        return
    try:
        cache.delete(_key(session_key_hash))
    except Exception:
        pass
