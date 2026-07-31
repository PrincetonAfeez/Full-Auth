"""
Minimal feature-flag helper for safe rollout. Flags are read from settings.FEATURE_FLAGS,
which is populated from FLAG_<NAME> environment variables. Use:

    from config.flags import feature_enabled
    if feature_enabled("new_dashboard"):
        ...
"""
from django.conf import settings


def feature_enabled(name: str, default: bool = False) -> bool:
    return settings.FEATURE_FLAGS.get(name.lower(), default)
