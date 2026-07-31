"""Django project settings and environment configuration."""
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


TESTING = "test" in sys.argv or env_bool("FULL_AUTH_TESTING") or any("pytest" in arg for arg in sys.argv)


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


ENVIRONMENT = os.getenv("FULL_AUTH_ENV", "development")
DEPLOY_ENVIRONMENTS = {"production", "staging"}
DEBUG = env_bool("DJANGO_DEBUG", ENVIRONMENT not in DEPLOY_ENVIRONMENTS)
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "dev-only-change-me")
SECRET_KEY_FALLBACKS = split_csv(os.getenv("DJANGO_SECRET_KEY_FALLBACKS", ""))
ALLOWED_HOSTS = split_csv(os.getenv("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1"))
CSRF_TRUSTED_ORIGINS = split_csv(os.getenv("DJANGO_CSRF_TRUSTED_ORIGINS", ""))


INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "accounts",
    "organizations",
    "security_policies",
    "security_events",
    "sessions.apps.SessionsConfig",
    "mfa",
    "passwords",
    "notifications",
    "sso",
    "api",
    "web",
    "ops",
]

# NOTE: The Django per-site cache middleware (Update/FetchFromCache) is deliberately
# NOT used. On an authenticated identity surface it is a cross-user leak waiting to
# happen; responses are made explicitly no-store by SecurityEnforcementMiddleware and
# any cacheable content is cached per-view instead.
MIDDLEWARE = [
    "config.middleware.RequestIDMiddleware",
    "config.middleware.SlowQueryLoggingMiddleware",  # self-disables when DB_SLOW_QUERY_MS=0
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "config.middleware.ApiJsonValidationMiddleware",
    "config.middleware.ApiRateLimitMiddleware",
    "sessions.middleware.SecurityEnforcementMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"


# Persistent connections (pooling) + liveness checks for production DB efficiency.
DB_CONN_MAX_AGE = int(os.getenv("DB_CONN_MAX_AGE", "60" if ENVIRONMENT == "production" else "0"))


def database_from_url(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.scheme in {"postgres", "postgresql"}:
        return {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": parsed.path.lstrip("/"),
            "USER": parsed.username or "",
            "PASSWORD": parsed.password or "",
            "HOST": parsed.hostname or "",
            "PORT": parsed.port or 5432,
            "CONN_MAX_AGE": DB_CONN_MAX_AGE,
            "CONN_HEALTH_CHECKS": True,
        }
    raise ValueError(f"Unsupported DATABASE_URL scheme: {parsed.scheme}")


if os.getenv("DATABASE_URL"):
    DATABASES = {"default": database_from_url(os.environ["DATABASE_URL"])}
else:
    # SQLite is a local-development convenience only. Production fails fast without
    # DATABASE_URL (see the bottom of this module); anything else gets a loud warning so the
    # behavioral gap vs PostgreSQL (constraint timing, locking) is never a silent surprise.
    if ENVIRONMENT not in {"development", "test"}:
        import warnings

        warnings.warn(f"Using SQLite fallback in ENVIRONMENT={ENVIRONMENT}; set DATABASE_URL to PostgreSQL.", stacklevel=1)
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }


# Password validation
# https://docs.djangoproject.com/en/6.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

AUTH_USER_MODEL = "accounts.User"
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
]


LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
# WhiteNoise serves collected static from gunicorn in production (no separate web server /
# CDN required). CompressedStaticFilesStorage (not the Manifest variant) avoids requiring a
# collectstatic manifest at template-render time, so dev/tests work without collectstatic.
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedStaticFilesStorage"},
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

SESSION_ENGINE = "django.contrib.sessions.backends.cached_db"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = env_bool("DJANGO_SECURE_COOKIES", ENVIRONMENT == "production")
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = SESSION_COOKIE_SECURE
SECURE_SSL_REDIRECT = env_bool("DJANGO_SECURE_SSL_REDIRECT", ENVIRONMENT == "production")
# Load balancers commonly probe liveness/readiness over plain HTTP; don't 301 them.
SECURE_REDIRECT_EXEMPT = [r"^healthz$", r"^readyz$", r"^metrics$", r"^internal/"]
# Bearer token guarding /metrics (set in production; empty = open, for local scraping only).
METRICS_TOKEN = os.getenv("METRICS_TOKEN", "")
# Bearer token guarding the Alertmanager webhook sink at /internal/alerts.
ALERT_WEBHOOK_TOKEN = os.getenv("ALERT_WEBHOOK_TOKEN", "")
SECURE_HSTS_SECONDS = int(os.getenv("DJANGO_HSTS_SECONDS", "31536000" if ENVIRONMENT == "production" else "0"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = ENVIRONMENT == "production"
SECURE_HSTS_PRELOAD = ENVIRONMENT == "production"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
# Only trust the proxy's X-Forwarded-Proto when explicitly deployed behind a known
# TLS-terminating proxy; trusting it unconditionally lets clients spoof request.is_secure().
if env_bool("DJANGO_TRUST_PROXY_SSL_HEADER", ENVIRONMENT == "production"):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
X_FRAME_OPTIONS = "DENY"
# Content-Security-Policy emitted by SecurityEnforcementMiddleware. Self-only by default;
# no third-party CDNs (HTMX is vendored under static/).
CONTENT_SECURITY_POLICY = os.getenv(
    "DJANGO_CSP",
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
)

# API CSRF failures return the stable JSON error envelope instead of Django's HTML 403.
CSRF_FAILURE_VIEW = "api.views.csrf_failure"

CACHE_URL = os.getenv("REDIS_URL")
if CACHE_URL:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": CACHE_URL,
            "TIMEOUT": 300,
        }
    }
else:
    CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}

EMAIL_BACKEND = os.getenv("DJANGO_EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend")
DEFAULT_FROM_EMAIL = os.getenv("DJANGO_DEFAULT_FROM_EMAIL", "security@example.test")
# Absolute base URL used by the worker to build actionable links (reset/verification).
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")
# How long an outbox event may sit in PROCESSING before the reaper requeues it.
OUTBOX_PROCESSING_TIMEOUT_MINUTES = int(os.getenv("OUTBOX_PROCESSING_TIMEOUT_MINUTES", "15"))

LOGIN_URL = "web:login"
LOGIN_REDIRECT_URL = "web:dashboard"
LOGOUT_REDIRECT_URL = "web:login"

# Defaults used when auto-provisioning the global SecurityPolicy row (see
# security_policies.services.get_policy) so these env knobs are authoritative, not dead.
DEFAULT_IDLE_TIMEOUT_MINUTES = int(os.getenv("DEFAULT_IDLE_TIMEOUT_MINUTES", "30"))
DEFAULT_ABSOLUTE_TIMEOUT_HOURS = int(os.getenv("DEFAULT_ABSOLUTE_TIMEOUT_HOURS", "12"))
RECENT_AUTH_WINDOW_MINUTES = int(os.getenv("RECENT_AUTH_WINDOW_MINUTES", "15"))

# Awaiting-2FA intermediate state and login throttling / lockout (Redis-backed via CACHES).
AWAITING_2FA_TTL_MINUTES = int(os.getenv("AWAITING_2FA_TTL_MINUTES", "5"))
AWAITING_2FA_MAX_ATTEMPTS = int(os.getenv("AWAITING_2FA_MAX_ATTEMPTS", "5"))
STEP_UP_MAX_ATTEMPTS = int(os.getenv("STEP_UP_MAX_ATTEMPTS", "5"))
# When the cache backend cannot be reached, protected auth flows fail closed.
THROTTLE_FAIL_CLOSED = env_bool("THROTTLE_FAIL_CLOSED", ENVIRONMENT in DEPLOY_ENVIRONMENTS)
# Minimum interval before the enforcement middleware re-persists ActiveSession.last_seen_at.
LAST_SEEN_WRITE_THROTTLE_SECONDS = int(os.getenv("LAST_SEEN_WRITE_THROTTLE_SECONDS", "60"))

TOTP_ENCRYPTION_KEY = os.getenv("TOTP_ENCRYPTION_KEY", "")
# Breached-password screening (HIBP k-anonymity). Toggle off for hermetic/offline testing.
BREACH_SCREENING_ENABLED = env_bool("BREACH_SCREENING_ENABLED", True)
# Consecutive HIBP failures before the circuit breaker trips (fail-open + alert).
HIBP_BREAKER_THRESHOLD = int(os.getenv("HIBP_BREAKER_THRESHOLD", "5"))
# Global ceiling on requests to /api/ per principal (authenticated user, else IP) per minute.
API_RATE_LIMIT_PER_MINUTE = int(os.getenv("API_RATE_LIMIT_PER_MINUTE", "600"))

# Log DB queries slower than this many ms (0 disables the middleware entirely).
DB_SLOW_QUERY_MS = int(os.getenv("DB_SLOW_QUERY_MS", "0"))

# Feature flags for safe rollout. Any env var FLAG_<NAME>=true|false becomes flag "<name>".
FEATURE_FLAGS = {
    key[len("FLAG_"):].lower(): value.lower() in {"1", "true", "yes", "on"}
    for key, value in os.environ.items()
    if key.startswith("FLAG_")
}
HIBP_RANGE_API_URL = os.getenv("HIBP_RANGE_API_URL", "https://api.pwnedpasswords.com/range/")
OIDC_JWT_ALGORITHMS = split_csv(os.getenv("OIDC_JWT_ALGORITHMS", "RS256,ES256,PS256,EdDSA"))
WEBAUTHN_RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
WEBAUTHN_RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "Full Auth")
WEBAUTHN_EXPECTED_ORIGINS = split_csv(os.getenv("WEBAUTHN_EXPECTED_ORIGINS", "http://localhost:8000"))

# Structured logging with request-id correlation (see config.middleware).
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"request_id": {"()": "config.middleware.RequestIDLogFilter"}},
    "formatters": {
        "structured": {"format": "%(asctime)s %(levelname)s [%(request_id)s] %(name)s %(message)s"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "filters": ["request_id"], "formatter": "structured"},
    },
    "root": {"handlers": ["console"], "level": os.getenv("DJANGO_LOG_LEVEL", "INFO")},
}

# Optional error tracking; only initialized when the SDK and DSN are both present.
SENTRY_DSN = os.getenv("SENTRY_DSN", "")
if SENTRY_DSN:
    try:
        import sentry_sdk

        sentry_sdk.init(dsn=SENTRY_DSN, environment=ENVIRONMENT, send_default_pii=False, traces_sample_rate=0.0)
    except ImportError:
        pass

if TESTING:
    # Fast, hermetic test runs: cheap password hashing and no live HIBP calls.
    PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    BREACH_SCREENING_ENABLED = False

if ENVIRONMENT in DEPLOY_ENVIRONMENTS:
    missing = [
        name
        for name in (
            "DJANGO_SECRET_KEY",
            "DATABASE_URL",
            "REDIS_URL",
            "TOTP_ENCRYPTION_KEY",
            "DJANGO_ALLOWED_HOSTS",
            "PUBLIC_BASE_URL",
            "METRICS_TOKEN",
            "ALERT_WEBHOOK_TOKEN",
            "WEBAUTHN_RP_ID",
        )
        if not os.getenv(name)
    ]
    if missing:
        raise RuntimeError(f"Missing required {ENVIRONMENT} settings: {', '.join(missing)}")
    weak_secrets = {"change-me", "dev-only-change-me", "changeme", "secret", "test"}
    if os.getenv("DJANGO_SECRET_KEY", "").strip().lower() in weak_secrets:
        raise RuntimeError("DJANGO_SECRET_KEY must not be a placeholder value in production/staging")
    if DEBUG:
        raise RuntimeError("DJANGO_DEBUG must be false in production/staging")
    if not (SESSION_COOKIE_SECURE and CSRF_COOKIE_SECURE):
        raise RuntimeError("Secure cookies must be enabled (DJANGO_SECURE_COOKIES=true)")
    if "*" in ALLOWED_HOSTS or "localhost" in ALLOWED_HOSTS:
        raise RuntimeError("DJANGO_ALLOWED_HOSTS must be real hostnames in production/staging")
    if not CSRF_TRUSTED_ORIGINS:
        raise RuntimeError("DJANGO_CSRF_TRUSTED_ORIGINS must be configured in production/staging")
    if PUBLIC_BASE_URL.startswith("http://localhost"):
        raise RuntimeError("PUBLIC_BASE_URL must be the real public URL in production/staging")
    if not WEBAUTHN_EXPECTED_ORIGINS or "localhost" in WEBAUTHN_EXPECTED_ORIGINS:
        raise RuntimeError("WEBAUTHN_EXPECTED_ORIGINS must list real origins in production/staging")

# Comma-separated Django group names org admins may assign (superusers may assign any group).
ASSIGNABLE_GROUP_NAMES = split_csv(os.getenv("ASSIGNABLE_GROUP_NAMES", "member,staff,auditor,admin"))
