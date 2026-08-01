"""Business logic and service layer for security_policies."""
from dataclasses import dataclass

from django.conf import settings

from organizations.models import Organization, OrganizationMembership

from .models import SecurityPolicy

PRIVILEGED_ROLES = {
    OrganizationMembership.Role.OWNER,
    OrganizationMembership.Role.ADMIN,
    OrganizationMembership.Role.STAFF,
}

STRONG_FACTORS = {"totp", "webauthn"}


@dataclass(frozen=True)
class EffectivePolicy:
    """
    The session/recent-auth policy that actually applies to a user: the STRICTEST of the
    global default and every active-org policy the user belongs to. This is what session
    creation, the enforcement middleware, and recent-auth read -- so per-org policy fields
    are finally honored (not just the global default).
    """

    idle_timeout_minutes: int
    absolute_timeout_hours: int
    recent_auth_window_minutes: int
    recent_auth_scope: str
    trusted_device_duration_days: int
    trusted_device_skips_2fa: bool
    lockout_threshold: int
    lockout_duration_minutes: int
    email_otp_max_verify_attempts: int
    allowed_2fa_methods: tuple[str, ...]
    policy_version: int


def _applicable_policies(user) -> list[SecurityPolicy]:
    policies = [get_policy()]
    if user is not None and getattr(user, "is_authenticated", False):
        memberships = (
            OrganizationMembership.objects.active()
            .filter(user=user, organization__status=Organization.Status.ACTIVE)
            .select_related("organization__security_policy")
        )
        for membership in memberships:
            policy = getattr(membership.organization, "security_policy", None)
            if policy is not None:
                policies.append(policy)
    return policies


def get_effective_policy(user=None) -> EffectivePolicy:
    # Request-scoped memoization: request.user is a single instance per request, so caching on
    # it collapses the repeated middleware/recent-auth lookups to ONE query per request without
    # any cross-request staleness (a new request gets a fresh user instance -> recomputed).
    cached = getattr(user, "_effective_policy_cache", None) if user is not None else None
    if cached is not None:
        return cached
    ps = _applicable_policies(user)
    allowed_methods = set(ps[0].allowed_2fa_methods)
    for p in ps[1:]:
        allowed_methods &= set(p.allowed_2fa_methods)
    if not allowed_methods and len(ps) > 1:
        from security_events.services import detect_risk_event

        detect_risk_event(
            event_type="policy.allowed_2fa_methods_empty",
            severity="high",
            user=user if user is not None and getattr(user, "is_authenticated", False) else None,
            details={"org_policy_count": len(ps) - 1},
        )
        allowed_methods = set(ps[0].allowed_2fa_methods)
    policy = EffectivePolicy(
        idle_timeout_minutes=min(p.idle_timeout_minutes for p in ps),
        absolute_timeout_hours=min(p.absolute_timeout_hours for p in ps),
        recent_auth_window_minutes=min(p.recent_auth_window_minutes for p in ps),
        recent_auth_scope=("per_action" if any(p.recent_auth_scope == "per_action" for p in ps) else "global"),
        trusted_device_duration_days=min(p.trusted_device_duration_days for p in ps),
        trusted_device_skips_2fa=all(p.trusted_device_skips_2fa for p in ps),
        lockout_threshold=min(p.lockout_threshold for p in ps),
        lockout_duration_minutes=max(p.lockout_duration_minutes for p in ps),
        email_otp_max_verify_attempts=min(p.email_otp_max_verify_attempts for p in ps),
        allowed_2fa_methods=tuple(sorted(allowed_methods)),
        policy_version=sum(p.policy_version for p in ps),
    )
    if user is not None:
        try:
            user._effective_policy_cache = policy
        except (AttributeError, TypeError):
            pass
    return policy


def get_policy(organization: Organization | None = None) -> SecurityPolicy:
    if organization:
        policy = getattr(organization, "security_policy", None)
        if policy:
            return policy
    # Seed the global default policy from the environment-driven settings so those knobs
    # are authoritative rather than dead configuration.
    policy, _ = SecurityPolicy.objects.get_or_create(
        organization=None,
        defaults={
            "idle_timeout_minutes": settings.DEFAULT_IDLE_TIMEOUT_MINUTES,
            "absolute_timeout_hours": settings.DEFAULT_ABSOLUTE_TIMEOUT_HOURS,
            "recent_auth_window_minutes": settings.RECENT_AUTH_WINDOW_MINUTES,
        },
    )
    return policy


# Fields an org admin may tune on their org's SecurityPolicy.
EDITABLE_POLICY_FIELDS = {
    "require_2fa_for_admins": bool,
    "require_2fa_for_staff": bool,
    "idle_timeout_minutes": int,
    "absolute_timeout_hours": int,
    "trusted_device_duration_days": int,
    "lockout_threshold": int,
    "lockout_duration_minutes": int,
    "email_otp_max_verify_attempts": int,
    "recent_auth_window_minutes": int,
    "trusted_device_skips_2fa": bool,
}


def update_org_policy(*, actor, organization: Organization, changes: dict) -> SecurityPolicy:
    """Create/update an organization's SecurityPolicy (org admin only), bumping policy_version."""
    from organizations.services import require_admin
    from security_events.services import record_audit_event

    require_admin(actor, organization)

    policy = getattr(organization, "security_policy", None)
    if policy is None:
        base = get_policy()  # global defaults
        policy = SecurityPolicy(organization=organization)
        # Copy the FULL configuration from the global default (not just editable fields) so
        # non-editable settings (recent_auth_scope, allowed_2fa_methods, ...) don't silently
        # revert to model defaults.
        skip = {"id", "pk", "organization", "created_at", "updated_at"}
        for field in SecurityPolicy._meta.fields:
            if field.name not in skip:
                setattr(policy, field.name, getattr(base, field.name))

    applied = {}
    for key, caster in EDITABLE_POLICY_FIELDS.items():
        if key in changes:
            try:
                value = caster(changes[key])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid value for {key}") from exc
            if caster is int and value < 0:
                raise ValueError(f"{key} must be non-negative")
            setattr(policy, key, value)
            applied[key] = value
    if not applied:
        raise ValueError("No editable policy fields provided.")
    policy.policy_version = (policy.policy_version or 1) + 1
    policy.save()
    record_audit_event(
        actor=actor, organization=organization, event_type="security_policy.updated", metadata=applied
    )
    return policy


def role_requires_mfa(role: str, policy: SecurityPolicy) -> bool:
    if role in {OrganizationMembership.Role.OWNER, OrganizationMembership.Role.ADMIN}:
        return policy.require_2fa_for_admins
    if role == OrganizationMembership.Role.STAFF:
        return policy.require_2fa_for_staff
    return False


def validate_factor_policy_for_role(*, role: str, enabled_factor_types: set[str], policy: SecurityPolicy) -> None:
    if not role_requires_mfa(role, policy):
        return
    if role in PRIVILEGED_ROLES and not (enabled_factor_types & STRONG_FACTORS):
        raise ValueError("Privileged roles require TOTP or WebAuthn; email OTP cannot be the sole factor.")
