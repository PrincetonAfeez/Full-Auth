"""Business logic and service layer for organizations."""
import hashlib
from datetime import timedelta

from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils import timezone

from accounts.models import User
from notifications.services import emit_outbox_event
from security_events.services import record_audit_event

from .models import Invitation, Organization, OrganizationMembership, RoleAssignment

ROLE_RANK = {
    OrganizationMembership.Role.MEMBER: 10,
    OrganizationMembership.Role.AUDITOR: 15,
    OrganizationMembership.Role.STAFF: 20,
    OrganizationMembership.Role.ADMIN: 30,
    OrganizationMembership.Role.OWNER: 40,
}


def role_rank(role: str) -> int:
    return ROLE_RANK.get(role, 0)


def validate_membership_role(role: str) -> None:
    if role not in OrganizationMembership.Role.values:
        raise ValueError(f"Invalid role: {role}")


def organization_active(organization: Organization) -> bool:
    return organization.status == Organization.Status.ACTIVE


def require_active_organization(organization: Organization) -> None:
    if not organization_active(organization):
        raise PermissionDenied("Organization is not active.")


def verify_tenant_scope(user: User, organization: Organization) -> bool:
    """
    Defense-in-depth (ADR-0017): confirm the requester is an active member of the organization
    (or a platform admin) BEFORE any tenant-scoped object is returned/mutated -- a second layer
    behind the org-scoped queryset filter, so a missed filter can't leak across tenants.
    """
    if user.is_superuser:
        return True
    return OrganizationMembership.objects.active().filter(user=user, organization=organization).exists()


def has_role_at_least(user: User, organization: Organization, role: str) -> bool:
    if user.is_superuser:
        return True
    # A suspended/closed org grants no role-based access to ordinary members.
    if not organization_active(organization):
        return False
    membership = OrganizationMembership.objects.active().filter(user=user, organization=organization).first()
    if not membership:
        return False
    return role_rank(membership.role) >= ROLE_RANK[role]


def _actor_rank(actor: User, organization: Organization) -> int:
    if actor.is_superuser:
        return max(ROLE_RANK.values())
    membership = OrganizationMembership.objects.active().filter(user=actor, organization=organization).first()
    return role_rank(membership.role) if membership else 0


def require_admin(actor: User, organization: Organization) -> None:
    if not has_role_at_least(actor, organization, OrganizationMembership.Role.ADMIN):
        raise PermissionDenied("Requires organization admin/owner.")


def can_manage_user(actor: User, target: User) -> bool:
    """
    True if actor may administer target: platform admin, or an admin/owner of a shared org
    whose rank STRICTLY EXCEEDS the target's role in that org. The rank check prevents an
    admin from deactivating/DoS-ing an owner (destructive actions must respect the hierarchy).
    """
    if actor.is_superuser:
        return True
    admin_memberships = OrganizationMembership.objects.active().filter(
        user=actor, role__in=[OrganizationMembership.Role.ADMIN, OrganizationMembership.Role.OWNER]
    )
    for actor_m in admin_memberships:
        target_m = OrganizationMembership.objects.active().filter(
            user=target, organization=actor_m.organization
        ).first()
        if target_m and role_rank(actor_m.role) > role_rank(target_m.role):
            return True
    return False


# --- organization lifecycle (platform-admin) ---------------------------------

def _set_org_status(*, actor: User, organization: Organization, status: str, event: str) -> Organization:
    if not actor.is_superuser:
        raise PermissionDenied("Organization lifecycle changes require a platform administrator.")
    organization.status = status
    organization.save(update_fields=["status", "updated_at"])
    record_audit_event(actor=actor, organization=organization, event_type=event, metadata={"status": status})
    return organization


@transaction.atomic
def suspend_organization(*, actor: User, organization: Organization) -> Organization:
    return _set_org_status(
        actor=actor, organization=organization, status=Organization.Status.SUSPENDED,
        event="organization.suspended",
    )


@transaction.atomic
def reactivate_organization(*, actor: User, organization: Organization) -> Organization:
    return _set_org_status(
        actor=actor, organization=organization, status=Organization.Status.ACTIVE,
        event="organization.reactivated",
    )


@transaction.atomic
def close_organization(*, actor: User, organization: Organization) -> Organization:
    """
    Close (offboard) an org: mark closed and remove all memberships. Deliberate decision: each
    member's GLOBAL security_stamp is bumped, which forces re-authentication across all of that
    user's orgs -- not just this one. For a rare, high-impact offboarding this fail-safe (stop
    all derived access immediately) is preferred over leaving stale sessions; per-org-scoped
    invalidation would require org-scoped session records, which we intentionally don't keep.
    """
    _set_org_status(
        actor=actor, organization=organization, status=Organization.Status.CLOSED, event="organization.closed",
    )
    for membership in OrganizationMembership.objects.filter(organization=organization).exclude(
        status=OrganizationMembership.Status.REMOVED
    ).select_related("user"):
        membership.status = OrganizationMembership.Status.REMOVED
        membership.removed_at = timezone.now()
        membership.save(update_fields=["status", "removed_at"])
        membership.user.bump_security_stamp()
        membership.user.save(update_fields=["security_stamp"])
    # Purge tenant-scoped data (spec §22 offboarding); the append-only audit trail is preserved.
    Invitation.objects.filter(organization=organization).delete()
    RoleAssignment.objects.filter(organization=organization, revoked_at__isnull=True).update(revoked_at=timezone.now())
    from security_policies.models import SecurityPolicy

    SecurityPolicy.objects.filter(organization=organization).delete()
    from sso.models import FederatedIdentity, IdentityProvider

    provider_ids = list(IdentityProvider.objects.filter(organization=organization).values_list("pk", flat=True))
    if provider_ids:
        FederatedIdentity.objects.filter(provider_id__in=provider_ids).delete()
    IdentityProvider.objects.filter(organization=organization).delete()
    return organization


@transaction.atomic
def remove_membership(*, actor: User, membership: OrganizationMembership) -> OrganizationMembership:
    require_admin(actor, membership.organization)
    # Mirror change_membership_role: cannot act on a member ranked ABOVE you (an admin must
    # not be able to eject an owner). Superuser has max rank, so it can still remove owners.
    if role_rank(membership.role) > _actor_rank(actor, membership.organization):
        raise PermissionDenied("Cannot remove a member ranked above your own level.")
    if membership.role == OrganizationMembership.Role.OWNER:
        others = (
            OrganizationMembership.objects.active()
            .filter(organization=membership.organization, role=OrganizationMembership.Role.OWNER)
            .exclude(pk=membership.pk)
            .exists()
        )
        if not others:
            raise PermissionDenied("Cannot remove the last remaining owner.")
    membership.status = OrganizationMembership.Status.REMOVED
    membership.removed_at = timezone.now()
    membership.save(update_fields=["status", "removed_at"])
    membership.user.bump_security_stamp()
    membership.user.save(update_fields=["security_stamp"])
    record_audit_event(
        actor=actor, target_user=membership.user, organization=membership.organization,
        event_type="organization.membership.removed",
    )
    return membership


@transaction.atomic
def invite_user(*, actor: User, organization: Organization, email: str, role: str) -> tuple[Invitation, str]:
    from django.core.exceptions import ValidationError as DjangoValidationError
    from django.core.validators import validate_email

    require_active_organization(organization)
    require_admin(actor, organization)
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("Email is required.")
    try:
        validate_email(email)
    except DjangoValidationError as exc:
        raise ValueError("Invalid email address.") from exc
    validate_membership_role(role)
    # Cannot invite at a role higher than your own (no privilege escalation).
    if role_rank(role) > _actor_rank(actor, organization):
        raise PermissionDenied("Cannot invite at a role above your own.")
    Invitation.objects.filter(
        organization=organization,
        email=email,
        accepted_at__isnull=True,
        revoked_at__isnull=True,
        expires_at__gt=timezone.now(),
    ).update(revoked_at=timezone.now())
    token = Invitation.make_token()
    invitation = Invitation.objects.create(
        organization=organization,
        email=email,
        intended_role=role,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        expires_at=timezone.now() + timedelta(days=7),
        inviter=actor,
    )
    record_audit_event(
        actor=actor,
        organization=organization,
        event_type="organization.invitation.created",
        metadata={"email": email, "role": role},
    )
    return invitation, token


@transaction.atomic
def accept_invitation(*, user: User, token: str) -> OrganizationMembership:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    invitation = Invitation.objects.select_for_update().filter(token_hash=token_hash).first()
    if invitation is None:
        raise ValueError("Invitation is no longer valid")
    if invitation.revoked_at or invitation.accepted_at or invitation.expires_at <= timezone.now():
        raise ValueError("Invitation is no longer valid")
    if invitation.organization.status != Organization.Status.ACTIVE:
        raise ValueError("Organization is not active")
    # The invitation is bound to a specific email; only that account, with a VERIFIED email,
    # may accept it (prevents claiming a role via an unverified address you don't control).
    if invitation.email.lower() != user.email.lower():
        raise PermissionDenied("This invitation was issued to a different email address.")
    if not user.email_verified:
        raise PermissionDenied("Verify your email address before accepting an invitation.")

    membership, created = OrganizationMembership.objects.select_for_update().get_or_create(
        organization=invitation.organization,
        user=user,
        defaults={"role": invitation.intended_role, "created_by": invitation.inviter},
    )
    if created:
        membership.role = invitation.intended_role
    else:
        # Never silently downgrade an existing member; only elevate to the invited role.
        if role_rank(invitation.intended_role) > role_rank(membership.role):
            membership.role = invitation.intended_role
    membership.activate()
    membership.save(update_fields=["role", "status", "accepted_at"])
    invitation.accepted_at = timezone.now()
    invitation.save(update_fields=["accepted_at"])
    if role_rank(membership.role) >= ROLE_RANK[OrganizationMembership.Role.STAFF]:
        user.bump_security_stamp()
        user.save(update_fields=["security_stamp"])
    record_audit_event(
        actor=user,
        target_user=user,
        organization=invitation.organization,
        event_type="organization.invitation.accepted",
    )
    return membership


@transaction.atomic
def assign_role(*, actor: User, user: User, organization: Organization | None, group_name: str) -> RoleAssignment:
    from django.conf import settings

    if not group_name:
        raise ValueError("Group name is required.")
    if not actor.is_superuser and group_name not in settings.ASSIGNABLE_GROUP_NAMES:
        raise PermissionDenied("Group is not assignable.")
    # Global/platform role grants require platform admin; org-scoped grants require org admin.
    if organization is None:
        if not actor.is_superuser:
            raise PermissionDenied("Global role assignment requires a platform admin.")
    else:
        require_admin(actor, organization)
        if not OrganizationMembership.objects.active().filter(organization=organization, user=user).exists():
            raise PermissionDenied("Target user is not an active member of this organization.")
    group, _ = Group.objects.get_or_create(name=group_name)
    assignment = RoleAssignment.objects.create(user=user, organization=organization, group=group, assigned_by=actor)
    user.bump_security_stamp()
    user.save(update_fields=["security_stamp"])
    record_audit_event(
        actor=actor,
        target_user=user,
        organization=organization,
        event_type="authorization.role.assigned",
        metadata={"group": group_name},
    )
    return assignment


@transaction.atomic
def change_membership_role(*, actor: User, membership: OrganizationMembership, role: str) -> OrganizationMembership:
    organization = membership.organization
    require_admin(actor, organization)
    validate_membership_role(role)
    actor_rank = _actor_rank(actor, organization)
    # An admin cannot grant a role above their own, nor modify someone ranked above them.
    if role_rank(role) > actor_rank or role_rank(membership.role) > actor_rank:
        raise PermissionDenied("Cannot change a role above your own level.")
    # Do not allow removing the organization's last owner.
    if membership.role == OrganizationMembership.Role.OWNER and role != OrganizationMembership.Role.OWNER:
        other_owners = (
            OrganizationMembership.objects.active()
            .filter(organization=organization, role=OrganizationMembership.Role.OWNER)
            .exclude(pk=membership.pk)
            .exists()
        )
        if not other_owners:
            raise PermissionDenied("Cannot demote the last remaining owner.")
    membership.role = role
    membership.save(update_fields=["role"])
    membership.user.bump_security_stamp()
    membership.user.save(update_fields=["security_stamp"])
    record_audit_event(
        actor=actor,
        target_user=membership.user,
        organization=membership.organization,
        event_type="organization.membership.role_changed",
        metadata={"role": role},
    )
    emit_outbox_event(
        event_type="organization.membership.role_changed", aggregate_type="user",
        aggregate_id=str(membership.user.pk), payload={"user_id": membership.user.pk, "role": role},
    )
    return membership
