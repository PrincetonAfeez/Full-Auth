"""Business logic and service layer for sso."""
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from security_events.services import record_audit_event

from .connectors import ExternalIdentity
from .models import FederatedIdentity, IdentityProvider

User = get_user_model()


class SSOError(Exception):
    pass


@transaction.atomic
def resolve_user(*, provider: IdentityProvider, external: ExternalIdentity):
    """
    Map an external identity to a local user (extension point). Precedence:
      1. Existing FederatedIdentity for (provider, subject) -> that user.
      2. auto_link_verified_email AND the IdP asserts a verified matching email -> link.
         (Never link on an unverified external email -- that would be account takeover.)
      3. auto_provision -> create a new local user.
    Otherwise refuse.
    """
    link = FederatedIdentity.objects.select_for_update().filter(provider=provider, subject=external.subject).first()
    if link:
        link.last_login_at = timezone.now()
        link.save(update_fields=["last_login_at"])
        return link.user

    email = (external.email or "").lower()
    if provider.auto_link_verified_email and external.email_verified and email:
        existing = User.objects.filter(email=email).first()
        if existing:
            FederatedIdentity.objects.create(
                user=existing, provider=provider, subject=external.subject, email=email, last_login_at=timezone.now()
            )
            record_audit_event(actor=existing, target_user=existing, event_type="sso.identity.linked",
                               metadata={"provider": provider.slug})
            return existing

    if not provider.auto_provision:
        raise SSOError("No local account is linked to this identity and provisioning is disabled.")

    if email and User.objects.filter(email=email).exists():
        # An unlinked local account already owns this email; refuse silent takeover.
        raise SSOError("An account already exists for this email; link it before SSO sign-in.")

    username = f"sso_{provider.slug}_{external.subject}"[:150]
    user = User.objects.create_user(
        username=username, email=email or f"{username}@sso.invalid",
        status=User.Status.ACTIVE, email_verified_at=timezone.now() if external.email_verified else None,
    )
    user.set_unusable_password()  # authenticated by the IdP, no local password
    user.save(update_fields=["password"])
    FederatedIdentity.objects.create(
        user=user, provider=provider, subject=external.subject, email=email, last_login_at=timezone.now()
    )
    record_audit_event(actor=user, target_user=user, event_type="sso.user.provisioned",
                       metadata={"provider": provider.slug})
    return user


def ensure_org_sso_access(*, provider: IdentityProvider, user) -> None:
    """
    Org-scoped IdPs require an active org membership. When auto_provision is enabled,
    missing membership is created on first SSO; otherwise login is refused.
    """
    if not provider.organization_id:
        return

    from organizations.models import OrganizationMembership

    org = provider.organization
    if OrganizationMembership.objects.active().filter(organization=org, user=user).exists():
        return

    if provider.auto_provision:
        OrganizationMembership.objects.create(
            organization=org,
            user=user,
            role=OrganizationMembership.Role.MEMBER,
            status=OrganizationMembership.Status.ACTIVE,
            accepted_at=timezone.now(),
        )
        record_audit_event(
            actor=user,
            target_user=user,
            organization=org,
            event_type="sso.membership.auto_added",
            metadata={"provider": provider.slug},
        )
        return

    record_audit_event(
        actor=user,
        target_user=user,
        organization=org,
        event_type="sso.org_access_denied",
        metadata={"provider": provider.slug},
    )
    raise SSOError("You are not a member of this organization.")
