"""Database models for the organizations app."""
import secrets

from django.conf import settings
from django.contrib.auth.models import Group
from django.db import models
from django.utils import timezone


class TenantQuerySet(models.QuerySet):
    def for_organization(self, organization):
        return self.filter(organization=organization)

    def visible_to(self, user, organization=None):
        if not user.is_authenticated:
            return self.none()
        memberships = OrganizationMembership.objects.active().filter(user=user)
        if organization is not None:
            memberships = memberships.filter(organization=organization)
        return self.filter(organization__in=memberships.values("organization"))


class TenantManager(models.Manager.from_queryset(TenantQuerySet)):
    pass


class Organization(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"
        CLOSED = "closed", "Closed"

    name = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)
    status = models.CharField(max_length=24, choices=Status, default=Status.ACTIVE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name


class MembershipQuerySet(TenantQuerySet):
    def active(self):
        return self.filter(status=OrganizationMembership.Status.ACTIVE)


class OrganizationMembership(models.Model):
    class Role(models.TextChoices):
        OWNER = "owner", "Owner"
        ADMIN = "admin", "Admin"
        STAFF = "staff", "Staff"
        MEMBER = "member", "Member"
        AUDITOR = "auditor", "Auditor"

    class Status(models.TextChoices):
        INVITED = "invited", "Invited"
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"
        REMOVED = "removed", "Removed"

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="memberships")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="memberships")
    role = models.CharField(max_length=24, choices=Role, default=Role.MEMBER)
    status = models.CharField(max_length=24, choices=Status, default=Status.INVITED)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="created_memberships"
    )
    accepted_at = models.DateTimeField(null=True, blank=True)
    removed_at = models.DateTimeField(null=True, blank=True)

    objects = TenantManager.from_queryset(MembershipQuerySet)()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["organization", "user"], name="one_membership_per_org_user")
        ]

    def activate(self) -> None:
        self.status = self.Status.ACTIVE
        self.accepted_at = timezone.now()

    def __str__(self) -> str:
        return f"{self.user} @ {self.organization} ({self.role})"


class Invitation(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="invitations")
    email = models.EmailField()
    intended_role = models.CharField(max_length=24, choices=OrganizationMembership.Role, default=OrganizationMembership.Role.MEMBER)
    token_hash = models.CharField(max_length=128, unique=True)
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    inviter = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = TenantManager()

    @classmethod
    def make_token(cls) -> str:
        return secrets.token_urlsafe(32)


class RoleAssignment(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="role_assignments")
    organization = models.ForeignKey(Organization, null=True, blank=True, on_delete=models.CASCADE, related_name="role_assignments")
    group = models.ForeignKey(Group, on_delete=models.PROTECT)
    assigned_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="assigned_roles")
    assigned_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    objects = TenantManager()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "organization", "group"],
                condition=models.Q(revoked_at__isnull=True),
                name="one_active_role_assignment",
            )
        ]

# Create your models here.
