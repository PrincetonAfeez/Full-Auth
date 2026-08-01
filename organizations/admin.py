"""Django admin registrations for organizations."""
from django.contrib import admin

from .models import Invitation, Organization, OrganizationMembership, RoleAssignment

admin.site.register(Organization)
admin.site.register(OrganizationMembership)
admin.site.register(Invitation)
admin.site.register(RoleAssignment)

# Register your models here.
