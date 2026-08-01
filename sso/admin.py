"""Django admin registrations for sso."""
from django.contrib import admin

from .models import FederatedIdentity, IdentityProvider


@admin.register(IdentityProvider)
class IdentityProviderAdmin(admin.ModelAdmin):
    list_display = ("slug", "name", "protocol", "organization", "enabled")
    list_filter = ("protocol", "enabled")


@admin.register(FederatedIdentity)
class FederatedIdentityAdmin(admin.ModelAdmin):
    list_display = ("user", "provider", "subject", "last_login_at")
    search_fields = ("subject", "user__username", "email")
