"""Django admin registrations for accounts."""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import EmailAddress, User


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ("Security", {"fields": ("status", "email_verified_at", "force_strong_mfa", "security_stamp")}),
    )
    list_display = ("username", "email", "status", "email_verified_at", "is_staff")
    list_filter = ("status", "is_staff", "is_superuser")


@admin.register(EmailAddress)
class EmailAddressAdmin(admin.ModelAdmin):
    list_display = ("email", "user", "is_primary", "verified_at")
    search_fields = ("email", "user__username")

# Register your models here.
