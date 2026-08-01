"""Django admin registrations for security_events."""
from django.contrib import admin

from .models import AuditEvent, SecurityRiskEvent


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ("event_type", "actor", "target_user", "organization", "timestamp")
    search_fields = ("event_type", "actor__username", "target_user__username")
    readonly_fields = [field.name for field in AuditEvent._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.register(SecurityRiskEvent)

# Register your models here.
