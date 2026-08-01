"""Django admin registrations for sessions."""
from django.contrib import admin

from .models import ActiveSession, DeviceRiskEvent, TrustedDevice

admin.site.register(ActiveSession)
admin.site.register(TrustedDevice)
admin.site.register(DeviceRiskEvent)

# Register your models here.
