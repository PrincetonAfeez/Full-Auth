"""Django admin registrations for notifications."""
from django.contrib import admin

from .models import NotificationDelivery, OutboxEvent

admin.site.register(OutboxEvent)
admin.site.register(NotificationDelivery)

# Register your models here.
