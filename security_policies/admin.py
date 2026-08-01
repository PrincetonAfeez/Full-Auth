"""Django admin registrations for security_policies."""
from django.contrib import admin

from .models import SecurityPolicy

admin.site.register(SecurityPolicy)

# Register your models here.
