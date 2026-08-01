"""Django admin registrations for passwords."""
from django.contrib import admin

from .models import EmailVerificationChallenge, PasswordResetChallenge

admin.site.register(PasswordResetChallenge)
admin.site.register(EmailVerificationChallenge)

# Register your models here.
