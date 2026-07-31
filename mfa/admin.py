"""Django admin registrations for mfa."""
from django.contrib import admin

from .models import BackupCode, EmailOTPChallenge, MFADevice, TOTPDevice, WebAuthnChallenge, WebAuthnCredential

admin.site.register(MFADevice)
admin.site.register(TOTPDevice)
admin.site.register(EmailOTPChallenge)
admin.site.register(BackupCode)
admin.site.register(WebAuthnCredential)
admin.site.register(WebAuthnChallenge)

# Register your models here.
