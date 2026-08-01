"""Django app configuration for sso."""
from django.apps import AppConfig


class SsoConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "sso"

    def ready(self):
        from sso.connectors import register_connector
        from sso.oidc_connector import ReferenceOIDCConnector

        register_connector("oidc", ReferenceOIDCConnector())
