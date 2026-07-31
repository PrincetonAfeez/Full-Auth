"""URL routes for the ops app."""
from django.urls import path

from . import views

urlpatterns = [
    path("healthz", views.healthz, name="healthz"),
    path("readyz", views.readyz, name="readyz"),
    path("metrics", views.metrics, name="metrics"),
    path("internal/alerts", views.alerts_webhook, name="alerts_webhook"),
]
