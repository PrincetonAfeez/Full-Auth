"""URL routes for the sso app."""
from django.urls import path

from . import views

app_name = "sso"

urlpatterns = [
    path("<slug:slug>/begin/", views.sso_begin, name="begin"),
    path("<slug:slug>/callback/", views.sso_callback, name="callback"),
]
