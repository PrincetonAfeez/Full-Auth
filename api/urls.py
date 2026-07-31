"""URL routes for the api app."""
from django.urls import path

from . import views

app_name = "api"

urlpatterns = [
    # auth
    path("auth/status/", views.auth_status, name="auth_status"),
    path("auth/login/", views.auth_login, name="auth_login"),
    path("auth/logout/", views.auth_logout, name="auth_logout"),
    path("auth/2fa/verify/", views.auth_2fa_verify, name="auth_2fa_verify"),
    path("auth/password-reset/request/", views.password_reset_request_view, name="password_reset_request"),
    path("auth/password-reset/complete/", views.password_reset_complete_view, name="password_reset_complete"),
    path("auth/email-verification/complete/", views.email_verification_complete_view, name="email_verification_complete"),
    path("auth/email-verification/request/", views.email_verification_request_view, name="email_verification_request"),
    # me
    path("me/", views.me, name="me"),
    path("me/security/", views.me_security, name="me_security"),
    path("me/sessions/", views.sessions, name="sessions"),
    path("me/sessions/<int:session_id>/revoke/", views.revoke_session_view, name="revoke_session"),
    path("me/backup-codes/regenerate/", views.regenerate_backup_codes_view, name="regenerate_backup_codes"),
    path("me/2fa/<int:factor_id>/disable/", views.disable_factor_view, name="disable_factor"),
    path("me/2fa/totp/enable/", views.totp_enable_view, name="totp_enable"),
    path("me/2fa/totp/confirm/", views.totp_confirm_view, name="totp_confirm"),
    path("me/2fa/email/enable/", views.email_otp_enable_view, name="email_otp_enable"),
    path("me/export/", views.me_export, name="me_export"),
    path("me/password/change/", views.me_password_change, name="me_password_change"),
    path("me/email/change/", views.me_email_change, name="me_email_change"),
    path("me/notification-preferences/", views.notification_preferences, name="notification_preferences"),
    path("me/notification-preferences/set/", views.set_notification_preference, name="set_notification_preference"),
    # trusted devices
    path("me/trusted-devices/", views.trusted_devices, name="trusted_devices"),
    path("me/trusted-devices/trust/", views.trust_current_device, name="trust_current_device"),
    path("me/trusted-devices/<int:device_id>/revoke/", views.revoke_trusted_device_view, name="revoke_trusted_device"),
    # webauthn / passkeys
    path("me/2fa/webauthn/register/options/", views.webauthn_register_options, name="webauthn_register_options"),
    path("me/2fa/webauthn/register/verify/", views.webauthn_register_verify, name="webauthn_register_verify"),
    path("auth/2fa/webauthn/register/options/", views.auth_webauthn_register_options, name="auth_webauthn_register_options"),
    path("auth/2fa/webauthn/register/verify/", views.auth_webauthn_register_verify, name="auth_webauthn_register_verify"),
    path("auth/2fa/webauthn/options/", views.webauthn_assertion_options, name="webauthn_assertion_options"),
    path("auth/2fa/webauthn/verify/", views.webauthn_assertion_verify, name="webauthn_assertion_verify"),
    path("me/step-up/begin/", views.step_up_begin, name="step_up_begin"),
    path("me/step-up/verify/", views.step_up_verify, name="step_up_verify"),
    path("me/step-up/webauthn/options/", views.step_up_webauthn_options, name="step_up_webauthn_options"),
    path("me/step-up/webauthn/verify/", views.step_up_webauthn_verify, name="step_up_webauthn_verify"),
    # tenant-scoped
    path("organizations/<slug:slug>/members/", views.organization_members, name="organization_members"),
    path("organizations/<slug:slug>/policy/", views.org_update_policy, name="org_update_policy"),
    path("organizations/<slug:slug>/invitations/", views.org_invite, name="org_invite"),
    path("organizations/<slug:slug>/members/<int:user_id>/role/", views.org_change_member_role, name="org_change_member_role"),
    path("organizations/<slug:slug>/members/<int:user_id>/remove/", views.org_remove_member, name="org_remove_member"),
    path("organizations/invitations/accept/", views.org_accept_invitation, name="org_accept_invitation"),
    # admin
    path("admin/organizations/<slug:slug>/suspend/", views.admin_org_suspend, name="admin_org_suspend"),
    path("admin/organizations/<slug:slug>/close/", views.admin_org_close, name="admin_org_close"),
    path("admin/users/", views.admin_users, name="admin_users"),
    path("admin/users/<int:user_id>/sessions/revoke/", views.admin_revoke_user_sessions, name="admin_revoke_user_sessions"),
    path("admin/users/<int:user_id>/deactivate/", views.admin_deactivate_user, name="admin_deactivate_user"),
    path("admin/users/<int:user_id>/erase/", views.admin_erase_user, name="admin_erase_user"),
    path("admin/users/<int:user_id>/roles/assign/", views.admin_assign_role, name="admin_assign_role"),
    path("admin/audit-events/", views.admin_audit_events, name="admin_audit_events"),
    path("admin/security-events/", views.admin_security_events, name="admin_security_events"),
]
