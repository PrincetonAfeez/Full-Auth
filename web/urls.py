"""URL routes for the web app."""
from django.urls import path

from . import console, views

app_name = "web"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("register/", views.register, name="register"),
    path("terms/", views.terms, name="terms"),
    path("privacy/", views.privacy, name="privacy"),
    path("login/", views.login_view, name="login"),
    path("login/2fa/", views.mfa_challenge, name="mfa_challenge"),
    path("login/mfa-enroll/", views.mfa_enroll, name="mfa_enroll"),
    path("logout/", views.logout_view, name="logout"),
    path("security/", views.security_home, name="security"),
    path("security/sessions/<int:session_id>/revoke/", views.revoke_session_web, name="revoke_session"),
    path("security/password/", views.change_password_view, name="change_password"),
    path("security/email/", views.change_email_view, name="change_email"),
    path("security/backup-codes/regenerate/", views.regenerate_backup_codes, name="regenerate_backup_codes"),
    path("security/2fa/totp/", views.enroll_totp, name="enroll_totp"),
    path("security/2fa/email/", views.enroll_email_otp, name="enroll_email_otp"),
    path("security/2fa/<int:factor_id>/disable/", views.disable_factor_web, name="disable_factor"),
    path("security/notifications/", views.notification_preferences_view, name="notification_preferences"),
    path("security/console/", views.admin_console, name="admin_console"),
    # HTMX security console (§21)
    path("console/", console.console_home, name="console"),
    path("console/users/", console.console_users, name="console_users"),
    path("console/orgs/", console.console_orgs, name="console_orgs"),
    path("console/sessions/", console.console_sessions, name="console_sessions"),
    path("console/audit/", console.console_audit, name="console_audit"),
    path("console/risk/", console.console_risk, name="console_risk"),
    path("console/policies/", console.console_policies, name="console_policies"),
    path("console/mfa/", console.console_mfa, name="console_mfa"),
    path("console/invitations/", console.console_invitations, name="console_invitations"),
    path("console/notifications/", console.console_notifications, name="console_notifications"),
    path("console/orgs/<slug:slug>/action/", console.console_org_action, name="console_org_action"),
    path("console/users/<int:user_id>/deactivate/", console.console_user_deactivate, name="console_user_deactivate"),
    path("console/sessions/<int:session_id>/revoke/", console.console_session_revoke, name="console_session_revoke"),
    path("console/risk/<int:event_id>/resolve/", console.console_risk_resolve, name="console_risk_resolve"),
    path("step-up/", views.step_up, name="step_up"),
    path("password-reset/", views.password_reset_request, name="password_reset_request"),
    path("password-reset/complete/", views.password_reset_complete, name="password_reset_complete"),
    path("verify-email/", views.verify_email_view, name="verify_email"),
    path("verify-email/resend/", views.resend_verification, name="resend_verification"),
    path("invitations/accept/", views.accept_invitation_view, name="accept_invitation"),
]
