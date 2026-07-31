"""Business logic and service layer for notifications."""
import logging
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.db import transaction
from django.urls import reverse
from django.utils import timezone

from accounts.models import User

from .models import (
    SUPPRESSIBLE_CATEGORIES,
    NotificationCategory,
    NotificationDelivery,
    NotificationPreference,
    OutboxEvent,
)

logger = logging.getLogger("notifications.outbox")

# Map each notified event_type to a category. Unlisted events default to security-critical
# (always delivered) so a new event is never accidentally silenced.
EVENT_CATEGORY = {
    "password.changed": NotificationCategory.SECURITY_CRITICAL,
    "password_reset.requested": NotificationCategory.SECURITY_CRITICAL,
    "mfa.factor.disabled": NotificationCategory.SECURITY_CRITICAL,
    "account.deactivated": NotificationCategory.SECURITY_CRITICAL,
    "account.erased": NotificationCategory.SECURITY_CRITICAL,
    "email_verification.requested": NotificationCategory.TRANSACTIONAL,
    "organization.invitation.created": NotificationCategory.TRANSACTIONAL,
    "login.new_device": NotificationCategory.ACCOUNT_ACTIVITY,
    "organization.membership.role_changed": NotificationCategory.ORG_ACTIVITY,
}


def category_for(event_type: str) -> str:
    return EVENT_CATEGORY.get(event_type, NotificationCategory.SECURITY_CRITICAL)


def is_suppressed(user, event_type: str) -> bool:
    """True only if the event is in a suppressible category AND the user opted out of it."""
    category = category_for(event_type)
    if user is None or category not in SUPPRESSIBLE_CATEGORIES:
        return False
    pref = NotificationPreference.objects.filter(user=user, category=category).first()
    return pref is not None and not pref.email_enabled


def get_preferences(user) -> dict:
    overrides = {p.category: p.email_enabled for p in NotificationPreference.objects.filter(user=user)}
    return {cat: overrides.get(cat, True) for cat in SUPPRESSIBLE_CATEGORIES}


def set_preference(*, user, category: str, email_enabled: bool) -> None:
    if category not in SUPPRESSIBLE_CATEGORIES:
        raise ValueError("This notification category cannot be muted.")
    NotificationPreference.objects.update_or_create(
        user=user, category=category, defaults={"email_enabled": email_enabled}
    )


def emit_outbox_event(*, event_type: str, aggregate_type: str, aggregate_id: str, payload: dict) -> OutboxEvent:
    return OutboxEvent.objects.create(
        event_type=event_type,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        payload=payload,
    )


def _absolute(path: str) -> str:
    return f"{settings.PUBLIC_BASE_URL}{path}"


def _render(event: OutboxEvent) -> tuple[str, str]:
    """Return (subject, body) for an event, embedding the actionable link where present."""
    token = event.payload.get("token")
    if event.event_type == "password_reset.requested" and token:
        link = _absolute(f"{reverse('web:password_reset_complete')}?token={token}")
        return (
            "Reset your Full Auth password",
            f"We received a request to reset your password.\n\nReset it here: {link}\n\n"
            "This link expires in 1 hour. If this wasn't you, ignore this email.",
        )
    if event.event_type == "email_verification.requested" and token:
        link = _absolute(f"{reverse('web:verify_email')}?token={token}")
        return (
            "Verify your Full Auth email",
            f"Confirm this email address:\n\n{link}\n\nThis link expires in 24 hours.",
        )
    if event.event_type == "organization.invitation.created" and token:
        link = _absolute(f"{reverse('web:accept_invitation')}?token={token}")
        org = event.payload.get("organization", "an organization")
        return (
            "You've been invited to a Full Auth organization",
            f"You've been invited to join {org}. Accept here after signing in:\n\n{link}\n\n"
            "This invitation expires in 7 days.",
        )
    friendly = {
        "password.changed": (
            "Your Full Auth password was changed",
            "Your account password was just changed. If this wasn't you, reset your password and contact support.",
        ),
        "login.new_device": (
            "New device signed in to your Full Auth account",
            "We recorded a sign-in from a device we haven't seen before. If this wasn't you, "
            "reset your password and revoke your sessions immediately.",
        ),
        "mfa.factor.disabled": (
            "A second factor was removed",
            "A two-factor method was removed from your account. If this wasn't you, secure your account now.",
        ),
        "organization.membership.role_changed": (
            "Your role changed",
            "Your role in an organization was changed by an administrator.",
        ),
        "account.deactivated": (
            "Your account was deactivated",
            "Your account has been deactivated. Contact your administrator if this is unexpected.",
        ),
    }
    if event.event_type in friendly:
        return friendly[event.event_type]
    return (
        f"Security notice: {event.event_type}",
        "A security event was recorded for your account. If this was not you, contact support.",
    )


def _deliver(event: OutboxEvent) -> None:
    user_id = event.payload.get("user_id")
    user = User.objects.filter(pk=user_id).first() if user_id else None
    # Recipient may be an explicit address (e.g. an invitation to a not-yet-registered user).
    recipient = event.payload.get("email") or (user.email if user else None)
    if not recipient:
        return
    # Idempotent: a prior successful delivery must not resend on worker retry after crash.
    already_sent = NotificationDelivery.objects.filter(
        related_event=event,
        channel=NotificationDelivery.Channel.EMAIL,
        status=NotificationDelivery.Status.SENT,
    ).exists()
    if already_sent:
        return
    # Honor user opt-outs for suppressible categories; security-critical is never muted.
    if is_suppressed(user, event.event_type):
        NotificationDelivery.objects.update_or_create(
            related_event=event, recipient=user, channel=NotificationDelivery.Channel.EMAIL,
            defaults={"template": event.event_type, "status": NotificationDelivery.Status.SUPPRESSED},
        )
        return
    subject, body = _render(event)
    # One delivery row per (event, recipient); retries update it rather than piling up rows.
    try:
        send_mail(subject, body, None, [recipient], fail_silently=False)
    except Exception as exc:
        NotificationDelivery.objects.update_or_create(
            related_event=event,
            recipient=user,
            channel=NotificationDelivery.Channel.EMAIL,
            defaults={
                "template": event.event_type,
                "status": NotificationDelivery.Status.FAILED,
                "failed_at": timezone.now(),
                "error": str(exc)[:500],
            },
        )
        raise
    NotificationDelivery.objects.update_or_create(
        related_event=event,
        recipient=user,
        channel=NotificationDelivery.Channel.EMAIL,
        defaults={
            "template": event.event_type,
            "status": NotificationDelivery.Status.SENT,
            "sent_at": timezone.now(),
            "error": "",
        },
    )


def _scrub_secret_payload(event: OutboxEvent) -> None:
    """Remove any transient token from the payload once the email has been sent."""
    if "token" in event.payload:
        payload = dict(event.payload)
        payload.pop("token", None)
        event.payload = payload


def requeue_stuck_processing(now=None) -> int:
    """
    Reaper: return events stranded in PROCESSING (e.g. worker crash) to FAILED for retry.
    Keyed on processing_started_at (when the claim happened), NOT created_at, so an in-flight
    event that merely happens to be old is never yanked out from under an active worker.
    """
    now = now or timezone.now()
    cutoff = now - timedelta(minutes=settings.OUTBOX_PROCESSING_TIMEOUT_MINUTES)
    return (
        OutboxEvent.objects.filter(status=OutboxEvent.Status.PROCESSING, processing_started_at__lte=cutoff)
        .update(status=OutboxEvent.Status.FAILED)
    )


def process_outbox(*, limit: int = 25) -> int:
    processed = 0
    now = timezone.now()
    requeue_stuck_processing(now)
    with transaction.atomic():
        events = list(
            OutboxEvent.objects.select_for_update(skip_locked=True)
            .filter(status__in=[OutboxEvent.Status.PENDING, OutboxEvent.Status.FAILED])
            .filter(models_q_next_attempt_ready(now))[:limit]
        )
        for event in events:
            event.status = OutboxEvent.Status.PROCESSING
            event.attempts += 1
            event.processing_started_at = now
            event.save(update_fields=["status", "attempts", "processing_started_at"])

    for event in events:
        try:
            _deliver(event)
        except Exception as exc:  # noqa: BLE001 - captured for dead-letter workflow.
            event.status = OutboxEvent.Status.DEAD_LETTER if event.attempts >= 5 else OutboxEvent.Status.FAILED
            event.last_error = str(exc)[:1000]
            event.next_attempt_at = timezone.now() + timedelta(minutes=2**event.attempts)
            event.save(update_fields=["status", "last_error", "next_attempt_at"])
            # Alertable: a dead-lettered event needs human attention (wired to Sentry/log pipeline).
            if event.status == OutboxEvent.Status.DEAD_LETTER:
                logger.error("outbox event %s dead-lettered after %s attempts: %s", event.pk, event.attempts, exc)
        else:
            event.status = OutboxEvent.Status.SENT
            event.processed_at = timezone.now()
            _scrub_secret_payload(event)
            event.save(update_fields=["status", "processed_at", "payload"])
            processed += 1
    return processed


def models_q_next_attempt_ready(now):
    from django.db.models import Q

    return Q(next_attempt_at__isnull=True) | Q(next_attempt_at__lte=now)


def outbox_stats() -> dict:
    """Queue-health snapshot for monitoring: depth by status + oldest-pending age (seconds)."""
    from django.db.models import Count, Min

    counts = {s: 0 for s, _ in OutboxEvent.Status.choices}
    for row in OutboxEvent.objects.values("status").annotate(n=Count("id")):
        counts[row["status"]] = row["n"]
    oldest = OutboxEvent.objects.filter(
        status__in=[OutboxEvent.Status.PENDING, OutboxEvent.Status.FAILED]
    ).aggregate(oldest=Min("created_at"))["oldest"]
    oldest_age = (timezone.now() - oldest).total_seconds() if oldest else 0
    return {"by_status": counts, "oldest_pending_age_seconds": int(oldest_age),
            "dead_letter": counts.get(OutboxEvent.Status.DEAD_LETTER, 0)}
