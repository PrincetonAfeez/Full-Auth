"""Django management command: cleanup expired."""
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone


class Command(BaseCommand):
    help = "Purge expired/consumed challenges, old revoked sessions, and sent outbox rows (data retention)."

    def add_arguments(self, parser):
        parser.add_argument("--challenge-days", type=int, default=30)
        parser.add_argument("--session-days", type=int, default=90)
        parser.add_argument("--outbox-days", type=int, default=30)

    def handle(self, *args, **options):
        from django.core.cache import cache

        if not cache.add("cleanup_expired:lock", 1, timeout=3600):
            self.stdout.write("Cleanup already running elsewhere; skipping.")
            return

        try:
            self._run_cleanup(options)
        finally:
            cache.delete("cleanup_expired:lock")

    def _run_cleanup(self, options):
        from mfa.models import EmailOTPChallenge, WebAuthnChallenge
        from notifications.models import OutboxEvent
        from passwords.models import EmailVerificationChallenge, PasswordResetChallenge
        from sessions.models import ActiveSession

        now = timezone.now()
        ch_cutoff = now - timedelta(days=options["challenge_days"])
        sess_cutoff = now - timedelta(days=options["session_days"])
        outbox_cutoff = now - timedelta(days=options["outbox_days"])
        total = 0

        for model in (PasswordResetChallenge, EmailVerificationChallenge):
            total += model.objects.filter(created_at__lt=ch_cutoff).delete()[0]
        total += EmailOTPChallenge.objects.filter(created_at__lt=ch_cutoff).delete()[0]
        total += WebAuthnChallenge.objects.filter(created_at__lt=ch_cutoff).delete()[0]
        # Only remove sessions that are already terminated (revoked); never delete audit rows.
        total += ActiveSession.objects.filter(revoked_at__lt=sess_cutoff).delete()[0]
        total += OutboxEvent.objects.filter(
            status=OutboxEvent.Status.SENT, processed_at__lt=outbox_cutoff
        ).delete()[0]

        self.stdout.write(self.style.SUCCESS(f"Cleanup removed {total} expired/consumed row(s)."))
