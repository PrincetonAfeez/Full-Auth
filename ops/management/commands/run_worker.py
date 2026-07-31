"""Django management command: run worker."""
import signal
import time

from django.core.management.base import BaseCommand

from notifications.services import process_outbox


class Command(BaseCommand):
    help = "Run the outbox worker loop with graceful shutdown (drains in-flight work on SIGTERM)."

    def add_arguments(self, parser):
        parser.add_argument("--interval", type=float, default=5.0)
        parser.add_argument("--limit", type=int, default=50)

    def handle(self, *args, **options):
        self._stop = False

        def _graceful(signum, frame):
            self.stdout.write(self.style.WARNING(f"Received signal {signum}; finishing current batch then exiting."))
            self._stop = True

        signal.signal(signal.SIGTERM, _graceful)
        signal.signal(signal.SIGINT, _graceful)

        self.stdout.write(self.style.SUCCESS("Outbox worker started."))
        while not self._stop:
            try:
                process_outbox(limit=options["limit"])
            except Exception as exc:  # noqa: BLE001 - keep the worker alive across transient errors
                self.stderr.write(self.style.ERROR(f"outbox batch failed: {exc}"))
            # Sleep in small slices so a shutdown signal is honored promptly.
            waited = 0.0
            while waited < options["interval"] and not self._stop:
                time.sleep(0.5)
                waited += 0.5
        self.stdout.write(self.style.SUCCESS("Outbox worker stopped cleanly."))
