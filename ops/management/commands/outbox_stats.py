"""Django management command: outbox stats."""
import json

from django.core.management.base import BaseCommand

from notifications.services import outbox_stats


class Command(BaseCommand):
    help = "Print outbox queue depth / oldest-pending age / dead-letter count (for monitoring)."

    def handle(self, *args, **options):
        self.stdout.write(json.dumps(outbox_stats(), indent=2))
