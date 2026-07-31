"""Django management command: process outbox."""
from django.core.management.base import BaseCommand

from notifications.services import process_outbox


class Command(BaseCommand):
    help = "Drain pending outbox events once."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=25)

    def handle(self, *args, **options):
        processed = process_outbox(limit=options["limit"])
        self.stdout.write(self.style.SUCCESS(f"Processed {processed} outbox event(s)."))
