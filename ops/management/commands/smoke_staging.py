"""Django management command: smoke staging."""
from django.core.management.base import BaseCommand

from ops.smoke import run_smoke


class Command(BaseCommand):
    help = "Run HTTP smoke checks against a running instance (staging gate)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--base-url",
            default="http://127.0.0.1:8000",
            help="Public base URL of the running instance.",
        )

    def handle(self, *args, **options):
        failures = run_smoke(base_url=options["base_url"])
        if failures:
            for msg in failures:
                self.stderr.write(self.style.ERROR(msg))
            raise SystemExit(1)
        self.stdout.write(self.style.SUCCESS(f"Smoke checks passed against {options['base_url']}"))
