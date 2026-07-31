"""Django management command: fire test alert."""
import json
import urllib.request

from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Send a synthetic alert through the /internal/alerts webhook to verify the alert path end-to-end."

    def add_arguments(self, parser):
        parser.add_argument("--url", default="http://localhost:8000/internal/alerts")
        parser.add_argument("--severity", default="page")

    def handle(self, *args, **options):
        payload = {
            "status": "firing",
            "alerts": [
                {
                    "status": "firing",
                    "labels": {"alertname": "TestAlert", "severity": options["severity"]},
                    "annotations": {"summary": "Synthetic test alert from fire_test_alert"},
                }
            ],
        }
        url = options["url"]
        if not url.startswith(("http://", "https://")):
            self.stderr.write(self.style.ERROR("--url must be http(s)"))
            return
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {settings.ALERT_WEBHOOK_TOKEN}"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310 - scheme validated; operator-supplied local URL
            body = resp.read().decode()
        self.stdout.write(self.style.SUCCESS(f"Alert delivered ({resp.status}): {body}"))
