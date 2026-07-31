"""Django unit tests for the ops app."""
from django.test import SimpleTestCase

from ops.smoke import run_smoke


class SmokeModuleTests(SimpleTestCase):
    def test_run_smoke_reports_failures_for_unreachable_host(self):
        failures = run_smoke(base_url="http://127.0.0.1:1")
        self.assertTrue(failures)
