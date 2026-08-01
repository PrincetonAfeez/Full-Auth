"""Pytest coverage for ops smoke."""
from unittest.mock import patch

import pytest
from django.core.management import call_command
from io import StringIO


@pytest.mark.django_db
class TestConfigFlags:
    def test_flags_module_imports(self):
        from config import flags

        assert hasattr(flags, "__name__")


@pytest.mark.django_db
class TestSmokeStaging:
    @patch("ops.smoke.run_smoke", return_value=[])
    def test_smoke_command_runs(self, mock_smoke):
        out = StringIO()
        call_command("smoke_staging", stdout=out)
        mock_smoke.assert_called_once()
        assert "passed" in out.getvalue().lower()
