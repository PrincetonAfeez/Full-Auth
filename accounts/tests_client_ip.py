"""Tests for client IP extraction behind proxies."""
from django.test import RequestFactory, TestCase, override_settings


class ClientIpTests(TestCase):
    def test_uses_remote_addr_by_default(self):
        from accounts.client_ip import client_ip

        request = RequestFactory().get("/", REMOTE_ADDR="203.0.113.7")
        self.assertEqual(client_ip(request), "203.0.113.7")

    @override_settings(SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"))
    def test_uses_x_forwarded_for_when_proxy_trusted(self):
        from accounts.client_ip import client_ip

        request = RequestFactory().get(
            "/", REMOTE_ADDR="10.0.0.1", HTTP_X_FORWARDED_FOR="198.51.100.42, 10.0.0.1"
        )
        self.assertEqual(client_ip(request), "198.51.100.42")
