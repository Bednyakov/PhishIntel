import unittest
import time
from unittest.mock import patch

from app.analyzers import resource_parser


class ResourceParserCollectionTests(unittest.TestCase):
    def test_contact_extraction_uses_phone_masks_and_specialized_fields(self):
        result = resource_parser._extract('''
            <span class="phone">+7 (999) 123-45-67</span>
            <a href="tel:+1 (212) 555-0199">Call</a>
            <div class="address">ул. Ленина, 10, Москва</div>
            <p>IP-адрес 2 Песни 2 и случайный текст с номером 1234567890123456</p>
        ''')
        self.assertEqual(result["phones"], ["+1 (212) 555-0199", "+7 (999) 123-45-67"])
        self.assertEqual(result["addresses"], ["ул. Ленина, 10, Москва"])

    def test_normalize_url_encodes_spaces_and_rejects_control_characters(self):
        self.assertEqual(
            resource_parser._normalize_url("/article/WordPress 6.4.10", "https://example.com/", "example.com"),
            "https://example.com/article/WordPress%206.4.10",
        )
        self.assertIsNone(resource_parser._normalize_url("/bad\nurl", "https://example.com/", "example.com"))

    @patch("app.analyzers.resource_parser.subdomains.analyze", return_value={"status": "ok"})
    @patch("app.analyzers.resource_parser.redirects.analyze", return_value={"status": "ok"})
    @patch("app.analyzers.resource_parser.whois.analyze", return_value={"status": "ok"})
    @patch("app.analyzers.resource_parser.tls.analyze", return_value={"status": "ok"})
    @patch("app.analyzers.resource_parser.rdap.analyze", return_value={"status": "ok"})
    @patch("app.analyzers.resource_parser.dns.analyze_ip", return_value={"status": "ok"})
    @patch("app.analyzers.resource_parser.dns.analyze", return_value={"status": "ok"})
    @patch("app.analyzers.resource_parser.record_history", return_value={"status": "ok"})
    @patch("app.analyzers.sitemap.analyze", return_value={"status": "ok", "urls": ["https://example.com/from-sitemap"]})
    @patch("app.analyzers.resource_parser._fetch")
    def test_report_contains_important_resources_without_page_dump(self, fetch, *_mocks):
        html = b'''<html><body>
        <a href="/about">About</a><a href="https://sub.example.com/contact">Contact</a>
        <script src="/static/app.js"></script>
        <script>fetch('/api/users')</script>
        support@example.com +1 202 555 0199
        </body></html>'''
        sitemap_html = b"<html>sales@example.com</html>"
        fetch.side_effect = [
            (200, "text/html", html.decode()),
            (200, "text/html", sitemap_html.decode()),
            (200, "text/html", "<html>about</html>"),
            (200, "text/html", "<html>contact</html>"),
            (200, "application/javascript", "console.log(1)"),
            (200, "application/json", "{}"),
        ]

        report = resource_parser.analyze("https://example.com", max_pages=20, max_depth=1, concurrency=3)

        self.assertNotIn("pages", report)
        self.assertIn("https://example.com/static/app.js", report["external_resources"]["scripts"])
        self.assertIn("https://example.com/api/users", report["external_resources"]["api_urls"])
        self.assertNotIn("links", report["external_resources"])
        self.assertNotIn("sitemap", report)
        self.assertNotIn("errors", report)
        self.assertIn("support@example.com", report["contacts"]["emails"])
        self.assertIn("subdomains", report["domain"])

    def test_async_analyzer_fetches_multiple_pages_concurrently(self):
        active = 0
        peak = 0

        def fetch(url, _timeout):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            time.sleep(0.02)
            active -= 1
            if url.endswith("/"):
                return 200, "text/html", '<a href="/one">one</a><a href="/two">two</a><a href="/three">three</a>'
            return 200, "text/html", "<html>page</html>"

        with patch("app.analyzers.sitemap.analyze", return_value={"status": "ok", "urls": []}), patch(
            "app.analyzers.resource_parser._fetch", side_effect=fetch
        ):
            report = resource_parser.analyze("https://example.com", max_pages=4, max_depth=1, concurrency=3)

        self.assertEqual(report["summary"]["pages_visited"], 4)
        self.assertGreaterEqual(peak, 2)


if __name__ == "__main__":
    unittest.main()