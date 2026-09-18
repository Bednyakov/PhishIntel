import unittest
import time
from unittest.mock import patch
import os

from app.analyzers import resource_parser


class ResourceParserCollectionTests(unittest.TestCase):
    @patch("app.analyzers.resource_parser.urllib.request.ProxyHandler")
    @patch("app.analyzers.resource_parser.urllib.request.build_opener")
    def test_fetch_applies_custom_user_agent_and_proxy(self, build_opener, proxy_handler):
        opener = build_opener.return_value
        response = opener.open.return_value.__enter__.return_value
        response.status = 200
        response.headers.get.return_value = "text/html"
        response.headers.get_content_charset.return_value = None
        response.read.return_value = b"<html></html>"

        resource_parser._fetch("https://example.com/", 3, "Crawler/2.0", "http://proxy.example:8080")

        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header("User-agent"), "Crawler/2.0")
        proxy_handler.assert_called_once_with({"http": "http://proxy.example:8080", "https": "http://proxy.example:8080"})
        build_opener.assert_called_once_with(proxy_handler.return_value)

    def test_empty_proxy_and_user_agent_configuration_keeps_defaults(self):
        with patch.dict(os.environ, {"PHISHINTEL_RESOURCE_USER_AGENTS": "", "PHISHINTEL_RESOURCE_PROXIES": ""}, clear=False):
            self.assertEqual(resource_parser.list_value("PHISHINTEL_RESOURCE_USER_AGENTS", (resource_parser._USER_AGENT,)), (resource_parser._USER_AGENT,))
            self.assertEqual(resource_parser.list_value("PHISHINTEL_RESOURCE_PROXIES"), ())

    @patch("app.analyzers.sitemap.analyze", return_value={"status": "ok", "urls": []})
    @patch("app.analyzers.resource_parser.port_scan.analyze_async")
    @patch("app.analyzers.resource_parser._fetch", return_value=(200, "text/html", "<html></html>"))
    def test_configured_pools_are_assigned_round_robin(self, fetch, port_scan, _sitemap):
        async def completed_scan(*_args):
            return {"status": "ok"}

        port_scan.return_value = completed_scan()
        with patch.dict(os.environ, {
            "PHISHINTEL_RESOURCE_USER_AGENTS": "UA-1,UA-2",
            "PHISHINTEL_RESOURCE_PROXIES": "http://proxy-1:8080,http://proxy-2:8080",
        }, clear=False):
            resource_parser.analyze("https://example.com", max_pages=4, max_depth=1, concurrency=2)

        assignments = [(call.args[2], call.args[3]) for call in fetch.call_args_list]
        self.assertEqual(len(assignments), 4)
        self.assertEqual(assignments.count(("UA-1", "http://proxy-1:8080")), 2)
        self.assertEqual(assignments.count(("UA-2", "http://proxy-2:8080")), 2)

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

    @patch("app.analyzers.redirects.urllib.request.OpenerDirector.open")
    def test_redirect_analyzer_returns_complete_chain_contract_on_error(self, open_request):
        from urllib.error import URLError

        from app.analyzers import redirects

        open_request.side_effect = URLError("connection refused")
        result = redirects.analyze("https://example.com")

        self.assertEqual(result["chain"], [])
        self.assertIsNone(result["final_url"])
        self.assertEqual(result["count"], 0)

    def test_resource_parser_report_prints_redirect_chain_details(self):
        from app.tools.resource_parser import print_report
        from contextlib import redirect_stdout
        from io import StringIO

        output = StringIO()
        report = {
            "target": "https://example.com",
            "summary": {"pages_visited": 1},
            "contacts": {},
            "domain": {
                "redirects": {
                    "status": "ok",
                    "chain": [{"from": "http://example.com", "to": "https://example.com", "status_code": 301}],
                    "final_url": "https://example.com/",
                    "count": 1,
                }
            },
        }

        with redirect_stdout(output):
            print_report(report)

        text = output.getvalue()
        self.assertIn("Redirect chain:", text)
        self.assertIn("301: http://example.com -> https://example.com", text)
        self.assertIn("final URL: https://example.com/", text)
        self.assertIn("transitions: 1", text)

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

    @patch("app.analyzers.resource_parser.subdomains.analyze", return_value={"status": "ok"})
    @patch("app.analyzers.resource_parser.redirects.analyze", return_value={"status": "ok"})
    @patch("app.analyzers.resource_parser.whois.analyze", return_value={"status": "ok"})
    @patch("app.analyzers.resource_parser.tls.analyze", return_value={"status": "ok"})
    @patch("app.analyzers.resource_parser.rdap.analyze", return_value={"status": "ok"})
    @patch("app.analyzers.resource_parser.dns.analyze_ip", return_value={"status": "ok"})
    @patch("app.analyzers.resource_parser.dns.analyze", return_value={"status": "ok"})
    @patch("app.analyzers.resource_parser.record_history", return_value={"status": "ok"})
    @patch("app.analyzers.sitemap.analyze", return_value={"status": "ok", "urls": []})
    @patch("app.analyzers.resource_parser._fetch")
    def test_report_contains_page_technologies(self, fetch, *_mocks):
        fetch.return_value = (200, "text/html", '<meta name="generator" content="WordPress 6.6"><script src="/wp-includes/js/jquery.js"></script>')

        report = resource_parser.analyze("https://example.com", max_pages=1)

        self.assertIn("WordPress", report["technologies"])
        self.assertIn("jQuery", report["technologies"])

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