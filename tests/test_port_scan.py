import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch

from app.analyzers import port_scan, resource_parser
from app.report_html import render


class PortScanTests(unittest.TestCase):
    def test_unavailable_result_has_stable_contract(self):
        result = port_scan.unavailable("example.com")
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["ports"], [])
        self.assertEqual(result["open_port_count"], 0)
        self.assertEqual(result["technologies"], [])

    @patch("app.analyzers.port_scan.shutil.which", return_value=None)
    def test_missing_binary_does_not_fail_scan(self, _which):
        result = asyncio.run(port_scan.analyze_async("example.com"))
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("binary", result["error"])

    def test_html_contains_port_scan_data(self):
        html = render({
            "target": "example.com",
            "summary": {},
            "contacts": {},
            "external_resources": {},
            "port_scan": {
                "status": "ok",
                "open_port_count": 1,
                "ports": [{"port": 443, "protocol": "tcp", "service": "https", "technology": "nginx", "version": "1.24"}],
            },
        })
        self.assertIn("Открытые порты и технологии", html)
        self.assertIn("443/tcp", html)
        self.assertIn("nginx", html)

    def test_resource_parser_starts_port_scan_before_page_fetch(self):
        events = []

        async def fake_scan(target, timeout):
            events.append("scan-start")
            await asyncio.sleep(0)
            events.append("scan-end")
            return {"status": "ok", "target": target, "ports": [], "open_port_count": 0, "technologies": []}

        def fake_fetch(url, timeout):
            events.append("fetch")
            return 200, "text/html", "<html>ok</html>"

        with patch("app.analyzers.resource_parser.port_scan.analyze_async", new=AsyncMock(side_effect=fake_scan)), \
             patch("app.analyzers.sitemap.analyze", return_value={"status": "ok", "urls": []}), \
             patch("app.analyzers.resource_parser._fetch", side_effect=fake_fetch), \
             patch("app.analyzers.resource_parser.dns.analyze", return_value={"status": "ok"}), \
             patch("app.analyzers.resource_parser.dns.analyze_ip", return_value={"status": "ok"}), \
             patch("app.analyzers.resource_parser.rdap.analyze", return_value={"status": "ok"}), \
             patch("app.analyzers.resource_parser.whois.analyze", return_value={"status": "ok"}), \
             patch("app.analyzers.resource_parser.tls.analyze", return_value={"status": "ok"}), \
             patch("app.analyzers.resource_parser.redirects.analyze", return_value={"status": "ok"}), \
             patch("app.analyzers.resource_parser.subdomains.analyze", return_value={"status": "ok"}), \
             patch("app.analyzers.resource_parser.record_history", return_value={"status": "ok"}):
            report = resource_parser.analyze("https://example.com", max_pages=1)

        self.assertEqual(report["port_scan"]["status"], "ok")
        self.assertLess(events.index("scan-start"), events.index("fetch"))


if __name__ == "__main__":
    unittest.main()