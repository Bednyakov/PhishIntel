import tempfile
import unittest
from pathlib import Path

from app.report_html import render, save


class HtmlReportTests(unittest.TestCase):
    def test_render_is_russian_compact_and_excludes_contact_sources(self):
        report = {
            "target": "https://example.com/?x=<script>",
            "summary": {"pages_visited": 3},
            "contacts": {"emails": ["a@example.com", "b@example.com"], "phones": ["+7 999 123-45-67"]},
            "contact_sources": [{"url": "https://secret.example"}],
            "redirects": {"count": 1, "final_url": "https://example.com/", "chain": [{"from": "http://example.com", "to": "https://example.com", "status_code": 301}]},
            "risk": {"level": "low", "score": 2},
        }
        document = render(report)
        self.assertIn('lang="ru"', document)
        self.assertIn("Цепочка перенаправлений", document)
        self.assertIn("301", document)
        self.assertIn("a@example.com", document)
        self.assertIn("b@example.com", document)
        self.assertIn("+7 999 123-45-67", document)
        self.assertIn("<h2>Контакты</h2>", document)
        self.assertIn("<h2>Контактная информация</h2>", document)
        self.assertIn("<li><b>emails</b>: 2</li>", document)
        self.assertNotIn("contact_sources", document)
        self.assertNotIn("secret.example", document)
        self.assertNotIn("Уровень риска", document)
        self.assertNotIn("Оценка риска", document)
        self.assertNotIn("Индикаторы", document)
        self.assertIn("&lt;script&gt;", document)

    def test_save_creates_html_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = save({"target": "example.com"}, directory)
            self.assertEqual(path.suffix, ".html")
            self.assertTrue(Path(path).is_file())

    def test_render_can_be_english(self):
        document = render({"target": "example.com"}, locale="en")
        self.assertIn('lang="en"', document)
        self.assertIn("intelligence report", document)
        self.assertIn("Summary", document)
        self.assertNotIn("Цепочка перенаправлений", document)

    def test_render_includes_dns_tls_and_whois(self):
        document = render({
            "target": "example.com",
            "dns": {"status": "ok", "a": ["192.0.2.1"], "mx": ["mail.example.com"]},
            "tls": {"status": "ok", "version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "not_after": "2030-01-01"},
            "whois": {"status": "ok", "registrar": "Example Registrar", "created": "2020-01-01", "privacy": True},
        })
        self.assertIn("Записи DNS", document)
        self.assertIn("192.0.2.1", document)
        self.assertIn("Краткая информация о TLS", document)
        self.assertIn("TLSv1.3", document)
        self.assertIn("WHOIS", document)
        self.assertIn("Example Registrar", document)
        self.assertIn("да", document)

    def test_render_supports_legacy_domain_sections(self):
        document = render({"target": "example.com", "domain": {"dns": {"a": ["192.0.2.2"]}, "tls": {"version": "TLSv1.2"}, "whois": {"registrar": "Legacy Registrar"}}})
        self.assertIn("192.0.2.2", document)
        self.assertIn("TLSv1.2", document)
        self.assertIn("Legacy Registrar", document)

    def test_render_includes_ip_and_ipinfo_data(self):
        document = render({
            "target": "example.com",
            "ip": {
                "status": "ok",
                "address": "192.0.2.10",
                "addresses": ["192.0.2.10", "2001:db8::10"],
                "version": 4,
                "reverse_dns": "host.example.com",
                "ipinfo": {"hostname": "host.example.com", "org": "AS64500 Example ISP", "country": "RU", "city": "Moscow"},
            },
        })
        self.assertIn("Информация об IP-адресе", document)
        self.assertIn("192.0.2.10", document)
        self.assertIn("2001:db8::10", document)
        self.assertIn("host.example.com", document)
        self.assertIn("AS64500 Example ISP", document)
        self.assertIn("Moscow", document)

    def test_render_includes_website_technologies(self):
        document = render({"target": "example.com", "technologies": ["WordPress", "PHP"]})
        self.assertIn("Технологии сайта", document)
        self.assertIn("WordPress", document)
        self.assertIn("PHP", document)

    def test_render_reads_technologies_from_content_compatibility_section(self):
        document = render({"target": "example.com", "content": {"technologies": ["React"]}})
        self.assertIn("React", document)


if __name__ == "__main__":
    unittest.main()