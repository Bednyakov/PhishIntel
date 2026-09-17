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


if __name__ == "__main__":
    unittest.main()