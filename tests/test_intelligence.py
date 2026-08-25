import unittest

from unittest.mock import patch

from app.analyzers.javascript import analyze as analyze_javascript
from app.analyzers.reputation import _clean_url, _entities
from app.analyzers.search import analyze as analyze_search


class IntelligenceTests(unittest.TestCase):
    def test_clean_url_removes_query_and_fragment(self):
        self.assertEqual(_clean_url("https://example.com/login?token=secret#form"), "https://example.com/login")

    def test_entities_include_redirect_form_script_and_all_ips(self):
        entities = _entities("example.com", {"url": "https://example.com/"}, {"final_url": "https://evil.example/x", "chain": [{"to": "https://redirect.example/"}]}, {"forms": [{"action": "https://collector.example/post"}], "scripts": ["https://cdn.example/app.js"], "external_domains": ["cdn.example"]}, {"addresses": ["192.0.2.1", "192.0.2.2"]})
        values = {item["value"] for item in entities}
        self.assertIn("https://evil.example/x", values)
        self.assertIn("https://collector.example/post", values)
        self.assertIn("192.0.2.2", values)

    @patch("app.analyzers.javascript.urllib.request.urlopen")
    def test_javascript_static_findings_and_hash(self, urlopen):
        class Response:
            status = 200
            headers = {"content-type": "application/javascript"}
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self, _): return b"eval(atob('abc')); document.cookie;"
        urlopen.return_value = Response()
        result = analyze_javascript({"status": "ok", "url": "https://example.com/"}, {"scripts": ["/app.js"]})
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["scripts"][0]["sha256"])
        self.assertTrue(result["scripts"][0]["findings"])

    def test_search_without_key_is_informational(self):
        with patch.dict("os.environ", {}, clear=True):
            result = analyze_search("example.com")
        self.assertEqual(result["status"], "not_configured")
        self.assertEqual(result["risk_weight"], 0)

    @patch.dict("os.environ", {}, clear=True)
    def test_reputation_without_keys_is_compact(self):
        from app.analyzers.reputation import analyze
        result = analyze("example.com", {"url": "https://example.com/"}, {}, {"forms": [], "scripts": [], "external_domains": []}, {"addresses": []})
        self.assertEqual(result, {"status": "not_configured"})


if __name__ == "__main__":
    unittest.main()