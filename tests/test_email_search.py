import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.analyzers.email_search import analyze, load_remote_rules, load_rules


class FakeResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class FakeSession:
    def get(self, url, **kwargs):
        return FakeResponse(200, '{"exists":true}')

    def post(self, url, **kwargs):
        return FakeResponse(404, '')


class EmailSearchTests(unittest.TestCase):
    def test_load_rules_skips_disabled_and_invalid_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_text(json.dumps([
                {"name": "Active", "url": "https://example.test/check?email={email}"},
                {"name": "Disabled", "url": "https://disabled.test/{email}", "disabled": True},
                {"name": "HTTP", "url": "http://bad.test/{email}"},
            ]), encoding="utf-8")
            self.assertEqual([item["name"] for item in load_rules(path, include_disabled=False)], ["Active"])
            self.assertEqual({item["name"] for item in load_rules(path, include_disabled=True)}, {"Active", "Disabled"})

    @patch("app.analyzers.email_search.requests.get")
    def test_remote_catalog_is_converted_and_cached(self, get):
        response = get.return_value
        response.json.return_value = {
            "Active": {"uri_check": "https://example.test/check?email={username}", "requestMethod": "GET", "e_code": 200, "e_string": "exists"},
            "Disabled": {"uri_check": "https://disabled.test/check?email={username}", "disabled": True, "disabled_reason": "WAF"},
        }
        response.raise_for_status.return_value = None
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "cache.json"
            rules, source = load_remote_rules(cache, update=True)
            self.assertEqual(source, "mailaccess_remote")
            self.assertEqual({item["name"] for item in rules}, {"Active", "Disabled"})
            self.assertTrue(cache.is_file())

    def test_analyze_posts_and_reports_found(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_text(json.dumps([{
                "name": "Example", "url": "https://example.test/check", "method": "POST",
                "payload": {"email": "{email}"}, "found_statuses": [200], "found_strings": ["exists"]
            }]), encoding="utf-8")
            cache = Path(directory) / "cache.json"
            cache.write_text("[]", encoding="utf-8")
            report = analyze(" Test@Example.com ", rules=path, remote_cache=cache, offline=True, workers=1, session_factory=FakeSession)
        self.assertEqual(report["target"], "test@example.com")
        self.assertEqual(report["summary"]["found"], 1)
        self.assertEqual(report["results"][0]["status"], "found")


if __name__ == "__main__":
    unittest.main()