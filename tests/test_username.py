import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.analyzers.username import analyze, load_templates, load_rules, load_remote_rules, normalize_username
from app.tools.username_search import print_report


class UsernameTests(unittest.TestCase):
    def test_normalize_username(self):
        self.assertEqual(normalize_username(" @test_user "), "test_user")
        with self.assertRaises(ValueError):
            normalize_username("bad username")

    def test_load_templates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sites.txt"
            path.write_text("# comment\nhttps://example.com/{username}\nhttp://bad/{username}\nhttps://example.com/{username}\n", encoding="utf-8")
            self.assertEqual(load_templates(path), ["https://example.com/{username}"])

    def test_load_rules_missing_file_is_optional(self):
        self.assertEqual(load_rules("/tmp/phishintel-missing-username-rules.json"), [])

    @patch("app.analyzers.username.requests.get")
    def test_remote_rules_are_converted_and_cached(self, get):
        response = get.return_value
        response.json.return_value = {"Example": {"url": "https://example.com/{}", "errorType": "status_code", "errorCode": 404}}
        response.raise_for_status.return_value = None
        with tempfile.TemporaryDirectory() as directory:
            rules, source = load_remote_rules(Path(directory) / "cache.json", update=True)
            self.assertEqual(source, "remote_sherlock")
            self.assertEqual(rules[0]["url"], "https://example.com/{username}")

    @patch("app.analyzers.username._check")
    def test_remote_local_and_user_sources_are_combined(self, check):
        check.side_effect = lambda rule, *args: {"site": rule.get("name", "custom"), "url": rule["url"], "source": rule.get("source"), "status": "not_found"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "remote.json").write_text(json.dumps([{"name": "Remote", "url": "https://remote.example/{username}"}]), encoding="utf-8")
            (root / "local.json").write_text(json.dumps([{"name": "Local", "url": "https://local.example/{username}"}]), encoding="utf-8")
            (root / "sites.txt").write_text("https://user.example/{username}\n", encoding="utf-8")
            with patch("app.analyzers.username.load_remote_rules", return_value=([{"name": "Remote", "url": "https://remote.example/{username}"}], "remote_sherlock")):
                report = analyze("test_user", wordlist=root / "sites.txt", rules=root / "local.json", remote_cache=root / "remote.json", workers=1)
        self.assertEqual(report["summary"]["checked"], 3)
        self.assertEqual({item["source"] for item in report["results"]}, {"remote_sherlock", "local_rules", "user_wordlist"})

    @patch("app.analyzers.username._check")
    def test_duplicate_templates_from_user_wordlist_are_checked_once(self, check):
        check.side_effect = lambda rule, *args: {
            "site": rule.get("name", "custom"),
            "url": rule["url"].replace("{username}", "test_user"),
            "source": rule.get("source"),
            "status": "not_found",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "remote.json").write_text("[]", encoding="utf-8")
            (root / "local.json").write_text(json.dumps([{"name": "GitHub", "url": "https://github.com/{username}"}]), encoding="utf-8")
            (root / "sites.txt").write_text(
                "https://github.com/{username}\nhttps://custom.example/{username}\nhttps://custom.example/{username}\n",
                encoding="utf-8",
            )
            with patch("app.analyzers.username.load_remote_rules", return_value=([], "remote_cache")):
                report = analyze("test_user", wordlist=root / "sites.txt", rules=root / "local.json", remote_cache=root / "remote.json", workers=1)
        self.assertEqual(report["summary"]["checked"], 2)
        self.assertEqual(check.call_count, 2)
        self.assertEqual({item["url"] for item in report["results"]}, {"https://github.com/test_user", "https://custom.example/test_user"})

    @patch("app.analyzers.username._check")
    def test_analyze_and_console_report(self, check):
        check.side_effect = [
            {"site": "example.com", "url": "https://example.com/test_user", "status": "found", "http_status": 200},
            {"site": "missing.example", "url": "https://missing.example/test_user", "status": "not_found", "http_status": 404},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sites.txt"
            rules = Path(directory) / "rules.json"
            cache = Path(directory) / "remote.json"
            path.write_text("https://example.com/{username}\nhttps://missing.example/{username}\n", encoding="utf-8")
            rules.write_text("[]", encoding="utf-8")
            cache.write_text("[]", encoding="utf-8")
            report = analyze("test_user", wordlist=path, rules=rules, remote_cache=cache, offline=True, workers=1, timeout=1)
        self.assertEqual(report["summary"]["found"], 1)
        self.assertEqual(report["target"], "test_user")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            print_report(report)
        self.assertIn("Resource", output.getvalue())
        self.assertIn("[+]", output.getvalue())
        self.assertIn("https://example.com/test_user", output.getvalue())


if __name__ == "__main__":
    unittest.main()