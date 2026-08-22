import unittest
import contextlib
import io
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from app.main import CHECK_STAGES, analyze
import scan


class ProgressTests(unittest.TestCase):
    @patch("app.main.record_history", return_value={"status": "ok"})
    @patch("app.main.score", return_value=({"score": 0, "level": "low", "reasons": []}, []))
    @patch("app.main.subdomains.analyze", return_value={"status": "ok"})
    @patch("app.main.sitemap.analyze", return_value={"status": "ok"})
    @patch("app.main.whois.analyze", return_value={"status": "ok"})
    @patch("app.main.http.analyze", return_value={"status": "ok", "_body": b""})
    @patch("app.main.tls.analyze", return_value={"status": "ok"})
    @patch("app.main.rdap.analyze", return_value={"status": "ok"})
    @patch("app.main.redirects.analyze", return_value={"status": "ok"})
    @patch("app.main.dns.analyze_ip", return_value={"status": "ok"})
    @patch("app.main.dns.analyze", return_value={"status": "ok"})
    @patch("app.main.domain.analyze", return_value={"status": "ok"})
    def test_reports_every_completed_stage(self, *_mocks):
        updates = []
        analyze("example.com", progress_callback=updates.append)

        self.assertEqual([item["stage"] for item in updates], list(CHECK_STAGES))
        self.assertEqual([item["completed"] for item in updates], list(range(1, len(CHECK_STAGES) + 1)))
        self.assertTrue(all(item["total"] == len(CHECK_STAGES) for item in updates))
        self.assertEqual(updates[-1]["percent"], 100)

    def test_report_path_uses_safe_domain_and_timestamp(self):
        path = scan._report_path("reports", "https://example.com/login")
        self.assertRegex(path.name, r"^example\.com_\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z\.json$")

    def test_cli_saves_report_and_prints_location(self):
        with tempfile.TemporaryDirectory() as directory, patch("sys.argv", ["scan.py", "example.com", "--no-progress", "--output-dir", directory]), contextlib.redirect_stdout(io.StringIO()) as stdout:
            with patch("scan.analyze", return_value={"target": "example.com", "risk": {}}):
                self.assertEqual(scan.main(), 0)

            files = list(Path(directory).glob("*.json"))
            self.assertEqual(len(files), 1)
            self.assertEqual(json.loads(files[0].read_text(encoding="utf-8"))["target"], "example.com")
            self.assertIn("Отчёт сохранён:", stdout.getvalue())

    def test_stdout_mode_does_not_create_report_file(self):
        with tempfile.TemporaryDirectory() as directory, patch("sys.argv", ["scan.py", "example.com", "--stdout", "--output-dir", directory]), contextlib.redirect_stdout(io.StringIO()) as stdout:
            with patch("scan.analyze", return_value={"target": "example.com", "risk": {}}):
                self.assertEqual(scan.main(), 0)

        self.assertEqual(list(Path(directory).glob("*.json")), [])
        self.assertEqual(json.loads(stdout.getvalue())["target"], "example.com")

    def test_json_is_pretty_by_default(self):
        with patch("sys.argv", ["scan.py", "example.com", "--stdout", "--no-progress"]), contextlib.redirect_stdout(io.StringIO()) as stdout:
            with patch("scan.analyze", return_value={"target": "example.com", "risk": {}}):
                self.assertEqual(scan.main(), 0)

        self.assertIn("\n  \"risk\"", stdout.getvalue())

    def test_compact_option_disables_pretty_json(self):
        with patch("sys.argv", ["scan.py", "example.com", "--stdout", "--compact", "--no-progress"]), contextlib.redirect_stdout(io.StringIO()) as stdout:
            with patch("scan.analyze", return_value={"target": "example.com", "risk": {}}):
                self.assertEqual(scan.main(), 0)

        self.assertNotIn("\n  ", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()