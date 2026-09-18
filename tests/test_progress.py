import unittest
import contextlib
import io
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from app.main import CHECK_STAGES, analyze
from app.tools import resource_parser as resource_parser_tool
from app.i18n import LocaleContext
import scan


class ProgressTests(unittest.TestCase):
    @patch("app.tools.resource_parser.print_report")
    @patch("app.tools.resource_parser.resource_parser.analyze", return_value={"summary": {}})
    def test_interactive_resource_parser_warns_after_page_scan(self, analyze, print_report):
        output = io.StringIO()
        with LocaleContext("ru"), patch("builtins.input", side_effect=["example.com", "1", "1", "1"]), contextlib.redirect_stdout(output):
            resource_parser_tool.interactive()

        self.assertIn("Сканирование портов ещё выполняется", output.getvalue())
        self.assertEqual(analyze.call_args.kwargs["progress_callback"].__name__, "_interactive_progress")
        print_report.assert_called_once()

    @patch("app.analyzers.resource_parser.port_scan.analyze_async")
    @patch("app.analyzers.resource_parser.sitemap.analyze")
    @patch("app.analyzers.resource_parser._fetch")
    def test_ip_target_skips_page_and_sitemap_checks(self, fetch, sitemap, port_scan):
        async def completed_scan(*_args):
            return {"status": "ok"}

        port_scan.return_value = completed_scan()
        report = resource_parser.analyze("192.0.2.10", max_pages=10)

        fetch.assert_not_called()
        sitemap.assert_not_called()
        self.assertEqual(report["summary"]["pages_visited"], 0)
        self.assertEqual(report["summary"]["pages_skipped"], "ip_target")

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

        completed_updates = [item for item in updates if item["status"] == "completed"]
        self.assertEqual([item["stage"] for item in completed_updates], list(CHECK_STAGES))
        self.assertEqual([item["completed"] for item in completed_updates], list(range(1, len(CHECK_STAGES) + 1)))
        self.assertTrue(all(item["total"] == len(CHECK_STAGES) for item in updates))
        self.assertEqual(updates[-1]["percent"], 100)

    @patch("app.main.active.analyze", return_value={"status": "ok"})
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
    def test_active_scan_is_reported_as_current_stage(self, *_mocks):
        updates = []
        analyze("example.com", progress_callback=updates.append)

        active_updates = [item for item in updates if item["stage"] == "active_scan"]
        self.assertEqual([item["status"] for item in active_updates], ["running", "completed"])
        self.assertEqual(active_updates[0]["completed"], active_updates[1]["completed"])

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