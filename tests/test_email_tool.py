import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.tools.email import print_report, run


class EmailToolTests(unittest.TestCase):
    @patch("app.tools.email.email_search.analyze")
    @patch("app.tools.email.email_analyzer.analyze")
    def test_runs_both_stages_and_returns_contract(self, validation, search):
        validation.return_value = {
            "sources": {}, "email": {"disposable": False, "is_role": False},
            "dns": {"mx": []}, "smtp": {"status": "not_checked"},
            "summary": {"status": "mx_missing", "reasons": ["mx_missing"]},
        }
        search.return_value = {"sources": {}, "summary": {"checked": 1, "found": 1, "not_found": 0, "blocked": 0, "timeout": 0, "uncertain": 0, "error": 0}, "results": [{"site": "Example", "status": "found", "url": "https://example.test"}]}
        report = run(" User@Example.com ", show_progress=False, show_report=False)
        self.assertEqual(report["tool"], "email-check")
        self.assertEqual(report["target"], "user@example.com")
        validation.assert_called_once()
        search.assert_called_once()
        self.assertEqual(report["summary"]["found_accounts"], 1)

    def test_report_has_username_style_color_markers(self):
        report = {
            "query": {"email": "user@example.com"},
            "summary": {"status": "mx_valid"},
            "validation": {"email": {"disposable": False, "is_role": False}, "dns": {"mx": ["mx.example"]}, "smtp": {"status": "not_checked"}},
            "account_search": {"summary": {"checked": 1, "found": 1, "not_found": 0, "blocked": 0, "timeout": 0, "uncertain": 0, "error": 0}, "results": [{"site": "Example", "status": "found", "url": "https://example.test"}]},
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            print_report(report)
        self.assertIn("[+]", output.getvalue())
        self.assertIn("\033[32m", output.getvalue())


if __name__ == "__main__":
    unittest.main()