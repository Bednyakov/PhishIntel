import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main
from app.core.profiles import get_profile
from app.tools.domain_scan import DomainScanOptions, run


class ArchitectureTests(unittest.TestCase):
    def test_profiles_have_expected_capabilities(self):
        self.assertFalse(get_profile("quick").dynamic)
        self.assertFalse(get_profile("quick").javascript)
        self.assertTrue(get_profile("full").javascript)
        self.assertTrue(get_profile("full").search)
        self.assertTrue(get_profile("full").dynamic)
        self.assertTrue(get_profile("security").dynamic)
        self.assertTrue(get_profile("security").active)
        self.assertTrue(get_profile("security").javascript)

    @patch("app.tools.domain_scan.analyze", return_value={"target": "example.com"})
    def test_tool_translates_profile_to_pipeline_options(self, analyze):
        run(DomainScanOptions("example.com", "quick"))
        analyze.assert_called_once_with(
            "example.com",
            timeout=8.0,
            progress_callback=None,
            active_tools=(),
            dynamic_analysis=False,
            search_analysis=False,
            thorough_active=False,
            javascript_analysis=False,
        )

    @patch("main._register_tools")
    def test_main_without_arguments_can_exit_from_menu(self, _register):
        with patch("main.all_tools", return_value=()), patch("builtins.input", return_value="0"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main.main([]), 0)

    @patch("main._register_tools")
    def test_interactive_report_is_saved_instead_of_printed_as_json(self, _register):
        report = {"target": "example.com", "risk": {"level": "low"}}
        tool = main.Tool("domain-scan", "Анализ домена", "", lambda: report, lambda _: report)
        with tempfile.TemporaryDirectory() as directory, patch("main.all_tools", return_value=(tool,)), patch("main._save_report", return_value=Path(directory) / "example.json") as save_report, patch("builtins.input", return_value="1"), contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(main.main([]), 0)

        save_report.assert_called_once_with(report)
        self.assertNotIn(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True), stdout.getvalue())
        self.assertIn("Отчёт сохранён:", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()