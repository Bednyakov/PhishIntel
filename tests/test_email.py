import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.analyzers.email import analyze, load_disposable_domains, normalize_email


class EmailTests(unittest.TestCase):
    def test_normalize_email(self):
        self.assertEqual(normalize_email("  User.Name@Example.COM "), "user.name@example.com")
        for value in ("bad", "a@@example.com", "a..b@example.com", "a b@example.com"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_email(value)

    def test_disposable_corpus_and_local_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            disposable = root / "disposable.json"
            rules = root / "rules.json"
            disposable.write_text(json.dumps(["mail.test"]), encoding="utf-8")
            rules.write_text(json.dumps([{"name": "Test Mail", "domain": "mail.test"}]), encoding="utf-8")
            self.assertEqual(load_disposable_domains(disposable), {"mail.test"})
            report = analyze("info@mail.test", rules=rules, disposable=disposable, resolver=lambda *_: [])
        self.assertEqual(report["summary"]["status"], "disposable")
        self.assertEqual(report["rules"]["matched"], ["Test Mail"])
        self.assertTrue(report["email"]["is_role"])
        self.assertEqual(report["smtp"]["status"], "not_checked")

    @patch("app.analyzers.email._dns_records", return_value={"mx": ["10 mx.example.test"], "a": [], "aaaa": [], "txt": []})
    def test_mx_and_smtp_are_explicit(self, _dns):
        report = analyze("person@example.com", resolver=lambda *_: [])
        self.assertEqual(report["summary"]["status"], "mx_valid")
        self.assertEqual(report["smtp"]["status"], "not_checked")


if __name__ == "__main__":
    unittest.main()