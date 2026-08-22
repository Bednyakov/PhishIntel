import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.analyzers import sitemap
from app import history


class SitemapHistoryTests(unittest.TestCase):
    @patch("app.analyzers.sitemap._fetch")
    def test_sitemap_index_and_urlset(self, fetch):
        fetch.side_effect = [
            (200, b'<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>https://example.com/a.xml</loc></sitemap></sitemapindex>', "application/xml"),
            (200, b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/</loc></url><url><loc>https://example.com/login</loc></url></urlset>', "application/xml"),
        ]
        result = sitemap.analyze("example.com")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["count"], 2)
        self.assertEqual(fetch.call_count, 2)

    def test_history_records_and_detects_changes(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"PHISHINTEL_HISTORY_FILE": str(Path(directory) / "history.jsonl")}):
            first = history.record("example.com", {"status": "ok", "a": ["192.0.2.1"]}, {"status": "ok", "not_after": "2027"})
            second = history.record("example.com", {"status": "ok", "a": ["192.0.2.2"]}, {"status": "ok", "not_after": "2028"})
            self.assertEqual(first["count"], 1)
            self.assertEqual(second["count"], 2)
            self.assertEqual(len(second["changes"]), 2)
            self.assertEqual(len((Path(directory) / "history.jsonl").read_text().splitlines()), 2)


if __name__ == "__main__":
    unittest.main()