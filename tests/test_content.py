import unittest

from app.analyzers.content import analyze


class TechnologyDetectionTests(unittest.TestCase):
    @staticmethod
    def _http(body: str, headers: dict[str, str] | None = None) -> dict:
        return {
            "status": "ok",
            "url": "https://example.com/",
            "headers": headers or {"content-type": "text/html"},
            "_body": body.encode(),
        }

    def test_detects_wordpress_from_generator_and_rest_api(self):
        result = analyze(self._http("""
            <html><head>
              <meta name="generator" content="WordPress 6.6.1">
              <link rel="https://api.w.org/" href="https://example.com/wp-json/">
            </head><body>Custom theme</body></html>
        """))
        self.assertIn("WordPress", result["technologies"])

    def test_detects_wordpress_from_assets_when_meta_is_removed(self):
        result = analyze(self._http("""
            <script src="/assets/site.js"></script>
            <link rel="stylesheet" href="/wp-content/cache/theme/style.css">
            <script src="/wp-includes/js/wp-embed.min.js"></script>
        """))
        self.assertIn("WordPress", result["technologies"])

    def test_uses_headers_and_does_not_report_wordpress_for_plain_page(self):
        result = analyze(self._http(
            "<html><body><h1>Word</h1><p>Press release</p></body></html>",
            {"content-type": "text/html", "server": "nginx", "x-powered-by": "PHP/8.3"},
        ))
        self.assertNotIn("WordPress", result["technologies"])
        self.assertIn("Nginx", result["technologies"])
        self.assertIn("PHP", result["technologies"])

    def test_detects_framework_assets(self):
        result = analyze(self._http("""
            <script src="/_next/static/chunks/app.js"></script>
            <script src="https://cdn.example.com/jquery-3.7.1.min.js"></script>
            <link href="/css/bootstrap.min.css" rel="stylesheet">
        """))
        self.assertIn("Next.js", result["technologies"])
        self.assertIn("React", result["technologies"])
        self.assertIn("jQuery", result["technologies"])
        self.assertIn("Bootstrap", result["technologies"])


if __name__ == "__main__":
    unittest.main()