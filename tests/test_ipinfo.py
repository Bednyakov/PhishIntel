import json
import unittest
from unittest.mock import patch

from app.analyzers import ipinfo


class IpinfoTests(unittest.TestCase):
    @staticmethod
    def _response(payload, status=200):
        response = type("Response", (), {})()
        response.status = status
        response.read = lambda _: json.dumps(payload).encode("utf-8")
        return response

    @patch("app.analyzers.ipinfo.urllib.request.urlopen")
    def test_returns_ipinfo_data_without_readme(self, urlopen):
        response = self._response({"ip": "192.0.2.1", "city": "Moscow", "readme": "https://ipinfo.io/missingauth"})
        urlopen.return_value.__enter__.return_value = response

        result = ipinfo.analyze("192.0.2.1")

        self.assertEqual(result, {"ip": "192.0.2.1", "city": "Moscow"})
        self.assertNotIn("readme", result)
        self.assertEqual(urlopen.call_args.args[0].full_url, "https://ipinfo.io/192.0.2.1/json")

    @patch("app.analyzers.ipinfo.urllib.request.urlopen")
    def test_invalid_response_is_omitted(self, urlopen):
        response = self._response({"readme": "https://ipinfo.io/missingauth"})
        urlopen.return_value.__enter__.return_value = response

        self.assertIsNone(ipinfo.analyze("192.0.2.1"))


if __name__ == "__main__":
    unittest.main()