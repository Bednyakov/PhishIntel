import unittest
from unittest.mock import patch

from app.analyzers import dns, rdap, subdomains, whois


class AnalyzerTests(unittest.TestCase):
    @patch("app.analyzers.subdomains.dns_analyze")
    def test_subdomain_bruteforce_probes_candidates_in_parallel_batch(self, dns_lookup):
        dns_lookup.side_effect = lambda candidate: {"status": "ok"} if candidate.startswith("www.") else {"status": "unavailable"}

        found = subdomains._brute_force(["www.example.com", "mail.example.com", "api.example.com"])

        self.assertEqual(found, {"www.example.com"})
        self.assertEqual(dns_lookup.call_count, 3)

    def test_ip_result_has_normalized_shape(self):
        result = dns.analyze_ip({"a": ["192.0.2.10"]})
        self.assertEqual(result["address"], "192.0.2.10")
        self.assertEqual(result["version"], 4)
        self.assertIn("reverse_dns", result)

    @patch("app.analyzers.whois._query")
    def test_whois_is_normalized(self, query):
        query.return_value = ("""Domain Name: example.com\nRegistrar: Example Registrar\nCreation Date: 2024-05-12T00:00:00Z\nUpdated Date: 2026-07-01T00:00:00Z\nRegistry Expiry Date: 2027-05-12T00:00:00Z\nName Server: NS1.EXAMPLE.COM\nDomain Status: clientTransferProhibited\n""", "tcp")
        result = whois.analyze("example.com")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["registrar"], "Example Registrar")
        self.assertEqual(result["name_servers"], ["ns1.example.com"])
        self.assertEqual(result["created"], "2024-05-12T00:00:00Z")

    @patch("app.analyzers.rdap.urllib.request.urlopen")
    def test_rdap_registration_is_normalized(self, urlopen):
        payload = b'''{"events":[{"eventAction":"registration","eventDate":"2024-05-12T00:00:00Z"},{"eventAction":"last changed","eventDate":"2026-07-01T00:00:00Z"},{"eventAction":"expiration","eventDate":"2027-05-12T00:00:00Z"}],"status":["active"],"entities":[]}'''
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, _): return payload
        bootstrap = b'{"services":[[["com"],["https://rdap.example"]]]}'
        urlopen.side_effect = [type("Response", (), {"__enter__": lambda s: s, "__exit__": lambda *args: None, "read": lambda s, _: bootstrap})(), Response()]
        result = rdap.analyze("example.com")
        self.assertEqual(result["registration"]["created"], "2024-05-12T00:00:00Z")
        self.assertEqual(result["registration"]["age"]["category"], "old")

    @patch("app.analyzers.rdap.urllib.request.urlopen")
    def test_rdap_404_is_not_found(self, urlopen):
        from urllib.error import HTTPError
        bootstrap = b'{"services":[[["ru"],["https://rdap.example"]]]}'
        bootstrap_response = type("Response", (), {"__enter__": lambda s: s, "__exit__": lambda *args: None, "read": lambda s, _: bootstrap})()
        urlopen.side_effect = [bootstrap_response, HTTPError("https://rdap.example/domain/example.ru", 404, "Not Found", {}, None)]
        result = rdap.analyze("example.ru")
        self.assertEqual(result["status"], "not_found")
        self.assertEqual(result["http_status"], 404)


if __name__ == "__main__":
    unittest.main()