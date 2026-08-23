import unittest

from app.analyzers.active import _parse_nmap


class ActiveScannerTests(unittest.TestCase):
    def test_nmap_text_is_structured(self):
        result = _parse_nmap("""Nmap scan report for example.com (192.0.2.10)
Host is up (0.1s latency).
rDNS record for 192.0.2.10: host.example
PORT     STATE SERVICE VERSION
21/tcp   open  ftp
3306/tcp open  mysql MySQL 8.0
443/tcp  open  https
8080/tcp filtered http-proxy
""")
        self.assertTrue(result["host_up"])
        self.assertEqual(result["address"], "192.0.2.10")
        self.assertEqual(result["open_port_count"], 3)
        self.assertEqual({item["port"] for item in result["open_ports"]}, {21, 3306, 443})
        self.assertEqual({item["name"] for item in result["findings"]}, {"exposed_ftp", "exposed_mysql"})


if __name__ == "__main__":
    unittest.main()