import unittest
from unittest.mock import patch

from app.analyzers.wallet import analyze, identify


class WalletTests(unittest.TestCase):
    def test_identifies_evm_address(self):
        result = identify("0x000000000000000000000000000000000000dEaD")
        self.assertEqual(result["blockchain"], "ethereum")
        self.assertTrue(result["valid"])

    def test_rejects_unknown_address(self):
        self.assertFalse(identify("not-a-wallet")["valid"])

    @patch("app.analyzers.wallet.requests.get")
    def test_report_contains_metrics(self, get):
        get.return_value.json.return_value = {"data": {}}
        get.return_value.raise_for_status.return_value = None
        report = analyze("0x0000000000000000000000000000000000000000")
        self.assertEqual(report["tool"], "wallet-check")
        self.assertIn("activity", report["metrics"])
        self.assertEqual(report["source"]["provider"], "blockchair")