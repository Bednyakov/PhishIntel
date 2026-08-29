import unittest
import subprocess
from unittest.mock import patch

from app.analyzers.active import _parse_nmap, analyze


class ActiveScannerTests(unittest.TestCase):
    @patch("app.analyzers.active._run")
    def test_empty_tool_list_disables_all_active_scanners(self, run):
        result = analyze("example.com", tools=())

        run.assert_not_called()
        self.assertEqual(result["status"], "not_configured")
        self.assertEqual(result["tools"], {})

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

    @patch("app.analyzers.active.shutil.which", return_value=None)
    def test_missing_scanners_are_reported_without_failure(self, _which):
        result = analyze("example.com")

        self.assertEqual(result["status"], "not_configured")
        self.assertEqual(set(result["tools"]), {"nmap", "nuclei", "zap"})
        self.assertTrue(all(item["status"] == "not_configured" for item in result["tools"].values()))

    @patch("app.analyzers.active.subprocess.run")
    @patch("app.analyzers.active.shutil.which", return_value="/usr/bin/nmap")
    def test_thorough_nmap_uses_full_ports_service_detection_os_and_safe_vuln_nse(self, _which, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "Nmap scan report for example.com (192.0.2.10)\nHost is up.\n80/tcp open http\n"
        run.return_value.stderr = ""

        analyze("example.com", tools=("nmap",), thorough=True)

        command = run.call_args_list[0].args[0]
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn("--top-ports", command)
        self.assertEqual(run.call_args_list[0].kwargs["timeout"], 300.0)
        self.assertTrue(any("-p" in command and "-sV" in command and "--version-all" in command for command in commands))
        self.assertTrue(any("--script=default,vuln" in command for command in commands))
        self.assertNotIn("exploit", " ".join(" ".join(command) for command in commands))
        self.assertNotIn("brute", " ".join(" ".join(command) for command in commands))

    @patch("app.analyzers.active.subprocess.run")
    @patch("app.analyzers.active.shutil.which", return_value="/usr/bin/nuclei")
    def test_thorough_nuclei_does_not_apply_quick_rate_limit(self, _which, run):
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""

        analyze("example.com", tools=("nuclei",), thorough=True)

        command = run.call_args.args[0]
        self.assertIn("-severity", command)
        self.assertIn("low,medium,high,critical", command)
        self.assertNotIn("-rate-limit", command)

    @patch("app.analyzers.active.subprocess.run")
    @patch("app.analyzers.active.shutil.which", return_value="/usr/bin/nmap")
    def test_thorough_nmap_falls_back_to_top_ports_when_full_scan_has_no_parseable_output(self, _which, run):
        run.side_effect = [
            type("Completed", (), {"returncode": 0, "stdout": "Nmap scan report for example.com (192.0.2.10)\nHost is up.\n80/tcp open http\n", "stderr": ""})(),
            type("Completed", (), {"returncode": 0, "stdout": "Nmap scan report for example.com (192.0.2.10)\nHost is up.\n80/tcp open http Apache httpd 2.4\n", "stderr": ""})(),
            type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
        ]

        result = analyze("example.com", tools=("nmap",), thorough=True)["tools"]["nmap"]

        self.assertEqual(result["open_port_count"], 1)
        self.assertEqual(run.call_count, 3)
        self.assertIn("-sV", run.call_args_list[1].args[0])
        self.assertIn("--script=default,vuln", run.call_args_list[2].args[0])

    @patch("app.analyzers.active.subprocess.run")
    @patch("app.analyzers.active.shutil.which", return_value="/usr/bin/nmap")
    def test_thorough_nmap_timeout_still_returns_service_scan(self, _which, run):
        run.side_effect = [
            subprocess.TimeoutExpired(["nmap"], 240),
            type("Completed", (), {"returncode": 0, "stdout": "Nmap scan report for example.com (192.0.2.10)\nHost is up.\n80/tcp open http Apache httpd 2.4\n", "stderr": ""})(),
        ]

        result = analyze("example.com", tools=("nmap",), thorough=True)["tools"]["nmap"]

        self.assertEqual(result["status"], "completed_with_errors")
        self.assertEqual(result["open_port_count"], 1)
        self.assertEqual(result["open_ports"][0]["version"], "Apache httpd 2.4")
        self.assertIn("error", result)
        self.assertEqual(run.call_count, 2)

    @patch("app.analyzers.active.subprocess.run")
    @patch("app.analyzers.active.shutil.which", return_value="/usr/bin/nmap")
    def test_thorough_nmap_nse_timeout_is_reported_without_erasing_ports(self, _which, run):
        run.side_effect = [
            type("Completed", (), {"returncode": 0, "stdout": "Nmap scan report for example.com (192.0.2.10)\nHost is up.\n80/tcp open http\n", "stderr": ""})(),
            type("Completed", (), {"returncode": 0, "stdout": "Nmap scan report for example.com (192.0.2.10)\nHost is up.\n80/tcp open http Apache httpd 2.4\n", "stderr": ""})(),
            subprocess.TimeoutExpired(["nmap"], 120),
        ]

        result = analyze("example.com", tools=("nmap",), thorough=True)["tools"]["nmap"]

        self.assertEqual(result["open_port_count"], 1)
        self.assertEqual(result["open_ports"][0]["version"], "Apache httpd 2.4")
        self.assertEqual(result["phases"][-1]["status"], "timeout")
        self.assertIn("nse_error", result)


if __name__ == "__main__":
    unittest.main()