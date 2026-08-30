"""Wrappers for installed active security scanners."""

import json
import shutil
import subprocess
import re
import os
from urllib.parse import urlparse


TOOLS = ("nmap", "nuclei", "zap")
_NMAP_THOROUGH_TIMEOUT = 900

_NMAP_PORT = re.compile(r"^(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?$")
_RISKY_SERVICES = {
    "ftp": ("high", "FTP is exposed; credentials may be transmitted in cleartext"),
    "telnet": ("high", "Telnet is exposed and does not provide encrypted transport"),
    "rpcbind": ("high", "rpcbind is exposed and may disclose RPC services"),
    "mysql": ("high", "MySQL is exposed to the network; it should normally be restricted"),
    "pop3": ("medium", "POP3 is exposed without transport encryption"),
    "imap": ("medium", "IMAP is exposed without transport encryption"),
    "smtp": ("medium", "SMTP is exposed; relay and authentication policy should be reviewed"),
}


def _parse_nmap(output: str) -> dict:
    host_up = "Host is up" in output
    address = None
    reverse_dns = None
    match = re.search(r"Nmap scan report for (?:[^\s(]+ \()?([^\s)]+)", output)
    if match:
        address = match.group(1)
    rdns = re.search(r"rDNS record for [^:]+:\s*(\S+)", output)
    if rdns:
        reverse_dns = rdns.group(1).rstrip(".")
    ports = []
    findings = []
    for line in output.splitlines():
        match = _NMAP_PORT.match(line.strip())
        if not match:
            continue
        port, protocol, state, service, version = match.groups()
        item = {"port": int(port), "protocol": protocol, "state": state, "service": service, "version": version or None}
        ports.append(item)
        if state == "open" and service in _RISKY_SERVICES:
            severity, description = _RISKY_SERVICES[service]
            findings.append({"name": f"exposed_{service}", "severity": severity, "description": description, "evidence": item})
    open_ports = [item for item in ports if item["state"] == "open"]
    scripts = []
    for line in output.splitlines():
        script_match = re.match(r"\|_?\s*([^:]+):\s*(.*)$", line.strip())
        if script_match:
            scripts.append({"name": script_match.group(1).strip(), "output": script_match.group(2).strip()})
    return {"host_up": host_up, "address": address, "reverse_dns": reverse_dns, "ports": ports, "open_ports": open_ports, "open_port_count": len(open_ports), "findings": findings, "nse_scripts": scripts, "nse_script_count": len(scripts)}


def _safe_target(target: str) -> tuple[str, str]:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    if not parsed.hostname or parsed.hostname != parsed.hostname.lower() or any(char in parsed.hostname for char in ("/", "\\", "@")):
        raise ValueError("active scan target must be a hostname or URL")
    return parsed.hostname, parsed.geturl()


def _run_nmap_thorough(executable: str, host: str, timeout: float) -> dict:
    """Run bounded Nmap phases so one slow NSE script cannot erase all data."""
    nmap_timeout = max(_NMAP_THOROUGH_TIMEOUT, timeout)

    def execute(command: list[str], phase_timeout: float) -> tuple[str, str, int]:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=phase_timeout, check=False)
        return completed.stdout[-200_000:], completed.stderr[-20_000:], completed.returncode

    result = {"status": "completed_with_errors", "ports": [], "open_ports": [], "findings": [], "nse_scripts": [], "nse_script_count": 0}
    phases = []
    try:
        # Start with a bounded discovery pass.  A full 1-65535 scan can spend
        # the whole subprocess timeout on filtered ports and must not prevent
        # the report from containing the ports already found.
        discovery = [executable, "-Pn", "--top-ports", "20", "--host-timeout", f"{max(1, int(timeout))}s", host]
        output, stderr, code = execute(discovery, nmap_timeout)
        parsed = _parse_nmap(output)
        result.update(parsed, output=output, stderr=stderr, return_code=code)
        phases.append({"name": "port_discovery", "status": "ok" if code == 0 else "completed_with_errors"})
        ports = ",".join(str(item["port"]) for item in parsed["open_ports"])
        if not ports:
            result["phases"] = phases
            result["status"] = "ok" if code == 0 else "completed_with_errors"
            return result
        service_command = [executable, "-Pn", "-p", ports, "-sV", "--version-all", host]
        output, stderr, code = execute(service_command, max(60.0, nmap_timeout))
        service = _parse_nmap(output)
        result.update({"ports": service["ports"], "open_ports": service["open_ports"], "open_port_count": service["open_port_count"], "address": service["address"], "reverse_dns": service["reverse_dns"], "output": result.get("output", "") + "\n" + output, "stderr": (result.get("stderr", "") + "\n" + stderr)[-20_000:], "return_code": code})
        phases.append({"name": "service_detection", "status": "ok" if code == 0 else "completed_with_errors"})
        nse_command = [executable, "-Pn", "-p", ports, "--script=default,vuln", host]
        try:
            output, stderr, code = execute(nse_command, nmap_timeout)
        except subprocess.TimeoutExpired as exc:
            phases.append({"name": "nse", "status": "timeout"})
            result["nse_error"] = str(exc)
            result["status"] = "completed_with_errors"
            result["phases"] = phases
            return result
        nse = _parse_nmap(output)
        result.update({"nse_scripts": nse["nse_scripts"], "nse_script_count": nse["nse_script_count"], "output": result.get("output", "") + "\n" + output, "stderr": (result.get("stderr", "") + "\n" + stderr)[-20_000:]})
        result["findings"].extend(nse["findings"])
        phases.append({"name": "nse", "status": "ok" if code == 0 else "completed_with_errors"})
        if os.geteuid() == 0:
            try:
                output, stderr, code = execute([executable, "-Pn", "-p", ports, "-O", host], nmap_timeout)
                result["os_detection"] = output
                phases.append({"name": "os_detection", "status": "ok" if code == 0 else "completed_with_errors"})
            except (OSError, subprocess.TimeoutExpired) as exc:
                result["os_detection_error"] = str(exc)
                phases.append({"name": "os_detection", "status": "timeout"})
        result["status"] = "ok"
        result["phases"] = phases
        return result
    except (OSError, subprocess.TimeoutExpired) as exc:
        result.setdefault("open_port_count", len(result.get("open_ports", [])))
        result.setdefault("address", None)
        result.setdefault("reverse_dns", None)
        result.setdefault("host_up", False)
        result.setdefault("output", "")
        result.setdefault("stderr", "")
        result["error"] = str(exc)
        result["phases"] = phases
        return result


def _run(name: str, host: str, url: str, timeout: float, thorough: bool = False) -> dict:
    executable = shutil.which(name)
    if not executable:
        return {"status": "not_configured", "error": f"{name} is not installed"}
    if name == "nmap":
        if thorough:
            return _run_nmap_thorough(executable, host, timeout)
        command = [executable, "-Pn", "--top-ports", "20", "--host-timeout", f"{max(1, int(timeout))}s", host]
    elif name == "nuclei":
        command = [executable, "-u", url, "-severity", "low,medium,high,critical", "-jsonl", "-silent"]
        if not thorough:
            command.extend(("-rate-limit", "5"))
    else:
        return {"status": "not_configured", "error": "ZAP requires an explicit daemon/API configuration; use --active-tool zap only after configuring it"}
    def execute(scan_command: list[str], command_timeout: float | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            scan_command,
            capture_output=True,
            text=True,
            # Full-port/version/NSE scans can legitimately take longer than
            # the ordinary HTTP timeout supplied by the CLI.
            timeout=command_timeout if command_timeout is not None else max(60.0, timeout * (4 if thorough else 1)),
            check=False,
        )

    try:
        completed = execute(command)
        output = completed.stdout[-200_000:]
        parsed = _parse_nmap(output) if name == "nmap" else {}
        fallback = None
        if name == "nmap" and thorough and (completed.returncode != 0 or not parsed.get("ports")):
            fallback_command = [
                executable,
                "-Pn",
                "--top-ports",
                "20",
                "-sV",
                "--version-all",
                "-sC",
                "--script=default,vuln",
                "--host-timeout",
                f"{max(1, int(timeout))}s",
                host,
            ]
            try:
                fallback_output, fallback_stderr, fallback_code = execute(fallback_command, max(30.0, timeout))
                fallback = _parse_nmap(fallback_output)
                if fallback.get("ports"):
                    parsed = fallback
                    output = fallback_output
            except (OSError, subprocess.TimeoutExpired) as exc:
                fallback = {"error": str(exc)}
        findings = []
        if name == "nuclei":
            for line in output.splitlines():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        result = {"status": "ok" if completed.returncode == 0 else "completed_with_errors", "return_code": completed.returncode, **parsed, "findings": findings or parsed.get("findings", []), "output": output, "stderr": completed.stderr[-20_000:]}
        if fallback is not None:
            result["fallback"] = "top_ports_20_with_service_detection_and_nse"
            result["fallback_details"] = fallback if not fallback.get("ports") else {"open_port_count": fallback["open_port_count"]}
        return result
    except subprocess.TimeoutExpired as exc:
        if name == "nmap" and thorough:
            fallback_command = [executable, "-Pn", "--top-ports", "20", "-sV", "--version-all", "-sC", "--script=default,vuln", "--host-timeout", f"{max(1, int(timeout))}s", host]
            try:
                fallback_completed = execute(fallback_command, max(30.0, timeout))
                fallback_output = fallback_completed.stdout[-200_000:]
                parsed = _parse_nmap(fallback_output)
                return {"status": "completed_with_errors", "return_code": fallback_completed.returncode, **parsed, "findings": parsed.get("findings", []), "output": fallback_output, "stderr": fallback_completed.stderr[-20_000:], "fallback": "top_ports_20_with_service_detection_and_nse", "full_scan_error": str(exc)}
            except (OSError, subprocess.TimeoutExpired) as fallback_exc:
                return {"status": "timeout", "error": str(exc), "fallback_error": str(fallback_exc)}
        return {"status": "timeout", "error": str(exc)}
    except OSError as exc:
        return {"status": "unavailable", "error": str(exc)}


def analyze(target: str, timeout: float = 60.0, tools: tuple[str, ...] | None = None, thorough: bool = False) -> dict:
    """Run selected scanners, or all supported scanners by default."""
    host, url = _safe_target(target)
    # None means all scanners; an empty tuple explicitly disables scanning.
    selected = tuple(dict.fromkeys(TOOLS if tools is None else tools))
    unknown = [tool for tool in selected if tool not in TOOLS]
    if unknown:
        raise ValueError(f"unsupported active scanner: {unknown[0]}")
    tool_results = {tool: _run(tool, host, url, timeout, thorough=thorough) for tool in selected}
    configured = [result for result in tool_results.values() if result["status"] not in ("not_configured", "unavailable")]
    return {"status": "ok" if configured else "not_configured", "scope": {"host": host, "url": url}, "tools": tool_results}