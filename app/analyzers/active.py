"""Explicit opt-in wrappers for installed active security scanners."""

import json
import shutil
import subprocess
import re
from urllib.parse import urlparse


TOOLS = ("nmap", "nuclei", "zap")

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
    return {"host_up": host_up, "address": address, "reverse_dns": reverse_dns, "ports": ports, "open_ports": open_ports, "open_port_count": len(open_ports), "findings": findings}


def _safe_target(target: str) -> tuple[str, str]:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    if not parsed.hostname or parsed.hostname != parsed.hostname.lower() or any(char in parsed.hostname for char in ("/", "\\", "@")):
        raise ValueError("active scan target must be a hostname or URL")
    return parsed.hostname, parsed.geturl()


def _run(name: str, host: str, url: str, timeout: float) -> dict:
    executable = shutil.which(name)
    if not executable:
        return {"status": "not_configured", "error": f"{name} is not installed"}
    if name == "nmap":
        command = [executable, "-Pn", "--top-ports", "20", "--host-timeout", f"{max(1, int(timeout))}s", host]
    elif name == "nuclei":
        command = [executable, "-u", url, "-severity", "low,medium,high,critical", "-jsonl", "-silent", "-rate-limit", "5"]
    else:
        return {"status": "not_configured", "error": "ZAP requires an explicit daemon/API configuration; use --active-tool zap only after configuring it"}
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=max(1.0, timeout), check=False)
        output = completed.stdout[-200_000:]
        findings = []
        if name == "nuclei":
            for line in output.splitlines():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        parsed = _parse_nmap(output) if name == "nmap" else {}
        return {"status": "ok" if completed.returncode == 0 else "completed_with_errors", "return_code": completed.returncode, **parsed, "findings": findings or parsed.get("findings", []), "output": output, "stderr": completed.stderr[-20_000:]}
    except subprocess.TimeoutExpired as exc:
        return {"status": "timeout", "error": str(exc)}
    except OSError as exc:
        return {"status": "unavailable", "error": str(exc)}


def analyze(target: str, timeout: float = 60.0, tools: tuple[str, ...] = ()) -> dict:
    if not tools:
        return {"status": "disabled", "reason": "active scanning requires an explicit tool flag", "tools": {}}
    host, url = _safe_target(target)
    selected = tuple(dict.fromkeys(tools))
    unknown = [tool for tool in selected if tool not in TOOLS]
    if unknown:
        raise ValueError(f"unsupported active scanner: {unknown[0]}")
    return {"status": "ok", "scope": {"host": host, "url": url}, "tools": {tool: _run(tool, host, url, timeout) for tool in selected}}