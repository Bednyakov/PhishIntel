"""Bounded static analysis of JavaScript resources."""

import hashlib
import re
import ssl
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse


_PATTERNS = (
    ("eval", "dynamic_code_execution", "medium"),
    ("new Function", "dynamic_code_execution", "medium"),
    ("atob", "base64_decoding", "low"),
    ("document.cookie", "cookie_access", "medium"),
    ("sendBeacon", "beacon_exfiltration", "medium"),
    ("XMLHttpRequest", "network_data_submission", "low"),
    ("fetch(", "network_data_submission", "low"),
    ("window.location", "script_redirect", "medium"),
    ("createElement('script')", "dynamic_script_injection", "medium"),
)


def _findings(source: str) -> list[dict]:
    lowered = source.lower()
    findings = []
    for needle, name, severity in _PATTERNS:
        count = lowered.count(needle.lower())
        if count:
            findings.append({"name": name, "severity": severity, "evidence": {"pattern": needle, "count": count}})
    base64_count = len(re.findall(r"[A-Za-z0-9+/]{160,}={0,2}", source))
    if base64_count:
        findings.append({"name": "long_encoded_string", "severity": "medium", "evidence": {"count": base64_count}})
    if len(source) > 100_000 and len(re.findall(r"\\x[0-9a-fA-F]{2}", source)) > 20:
        findings.append({"name": "obfuscated_javascript", "severity": "medium", "evidence": {"hex_escapes": len(re.findall(r"\\x[0-9a-fA-F]{2}", source))}})
    return findings


def analyze(http_result: dict, content: dict, timeout: float = 8.0, max_scripts: int = 20, max_size: int = 1_000_000) -> dict:
    if http_result.get("status") != "ok":
        return {"status": "unavailable", "error": http_result.get("error", "HTTP response unavailable"), "scripts": []}
    page_url = http_result.get("url", "")
    page_host = urlparse(page_url).hostname
    output = []
    for raw_url in content.get("scripts", [])[:max_scripts]:
        url = urljoin(page_url, raw_url)
        parsed = urlparse(url)
        item = {"url": url, "domain": parsed.hostname, "same_origin": parsed.hostname == page_host, "status": "unavailable", "sha256": None, "size": None, "findings": []}
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "phishintel/1.0", "Accept": "application/javascript,text/javascript,*/*"})
            with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
                body = response.read(max_size + 1)
                item.update({"status": "ok", "status_code": response.status, "content_type": response.headers.get("content-type"), "size": len(body)})
            if len(body) <= max_size:
                source = body.decode("utf-8", errors="replace")
                item["sha256"] = hashlib.sha256(body).hexdigest()
                item["findings"] = _findings(source)
            else:
                item["status"] = "too_large"
        except urllib.error.HTTPError as exc:
            item.update({"status": "unavailable", "status_code": exc.code, "error": str(exc)})
        except (OSError, UnicodeError) as exc:
            item["error"] = str(exc)
        output.append(item)
    return {"status": "ok", "scripts": output, "count": len(output), "truncated": len(content.get("scripts", [])) > max_scripts}