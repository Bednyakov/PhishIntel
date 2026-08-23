"""HTTP security-header and cookie hygiene checks."""

import re


def analyze(http_result: dict) -> dict:
    if http_result.get("status") != "ok":
        return {"status": "unavailable", "error": http_result.get("error", "HTTP response unavailable"), "missing": [], "issues": [], "cookies": []}
    headers = {str(key).lower(): str(value) for key, value in http_result.get("headers", {}).items()}
    required = ("strict-transport-security", "content-security-policy", "x-content-type-options", "referrer-policy", "permissions-policy")
    missing = [header for header in required if not headers.get(header)]
    issues = []
    if http_result.get("url", "").lower().startswith("https://") and "strict-transport-security" in missing:
        issues.append("missing_hsts")
    if "content-security-policy" in missing:
        issues.append("missing_csp")
    if headers.get("access-control-allow-origin") == "*":
        issues.append("permissive_cors")
    cookies = []
    raw_cookies = http_result.get("headers", {}).get("set-cookie", "")
    if isinstance(raw_cookies, str):
        cookie_lines = raw_cookies.splitlines()
    elif isinstance(raw_cookies, (list, tuple)):
        cookie_lines = list(raw_cookies)
    else:
        cookie_lines = []
    for raw in cookie_lines:
        name = raw.split("=", 1)[0].strip()
        lower = raw.lower()
        cookies.append({"name": name, "secure": "secure" in lower, "httponly": "httponly" in lower, "samesite": (re.search(r"samesite=([^;]+)", lower) or [None, None])[1]})
        if http_result.get("url", "").lower().startswith("https://") and "secure" not in lower:
            issues.append("cookie_without_secure")
        if "httponly" not in lower:
            issues.append("cookie_without_httponly")
    return {"status": "ok", "missing": missing, "issues": sorted(set(issues)), "cookies": cookies, "cors": {key: value for key, value in headers.items() if key.startswith("access-control-")}}