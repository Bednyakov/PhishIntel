"""Context-aware and explainable risk scoring."""

LEVELS = ((90, "critical"), (70, "high"), (40, "medium"), (15, "low"), (0, "informational"))


def _level(score: int) -> str:
    return next(name for threshold, name in LEVELS if score >= threshold)


def _indicator(name: str, severity: str, description: str, evidence=None) -> dict:
    item = {"name": name, "description": description, "severity": severity}
    if evidence is not None:
        item["evidence"] = evidence
    return item


def score(results: dict) -> tuple[dict, list[dict]]:
    content = results.get("content", {})
    keywords = set(content.get("keywords", []))
    forms = content.get("forms", [])
    header_issues = set(results.get("headers", {}).get("issues", []))
    active_findings = [finding for tool in results.get("active_scan", {}).get("tools", {}).values() for finding in tool.get("findings", []) if isinstance(finding, dict)]
    brand = bool(results.get("domain", {}).get("brand_match") or content.get("brand_match"))
    login_form = bool(forms)
    password_form = any(any(field.get("type") == "password" or any(word in (field.get("name") or "").lower() for word in ("password", "passwd", "card", "cvv", "token")) for field in form.get("fields", [])) or form.get("sensitive_fields") for form in forms)
    external_action = any(form.get("same_origin") is False or form.get("external_action") for form in forms)
    indicators = []
    if keywords:
        indicators.append(_indicator("keyword_presence", "informational", "Potentially sensitive keyword found on page", sorted(keywords)))
    if keywords and login_form:
        indicators.append(_indicator("keyword_login_form", "low", "Keyword is combined with a login form"))
    if keywords and password_form:
        indicators.append(_indicator("keyword_password_form", "medium", "Keyword is combined with a form containing sensitive fields"))
    if brand and login_form:
        indicators.append(_indicator("brand_login_form", "high", "Brand name is combined with a login form"))
    if brand and external_action:
        indicators.append(_indicator("brand_external_form", "critical", "Brand name is combined with a form posting to an external domain"))
    if any("unencrypted_transport" in form.get("issues", []) for form in forms):
        indicators.append(_indicator("unencrypted_sensitive_form", "high", "Sensitive form data may be transmitted without encryption"))
    if any("sensitive_data_in_query" in form.get("issues", []) for form in forms):
        indicators.append(_indicator("sensitive_data_in_query", "high", "Sensitive data is submitted using a GET query string"))
    if content.get("dangerous_downloads"):
        indicators.append(_indicator("dangerous_download", "medium", "Page links to potentially dangerous executable or script downloads", content["dangerous_downloads"]))
    if content.get("mixed_content"):
        indicators.append(_indicator("mixed_content", "medium", "HTTPS page references unencrypted HTTP resources", content["mixed_content"]))
    if "permissive_cors" in header_issues:
        indicators.append(_indicator("permissive_cors", "medium", "Server exposes a permissive CORS policy"))
    for finding in active_findings:
        severity = finding.get("severity")
        if severity in {"low", "medium", "high", "critical"}:
            indicators.append(_indicator(finding.get("name", "active_scan_finding"), severity, finding.get("description", "Active scanner reported a finding"), finding.get("evidence")))
    reasons = [item["description"] for item in indicators if item["severity"] != "informational"]
    weights = {"informational": 0, "low": 15, "medium": 40, "high": 70, "critical": 100}
    score_value = max((weights[item["severity"]] for item in indicators), default=0)
    level = "low" if not indicators and score_value == 0 and results else _level(score_value)
    return {"score": score_value, "level": level, "reasons": reasons}, indicators
