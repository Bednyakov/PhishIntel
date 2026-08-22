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
    reasons = [item["description"] for item in indicators if item["severity"] != "informational"]
    weights = {"informational": 0, "low": 15, "medium": 40, "high": 70, "critical": 100}
    score_value = max((weights[item["severity"]] for item in indicators), default=0)
    return {"score": score_value, "level": _level(score_value), "reasons": reasons}, indicators
