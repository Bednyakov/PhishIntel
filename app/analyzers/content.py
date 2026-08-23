"""Content indicators and lightweight technology detection."""

import hashlib
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlparse


_WORDLIST_DIR = Path(__file__).resolve().parents[2] / "wordlists"


def _load_wordlist(filename: str, fallback: tuple[str, ...] = ()) -> tuple[str, ...]:
    try:
        values = [line.strip().lower() for line in (_WORDLIST_DIR / filename).read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    except (OSError, UnicodeError):
        values = list(fallback)
    return tuple(dict.fromkeys(values))


class _PageParser(HTMLParser):
    def __init__(self, page_url: str | None = None) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.page_origin = self._origin(page_url)
        self.title_parts: list[str] = []
        self.language: str | None = None
        self.forms: list[dict] = []
        self._form: dict | None = None
        self.scripts: list[str] = []
        self.external_domains: set[str] = set()
        self.resources: list[dict] = []
        self.downloads: list[dict] = []
        self.links_count = 0
        self._in_title = False

    @staticmethod
    def _origin(value: str | None) -> tuple[str, str, int | None] | None:
        if not value:
            return None
        parsed = urlparse(value)
        if not parsed.hostname:
            return None
        port = parsed.port
        return parsed.scheme.lower(), parsed.hostname.lower(), port

    def _resolve_action(self, action: str | None) -> tuple[str | None, bool | None]:
        if not action:
            return self.page_url, True if self.page_origin else None
        resolved = urljoin(self.page_url or "", action)
        if not self.page_origin:
            return resolved, None
        return resolved, self._origin(resolved) == self.page_origin

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "html":
            self.language = values.get("lang") or None
        elif tag == "title":
            self._in_title = True
        elif tag == "form":
            action, same_origin = self._resolve_action(values.get("action") or None)
            self._form = {"method": (values.get("method") or "GET").upper(), "action": action, "same_origin": same_origin, "fields": []}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            name = values.get("name") or values.get("id") or ""
            field_type = values.get("type", "text").lower()
            field = {"name": name or None, "type": field_type}
            for key in ("autocomplete", "placeholder", "aria-label"):
                if values.get(key):
                    field[key.replace("-", "_")] = values[key]
            self._form["fields"].append(field)
        elif tag == "script":
            src = values.get("src")
            if src:
                self.scripts.append(src)
        elif tag == "a":
            self.links_count += 1
            href = values.get("href")
            if href:
                self._record_resource(href, "link")
        elif tag in ("img", "script", "iframe", "video", "audio", "source", "object", "embed", "link"):
            for attribute in ("src", "href", "data"):
                if values.get(attribute):
                    self._record_resource(values[attribute], tag)
        for attribute in ("src", "href", "action"):
            value = values.get(attribute)
            if value and "://" in value:
                self.external_domains.add(urlparse(value).hostname or value)

    def _record_resource(self, value: str, kind: str) -> None:
        resolved = urljoin(self.page_url or "", value)
        parsed = urlparse(resolved)
        if parsed.scheme not in ("http", "https"):
            return
        item = {"url": resolved, "type": kind, "scheme": parsed.scheme}
        self.resources.append(item)
        if parsed.path.lower().endswith((".exe", ".msi", ".dmg", ".pkg", ".apk", ".ipa", ".scr", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".jar", ".zip", ".rar", ".7z")):
            self.downloads.append({"url": resolved, "type": kind, "extension": parsed.path.rsplit(".", 1)[-1].lower()})

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False
        elif tag.lower() == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)


def analyze(http_result: dict) -> dict:
    if http_result.get("status") != "ok":
        return {"status": "unavailable", "error": http_result.get("error", "HTTP response unavailable"), "title": None, "language": None, "body_length": 0, "sha256": None, "forms": [], "keywords": [], "technologies": [], "external_domains": [], "scripts": [], "links_count": 0, "risk_indicators": []}
    raw_body = http_result.get("_body", b"")
    body = raw_body.decode("utf-8", errors="replace") if isinstance(raw_body, bytes) else str(raw_body)
    lower = body.lower()
    parser = _PageParser(http_result.get("url"))
    parser.feed(body)
    keywords = _load_wordlist("phishing_keywords.txt", ("password", "sign in", "login", "verify", "wallet", "seed phrase", "recovery phrase"))
    found = sorted({word for word in keywords if word in lower})
    technologies = [name for name, marker in (("WordPress", "wp-content"), ("React", "react"), ("jQuery", "jquery"), ("Cloudflare", "cloudflare")) if marker in lower]
    indicators = []
    title = " ".join("".join(parser.title_parts).split()) or None
    brands = _load_wordlist("brands.txt", ("google", "microsoft", "apple", "paypal", "binance", "facebook", "instagram", "amazon"))
    brand_match = sorted({brand for brand in brands if brand in lower or (title and brand in title.lower())})
    page_url = http_result.get("url") or ""
    page_scheme = urlparse(page_url).scheme.lower()
    sensitive_names = ("password", "passwd", "card", "cvv", "token", "secret", "seed", "ssn", "passport", "phone", "email", "address", "iban")
    sensitive_types = {"password", "email", "tel", "number"}
    for form in parser.forms:
        sensitive_fields = []
        for field in form["fields"]:
            haystack = " ".join(str(field.get(key) or "").lower() for key in ("name", "type", "placeholder", "aria_label"))
            if field.get("type") in sensitive_types or any(name in haystack for name in sensitive_names):
                sensitive_fields.append(field.get("name") or field.get("type"))
        form["sensitive_fields"] = sorted(set(sensitive_fields))
        action = form.get("action") or page_url
        action_scheme = urlparse(action).scheme.lower()
        form["page_scheme"] = page_scheme or None
        form["action_scheme"] = action_scheme or None
        form["transport_encrypted"] = page_scheme == "https" and action_scheme == "https"
        form["external_action"] = form.get("same_origin") is False
        form["issues"] = []
        if form["sensitive_fields"] and form["method"] == "GET":
            form["issues"].append("sensitive_data_in_query")
        if form["sensitive_fields"] and not form["transport_encrypted"]:
            form["issues"].append("unencrypted_transport")
        if form["external_action"]:
            form["issues"].append("external_action")
        if form["sensitive_fields"] and not any("csrf" in str(field.get("name") or "").lower() or "xsrf" in str(field.get("name") or "").lower() or "token" in str(field.get("name") or "").lower() for field in form["fields"]):
            form["issues"].append("csrf_indicator_not_found")
    mixed_content = sorted({item["url"] for item in parser.resources if page_scheme == "https" and item["scheme"] == "http"})
    if brand_match:
        indicators.append({"name": "brand_reference", "severity": "informational", "description": "Known brand referenced by page", "evidence": brand_match})
    return {"status": "ok", "title": title, "language": parser.language, "body_length": len(raw_body), "sha256": hashlib.sha256(raw_body if isinstance(raw_body, bytes) else body.encode()).hexdigest(), "forms": parser.forms, "keywords": found, "brand_match": brand_match, "technologies": technologies, "external_domains": sorted(parser.external_domains), "scripts": parser.scripts, "links_count": parser.links_count, "risk_indicators": indicators, "mixed_content": mixed_content, "dangerous_downloads": parser.downloads, "query_parameters": sorted({key for item in parser.resources for key, _ in parse_qsl(urlparse(item["url"]).query) if key.lower() in sensitive_names})}
