"""Content indicators and lightweight technology detection."""

import hashlib
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse


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
            self._form["fields"].append({"name": name or None, "type": field_type})
        elif tag == "script":
            src = values.get("src")
            if src:
                self.scripts.append(src)
        elif tag == "a":
            self.links_count += 1
        for attribute in ("src", "href", "action"):
            value = values.get(attribute)
            if value and "://" in value:
                self.external_domains.add(urlparse(value).hostname or value)

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
    if brand_match:
        indicators.append({"name": "brand_reference", "severity": "informational", "description": "Known brand referenced by page", "evidence": brand_match})
    return {"status": "ok", "title": title, "language": parser.language, "body_length": len(raw_body), "sha256": hashlib.sha256(raw_body if isinstance(raw_body, bytes) else body.encode()).hexdigest(), "forms": parser.forms, "keywords": found, "brand_match": brand_match, "technologies": technologies, "external_domains": sorted(parser.external_domains), "scripts": parser.scripts, "links_count": parser.links_count, "risk_indicators": indicators}
