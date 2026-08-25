"""Optional search visibility OSINT; never a risk verdict by itself."""

import json
import os
import ssl
import urllib.parse
import urllib.request


def analyze(domain: str, timeout: float = 8.0) -> dict:
    key = os.getenv("PHISHINTEL_BING_KEY")
    if not key:
        return {"status": "not_configured", "risk_weight": 0, "reason": "Search provider is not configured"}
    query = f"site:{domain}"
    request = urllib.request.Request("https://api.bing.microsoft.com/v7.0/search?" + urllib.parse.urlencode({"q": query, "count": 10, "responseFilter": "Webpages"}), headers={"Ocp-Apim-Subscription-Key": key, "User-Agent": "phishintel/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            data = json.loads(response.read(500_000).decode("utf-8", errors="replace"))
        pages = data.get("webPages", {})
        return {"status": "ok", "provider": "bing", "query": query, "total_estimated_matches": pages.get("totalEstimatedMatches", 0), "results": [{"name": item.get("name"), "url": item.get("url")} for item in pages.get("value", [])], "risk_weight": 0}
    except (OSError, ValueError) as exc:
        return {"status": "unavailable", "provider": "bing", "query": query, "error": str(exc), "risk_weight": 0}