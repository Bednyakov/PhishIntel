"""Application orchestration."""

from collections.abc import Callable

from .analyzers import content, dns, domain, http, rdap, redirects, sitemap, subdomains, tls, whois
from .analyzers.common import normalize_target
from .history import record as record_history
from .models.report import Report
from .scoring.engine import score


CHECK_STAGES = (
    "domain",
    "dns",
    "ip",
    "rdap",
    "tls",
    "http",
    "redirects",
    "content",
    "whois",
    "sitemap",
    "subdomains",
    "history",
    "scoring",
)


def analyze(target: str, timeout: float = 8.0, progress_callback: Callable[[dict], None] | None = None) -> dict:
    """Run all checks and optionally report completed stages."""
    host, _ = normalize_target(target)

    completed = 0

    def complete(stage: str) -> None:
        nonlocal completed
        completed += 1
        if progress_callback is not None:
            progress_callback({"stage": stage, "completed": completed, "total": len(CHECK_STAGES), "percent": completed * 100 // len(CHECK_STAGES)})

    dns_result = dns.analyze(host)
    results = {"domain": domain.analyze(host)}
    complete("domain")
    results["dns"] = dns_result
    complete("dns")
    results["ip"] = dns.analyze_ip(dns_result)
    complete("ip")
    results["rdap"] = rdap.analyze(host, timeout)
    complete("rdap")
    results["tls"] = tls.analyze(host, timeout)
    complete("tls")
    results["http"] = http.analyze(host, timeout)
    complete("http")
    results["redirects"] = redirects.analyze(host, timeout)
    complete("redirects")
    results["content"] = content.analyze(results["http"])
    complete("content")
    results["http"].pop("_body", None)
    results["whois"] = whois.analyze(host, timeout)
    complete("whois")
    results["sitemap"] = sitemap.analyze(host, timeout)
    complete("sitemap")
    results["subdomains"] = subdomains.analyze(host, timeout=min(timeout, 3))
    complete("subdomains")
    results.update({"technologies": results["content"].get("technologies", []), "forms": results["content"].get("forms", []), "reputation": {"status": "not_configured"}, "history": record_history(host, dns_result, results["tls"])})
    complete("history")
    risk, indicators = score(results)
    complete("scoring")
    return Report(target=host, results=results, indicators=indicators, risk=risk).as_dict()
