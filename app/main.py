"""Application orchestration."""

from collections.abc import Callable

from .analyzers import active, content, dns, domain, dynamic, headers, http, ipinfo, javascript, rdap, redirects, reputation, resources, search, sitemap, subdomains, tls, whois
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
    "headers",
    "resources",
    "whois",
    "sitemap",
    "subdomains",
    "active_scan",
    "history",
    "reputation",
    "javascript",
    "dynamic",
    "search",
    "scoring",
)


def analyze(target: str, timeout: float = 8.0, progress_callback: Callable[[dict], None] | None = None, active_tools: tuple[str, ...] | None = None, dynamic_analysis: bool = False, search_analysis: bool = False, javascript_analysis: bool = True, thorough_active: bool = False) -> dict:
    """Run all checks and optionally report completed stages."""
    host, _ = normalize_target(target)

    completed = 0

    def report(stage: str, status: str) -> None:
        if progress_callback is not None:
            progress_callback({"stage": stage, "status": status, "completed": completed, "total": len(CHECK_STAGES), "percent": completed * 100 // len(CHECK_STAGES)})

    def complete(stage: str) -> None:
        nonlocal completed
        completed += 1
        report(stage, "completed")

    dns_result = dns.analyze(host)
    results = {"domain": domain.analyze(host)}
    complete("domain")
    results["dns"] = dns_result
    complete("dns")
    results["ip"] = dns.analyze_ip(dns_result)
    ipinfo_result = ipinfo.analyze(results["ip"].get("address"), timeout)
    if ipinfo_result is not None:
        results["ip"]["ipinfo"] = ipinfo_result
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
    results["headers"] = headers.analyze(results["http"])
    complete("headers")
    results["resources"] = resources.analyze(host, timeout)
    complete("resources")
    results["whois"] = whois.analyze(host, timeout)
    complete("whois")
    results["sitemap"] = sitemap.analyze(host, timeout)
    complete("sitemap")
    results["subdomains"] = subdomains.analyze(host, timeout=min(timeout, 3))
    complete("subdomains")
    report("active_scan", "running")
    results.update({"technologies": results["content"].get("technologies", []), "forms": results["content"].get("forms", []), "active_scan": active.analyze(host, timeout=max(timeout, 60.0), tools=active_tools, thorough=thorough_active)})
    report("active_scan", "completed")
    results["history"] = record_history(host, dns_result, results["tls"])
    complete("active_scan")
    complete("history")
    reputation_result = reputation.analyze(host, results["http"], results["redirects"], results["content"], results["ip"], timeout)
    if reputation_result.get("status") != "not_configured":
        results["reputation"] = reputation_result
    complete("reputation")
    results["javascript"] = javascript.analyze(results["http"], results["content"], timeout) if javascript_analysis else {"status": "not_requested"}
    complete("javascript")
    results["dynamic_analysis"] = dynamic.analyze(results["redirects"].get("final_url") or results["http"].get("url"), timeout=max(timeout, 15.0)) if dynamic_analysis else {"status": "not_requested"}
    complete("dynamic")
    if search_analysis:
        search_result = search.analyze(host, timeout)
        if search_result.get("status") != "not_configured":
            results["search_visibility"] = search_result
    complete("search")
    risk, indicators = score(results)
    complete("scoring")
    return Report(target=host, results=results, indicators=indicators, risk=risk).as_dict()
