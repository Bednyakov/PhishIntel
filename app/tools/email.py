"""Unified user-facing email check."""
from __future__ import annotations

import argparse
from pathlib import Path

from ..analyzers import email as email_analyzer
from ..analyzers import email_search

RESET = "\033[0m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"


def _color(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{RESET}" if enabled else text


def _marker(status: str) -> tuple[str, str]:
    if status in {"found", "accepted", "mx_valid"}:
        return "[+]", GREEN
    if status in {"not_found", "rejected", "mx_missing", "disposable"}:
        return "[-]", RED
    return "[?]", YELLOW


def _progress(update: dict) -> None:
    print(f"Проверено: {update['completed']}/{update['total']}", end="\r", flush=True)


def print_report(report: dict, color: bool = True) -> None:
    validation = report["validation"]
    summary = report["summary"]
    search = report["account_search"]
    search_summary = search["summary"]
    print("\r" + " " * 80)
    print("\nEmail Check")
    print("===========")
    print(f"Email: {report['query']['email']}")
    marker, code = _marker(summary["status"])
    print(f"Status: {_color(marker, code, color)} {summary['status'].replace('_', ' ').upper()}")
    print(f"Syntax: {_color('VALID', GREEN, color)} | Disposable: {validation['email']['disposable']} | Role: {validation['email']['is_role']}")
    print(f"MX: {', '.join(validation['dns']['mx']) or _color('not found', RED, color)}")
    print(f"SMTP: {validation['smtp']['status']}")
    print(f"Account search: checked {search_summary['checked']} | found {_color(str(search_summary['found']), GREEN, color)} | not found {search_summary['not_found']} | uncertain {search_summary['uncertain'] + search_summary['blocked'] + search_summary['timeout'] + search_summary['error']}")
    print("\n" + "-" * 78)
    print("  Result   Resource")
    print("-" * 78)
    for item in search["results"]:
        marker, code = _marker(item["status"])
        status = item["status"].replace("_", " ").upper()
        print(f"  {_color(marker, code, color)}    {item['site']} — {status} ({item['url']})")
    print("-" * 78)


def run(address: str, timeout: float = 8.0, rules: str | Path | None = None, disposable: str | Path | None = None, smtp: bool = False, search_rules: str | Path | None = None, remote_cache: str | Path | None = None, workers: int = 12, show_progress: bool = True, show_report: bool = True, color: bool = True, offline: bool = False, update_sites: bool = False, include_disabled: bool = False) -> dict:
    normalized = email_analyzer.normalize_email(address)
    validation = email_analyzer.analyze(normalized, timeout=timeout, rules=rules or email_analyzer.DEFAULT_RULES, disposable=disposable or email_analyzer.DEFAULT_DISPOSABLE, check_smtp=True)
    account_search = email_search.analyze(normalized, timeout=timeout, rules=search_rules or email_search.DEFAULT_RULES, remote_cache=remote_cache or email_search.DEFAULT_REMOTE_CACHE, workers=workers, progress_callback=_progress if show_progress else None, offline=offline, update_sites=update_sites, include_disabled=include_disabled)
    report = {
        "tool": "email-check",
        "target": normalized,
        "query": {"email": normalized},
        "sources": {"validation": validation["sources"], "account_search": account_search["sources"]},
        "validation": validation,
        "account_search": account_search,
        "summary": {"status": validation["summary"]["status"], "reasons": validation["summary"]["reasons"], "found_accounts": account_search["summary"]["found"], "checked_accounts": account_search["summary"]["checked"]},
    }
    if show_report:
        print_report(report, color=color)
    return report


def run_cli(args: argparse.Namespace) -> dict:
    return run(args.email, args.timeout, args.rules, args.disposable, args.smtp, args.search_rules, args.remote_cache, args.workers, not args.no_progress, not args.stdout, not args.no_color, args.offline, args.update_sites, args.include_disabled)


def interactive() -> dict:
    return run(input("Email: ").strip(), smtp=True)