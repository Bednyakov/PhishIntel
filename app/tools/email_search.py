"""User-facing email account search tool."""
from __future__ import annotations

import argparse

from ..analyzers import email_search


def _progress(update: dict) -> None:
    print(f"Проверено: {update['completed']}/{update['total']}", end="\r", flush=True)


def print_report(report: dict) -> None:
    summary = report["summary"]
    print("\r" + " " * 80)
    print("\nEmail Search\n============")
    print(f"Email: {report['query']['email']}")
    print(f"Checked: {summary['checked']} | Found: {summary['found']} | Not found: {summary['not_found']} | Uncertain: {summary['blocked'] + summary['timeout'] + summary['uncertain'] + summary['error']}")
    for item in report["results"]:
        marker = "[+]" if item["status"] == "found" else "[-]" if item["status"] == "not_found" else "[?]"
        print(f"{marker} {item['site']}: {item['status'].upper()} — {item['url']}")


def run(address: str, timeout: float = 8.0, rules: str | None = None, remote_cache: str | None = None, workers: int = 12, show_progress: bool = True, show_report: bool = True, offline: bool = False, update_sites: bool = False, include_disabled: bool = False) -> dict:
    report = email_search.analyze(address, timeout=timeout, rules=rules or email_search.DEFAULT_RULES, remote_cache=remote_cache or email_search.DEFAULT_REMOTE_CACHE, workers=workers, progress_callback=_progress if show_progress else None, offline=offline, update_sites=update_sites, include_disabled=include_disabled)
    if show_report:
        print_report(report)
    return report


def run_cli(args: argparse.Namespace) -> dict:
    return run(args.email, args.timeout, args.rules, args.remote_cache, args.workers, not args.no_progress, not args.stdout, args.offline, args.update_sites, args.include_disabled)


def interactive() -> dict:
    return run(input("Email: ").strip())