"""User-facing username search tool."""
from __future__ import annotations

import argparse
from pathlib import Path
from ..analyzers import username

RESET = "\033[0m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"


def _color(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{RESET}" if enabled else text


def _marker(status: str) -> tuple[str, str]:
    if status == "found":
        return "[+]", GREEN
    if status == "not_found":
        return "[-]", RED
    return "[?]", YELLOW


def _progress(update: dict) -> None:
    # The final table contains every resource; progress stays compact.
    print(f"Проверено: {update['completed']}/{update['total']}", end="\r", flush=True)


def print_report(report: dict, color: bool = True) -> None:
    summary = report["summary"]
    rows = report["results"]
    width = max([len(item["site"]) for item in rows] + [4])
    print("\r" + " " * 80)
    print("\nUsername Search")
    print("===============")
    print(f"Username: {report['query']['username']}")
    print(f"Checked: {summary['checked']} | Found: {summary['found']} | Not found: {summary['not_found']} | Uncertain: {summary.get('blocked', 0) + summary.get('waf', 0) + summary.get('rate_limited', 0) + summary.get('timeout', 0) + summary.get('illegal', 0) + summary.get('error', 0)}")
    print("\n" + "-" * (width + 58))
    print(f"  {'Result':<8} {'Resource':<{width}}  URL")
    print("-" * (width + 58))
    for item in rows:
        marker, code = _marker(item["status"])
        status = "FOUND" if item["status"] == "found" else item["status"].replace("_", " ").upper()
        marker_text = _color(marker, code, color)
        site_text = _color(f"{item['site']:<{width}}", GREEN, color) if item["status"] == "found" else f"{item['site']:<{width}}"
        print(f"  {marker_text:<8} {site_text}  {item['url']} ({status})")
    print("-" * (width + 58))


def run(value: str, timeout: float = 8.0, wordlist: str | Path | None = None, rules: str | Path | None = None, workers: int = 12, show_progress: bool = True, show_report: bool = True, color: bool = True, offline: bool = False, update_sites: bool = False) -> dict:
    report = username.analyze(value, timeout=timeout, wordlist=wordlist or username.DEFAULT_WORDLIST, rules=rules or username.DEFAULT_RULES, workers=workers, progress_callback=_progress if show_progress else None, offline=offline, update_sites=update_sites)
    if show_report:
        print_report(report, color=color)
    return report


def run_cli(args: argparse.Namespace) -> dict:
    return run(args.username, args.timeout, args.wordlist, args.rules, args.workers, not args.no_progress, not args.stdout, not args.no_color, args.offline, args.update_sites)


def interactive() -> dict:
    return run(input("Username (with or without @): ").strip())