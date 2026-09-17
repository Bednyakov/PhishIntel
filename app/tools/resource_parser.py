"""User-facing recursive resource contact parser."""
from __future__ import annotations

import argparse

from ..analyzers import resource_parser


def _progress(update: dict) -> None:
    print(f"Проверено страниц: {update['completed']} | в очереди: {update['queued']}", end="\r", flush=True)


def print_report(report: dict) -> None:
    print("\r" + " " * 100)
    print("\nResource Parser\n===============")
    print(f"Target: {report['target']}")
    print(f"Pages scanned: {report['summary']['pages_visited']}")
    for key, values in report["contacts"].items():
        print(f"{key.title()}: {len(values)}")
        for value in values:
            print(f"  - {value}")
    for key, values in report.get("external_resources", {}).items():
        print(f"{key.replace('_', ' ').title()}: {len(values)}")
        for value in values:
            print(f"  - {value}")
    domain = report.get("domain", {})
    if domain:
        print("Domain infrastructure:")
        for key in ("dns", "ip", "rdap", "whois", "tls", "redirects", "subdomains", "history"):
            if key in domain:
                value = domain[key]
                print(f"  - {key}: {value.get('status', 'ok') if isinstance(value, dict) else 'ok'}")


def run(target: str, timeout: float = 8.0, max_pages: int = 500, max_depth: int = 8, concurrency: int = 8, show_progress: bool = True, show_report: bool = True) -> dict:
    report = resource_parser.analyze(target, timeout=timeout, max_pages=max_pages, max_depth=max_depth, concurrency=concurrency, progress_callback=_progress if show_progress else None)
    if show_report:
        print_report(report)
    return report


def run_cli(args: argparse.Namespace) -> dict:
    return run(args.target, args.timeout, args.max_pages, args.max_depth, args.concurrency, not args.no_progress, not args.stdout)


def interactive() -> dict:
    target = input("Домен или URL ресурса: ").strip()
    max_pages = int(input("Максимальное число страниц [500]: ").strip() or "500")
    max_depth = int(input("Глубина поиска [8]: ").strip() or "8")
    concurrency = int(input("Параллельных запросов [8]: ").strip() or "8")
    return run(target, max_pages=max_pages, max_depth=max_depth, concurrency=concurrency)