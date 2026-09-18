"""User-facing recursive resource contact parser."""
from __future__ import annotations

import argparse

from ..analyzers import resource_parser
from ..i18n import tr


def _progress(update: dict) -> None:
    print(tr("progress_pages", completed=update["completed"], queued=update["queued"]), end="\r", flush=True)


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
    print("Technologies:")
    for technology in report.get("technologies", []):
        print(f"  - {technology}")
    port_scan = report.get("port_scan", {})
    print("Port scan:")
    print(f"  - status: {port_scan.get('status', 'unavailable')}")
    print(f"  - open ports: {port_scan.get('open_port_count', len(port_scan.get('ports', [])))}")
    for item in port_scan.get("ports", []):
        technology = f"; technology: {item.get('technology')}" if item.get("technology") else ""
        version = f" {item.get('version')}" if item.get("version") else ""
        print(f"  - {item.get('port')}/{item.get('protocol', 'tcp')}: {item.get('service', 'unknown')}{version}{technology}")
    domain = report.get("domain", {})
    if domain:
        print("Domain infrastructure:")
        for key in ("dns", "ip", "rdap", "whois", "tls", "redirects", "subdomains", "history"):
            if key in domain:
                value = domain[key]
                print(f"  - {key}: {value.get('status', 'ok') if isinstance(value, dict) else 'ok'}")
        redirect_report = domain.get("redirects")
        if isinstance(redirect_report, dict):
            print("Redirect chain:")
            print(f"  - transitions: {redirect_report.get('count', len(redirect_report.get('chain', [])))}")
            for item in redirect_report.get("chain", []):
                print(f"  - {item.get('status_code', '?')}: {item.get('from', '')} -> {item.get('to', '')}")
            if redirect_report.get("final_url"):
                print(f"  - final URL: {redirect_report['final_url']}")


def run(target: str, timeout: float = 8.0, max_pages: int = 500, max_depth: int = 8, concurrency: int = 8, show_progress: bool = True, show_report: bool = True) -> dict:
    report = resource_parser.analyze(target, timeout=timeout, max_pages=max_pages, max_depth=max_depth, concurrency=concurrency, progress_callback=_progress if show_progress else None)
    if show_report:
        print_report(report)
    return report


def run_cli(args: argparse.Namespace) -> dict:
    return run(args.target, args.timeout, args.max_pages, args.max_depth, args.concurrency, not args.no_progress, not args.stdout)


def interactive() -> dict:
    target = input(f"{tr('resource_url')}: ").strip()
    max_pages = int(input(f"{tr('max_pages')} [500]: ").strip() or "500")
    max_depth = int(input(f"{tr('max_depth')} [8]: ").strip() or "8")
    concurrency = int(input(f"{tr('concurrency')} [8]: ").strip() or "8")
    return run(target, max_pages=max_pages, max_depth=max_depth, concurrency=concurrency)