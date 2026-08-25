#!/usr/bin/env python3
"""Command-line scanner for phishintel."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
import re

from app.main import analyze
from app.analyzers.common import normalize_target


def _render_progress(update: dict) -> None:
    width = 28
    completed = update["completed"]
    total = update["total"]
    filled = width * completed // total
    bar = "#" * filled + "-" * (width - filled)
    print(f"\rПроверка: [{bar}] {completed}/{total} ({update['percent']}%) — {update['stage']}", end="", file=sys.stderr, flush=True)
    if completed == total:
        print(file=sys.stderr)


def _report_path(output_dir: str, domain: str) -> Path:
    normalized_domain, _ = normalize_target(domain)
    safe_domain = re.sub(r"[^A-Za-z0-9._-]+", "_", normalized_domain).strip("._") or "report"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    return Path(output_dir) / f"{safe_domain}_{timestamp}.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Domain intelligence and phishing risk analyzer")
    parser.add_argument("domain", help="domain name or URL")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--compact", action="store_true", help="вывести компактный JSON без отступов")
    parser.add_argument("--no-progress", action="store_true", help="не показывать progress bar")
    parser.add_argument("--output-dir", default="reports", help="directory for JSON reports")
    parser.add_argument("--stdout", action="store_true", help="print JSON to stdout instead of saving a report file")
    parser.add_argument("--active-tool", action="append", choices=("nmap", "nuclei", "zap"), help="explicitly run an installed active scanner; repeat for multiple tools")
    parser.add_argument("--dynamic", action="store_true", help="run optional isolated Playwright browser analysis")
    parser.add_argument("--search", action="store_true", help="query configured search provider for OSINT visibility")
    args = parser.parse_args()
    try:
        report = analyze(args.domain, args.timeout, None if args.no_progress else _render_progress, tuple(args.active_tool or ()), args.dynamic, args.search)
    except ValueError as exc:
        parser.error(str(exc))
        return 2
    serialized = json.dumps(report, ensure_ascii=False, indent=None if args.compact else 2, sort_keys=not args.compact)
    if args.stdout:
        print(serialized)
        return 0

    report_path = _report_path(args.output_dir, report["target"])
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(serialized + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"Не удалось сохранить отчёт: {exc}", file=sys.stderr)
        return 1
    print(f"Проверка домена {report['target']} завершена.")
    print(f"Отчёт сохранён: {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
