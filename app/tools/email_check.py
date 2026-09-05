"""User-facing local email checker."""
from __future__ import annotations

import argparse

from ..analyzers import email


def print_report(report: dict) -> None:
    item = report["email"]
    print("\nEmail Check\n===========")
    print(f"Email: {item['address']}")
    print(f"Status: {report['summary']['status']}")
    print(f"Syntax: {'valid' if item['syntax_valid'] else 'invalid'} | Disposable: {item['disposable']} | Role: {item['is_role']}")
    print(f"MX: {', '.join(report['dns']['mx']) or 'not found'}")
    print(f"Rules: {', '.join(report['rules']['matched']) or 'none'}")
    print(f"SMTP: {report['smtp']['status']}")
    if report["summary"]["reasons"]:
        print("Reasons: " + ", ".join(report["summary"]["reasons"]))


def run(address: str, timeout: float = 8.0, rules: str | None = None, disposable: str | None = None, check_smtp: bool = False, show_report: bool = True) -> dict:
    report = email.analyze(address, timeout=timeout, rules=rules or email.DEFAULT_RULES, disposable=disposable or email.DEFAULT_DISPOSABLE, check_smtp=check_smtp)
    if show_report:
        print_report(report)
    return report


def run_cli(args: argparse.Namespace) -> dict:
    return run(args.email, args.timeout, args.rules, args.disposable, args.smtp, not args.stdout)


def interactive() -> dict:
    address = input("Email: ").strip()
    smtp = input("Проверить SMTP RCPT TO? (y/N): ").strip().lower() in {"y", "yes", "д", "да"}
    return run(address, check_smtp=smtp)